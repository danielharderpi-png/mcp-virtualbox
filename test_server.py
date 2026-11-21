import asyncio
import os
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import server


class TestVirtualBoxMCP(unittest.TestCase):
    def setUp(self) -> None:
        server.rate_limiter.reset()

    # --- Executable Discovery ---

    @patch.dict(os.environ, {"VBOXMANAGE_PATH": r"C:\Custom\VBoxManage.exe"}, clear=False)
    @patch("server.os.path.exists", return_value=True)
    def test_get_vboxmanage_path_env_valid(self, mock_exists: MagicMock) -> None:
        self.assertEqual(server.get_vboxmanage_path(), r"C:\Custom\VBoxManage.exe")
        mock_exists.assert_called_with(r"C:\Custom\VBoxManage.exe")

    @patch.dict(os.environ, {"VBOXMANAGE_PATH": r"C:\Missing\VBoxManage.exe"}, clear=False)
    @patch("server.os.path.exists", return_value=False)
    def test_get_vboxmanage_path_env_invalid_raises(self, _mock_exists: MagicMock) -> None:
        with self.assertRaises(FileNotFoundError):
            server.get_vboxmanage_path()

    @patch.dict(os.environ, {"VBOXMANAGE_PATH": ""}, clear=False)
    @patch("server.shutil.which", return_value="/usr/bin/VBoxManage")
    def test_get_vboxmanage_path_found_in_path(self, _mock_which: MagicMock) -> None:
        self.assertEqual(server.get_vboxmanage_path(), "/usr/bin/VBoxManage")

    @patch.dict(os.environ, {"VBOXMANAGE_PATH": ""}, clear=False)
    @patch("server.shutil.which", return_value=None)
    @patch("server.os.path.exists")
    def test_get_vboxmanage_path_platform_fallback(
        self, mock_exists: MagicMock, _mock_which: MagicMock
    ) -> None:
        mock_exists.side_effect = [True]
        path = server.get_vboxmanage_path()
        self.assertTrue(path.endswith("VBoxManage.exe") or path.endswith("VBoxManage"))

    @patch.dict(os.environ, {"VBOXMANAGE_PATH": ""}, clear=False)
    @patch("server.shutil.which", return_value=None)
    @patch("server.os.path.exists", return_value=False)
    def test_get_vboxmanage_path_not_found_raises(
        self, _mock_exists: MagicMock, _mock_which: MagicMock
    ) -> None:
        with self.assertRaises(FileNotFoundError):
            server.get_vboxmanage_path()

    # --- Redaction & Subprocess Execution ---

    def test_redact_cmd_masks_passwords(self) -> None:
        cmd = [
            "VBoxManage",
            "guestcontrol",
            "DevVM",
            "run",
            "--username",
            "admin",
            "--password",
            "TopSecret99!",
            "--password=InlineSecret",
            "--password-file",
            "/tmp/pass.txt",
        ]
        redacted = server._redact_cmd(cmd)
        self.assertNotIn("TopSecret99!", redacted)
        self.assertNotIn("InlineSecret", redacted)
        self.assertNotIn("/tmp/pass.txt", redacted)
        self.assertIn("--password ***", redacted)
        self.assertIn("--password=***", redacted)
        self.assertIn("--password-file ***", redacted)

    @patch("server.get_vboxmanage_path", return_value="VBoxManage")
    @patch("server.subprocess.run")
    def test_run_vbox_cmd_redacts_password_on_error(
        self, mock_run: MagicMock, _mock_path: MagicMock
    ) -> None:
        proc = MagicMock(returncode=1, stdout="", stderr="Error authenticating with SecretPass123")
        mock_run.return_value = proc

        res = server.run_vbox_cmd(
            ["guestcontrol", "DevVM", "run", "--username", "u", "--password", "SecretPass123", "--exe", "/bin/id"]
        )
        self.assertFalse(res.ok)
        assert res.error is not None
        self.assertNotIn("SecretPass123", res.error)
        self.assertIn("--password ***", res.error)

    @patch("server.get_vboxmanage_path", return_value="VBoxManage")
    @patch("server.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="VBoxManage", timeout=5))
    def test_run_vbox_cmd_timeout(self, _mock_run: MagicMock, _mock_path: MagicMock) -> None:
        res = server.run_vbox_cmd(["list", "vms"], timeout=5)
        self.assertFalse(res.ok)
        assert res.error is not None
        self.assertIn("timed out after 5 seconds", res.error)

    @patch("server.get_vboxmanage_path", return_value="VBoxManage")
    @patch("server.subprocess.run")
    def test_run_vbox_cmd_success(self, mock_run: MagicMock, _mock_path: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="  ok  \n", stderr="")
        res = server.run_vbox_cmd(["--version"])
        self.assertTrue(res.ok)
        self.assertEqual(res.stdout, "ok")

    # --- Auth, Rate Limiting & Validation ---

    @patch.dict(os.environ, {"VBOX_MAX_CALLS_PER_MINUTE": "2"}, clear=False)
    def test_rate_limiter_enforces_limit(self) -> None:
        server.rate_limiter.acquire()
        server.rate_limiter.acquire()
        with self.assertRaises(RuntimeError) as ctx:
            server.rate_limiter.acquire()
        self.assertIn("429 Too Many Requests", str(ctx.exception))

    @patch.dict(os.environ, {"VBOX_MAX_CALLS_PER_MINUTE": "0"}, clear=False)
    def test_rate_limiter_disabled_when_zero(self) -> None:
        for _ in range(10):
            server.rate_limiter.acquire()

    @patch.dict(os.environ, {"VBOX_MAX_CALLS_PER_MINUTE": "1"}, clear=False)
    @patch("server.get_vboxmanage_path", return_value="VBoxManage")
    @patch("server.subprocess.run")
    def test_list_vms_does_not_self_throttle(
        self, mock_run: MagicMock, _mock_path: MagicMock
    ) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout='"Ubuntu" {1111-2222}', stderr=""),
            MagicMock(returncode=0, stdout='"Ubuntu" {1111-2222}\n"Win11" {3333-4444}', stderr=""),
        ]
        result = server.list_vms()
        self.assertIn("Ubuntu", result)
        self.assertIn("Win11", result)
        self.assertEqual(mock_run.call_count, 2)

        # Second tool invocation within the same window hits the 1/min limit cleanly.
        throttled = server.list_vms()
        self.assertIn("429 Too Many Requests", throttled)

    def test_check_auth_strict_mode(self) -> None:
        with patch.dict(os.environ, {"VBOX_REQUIRE_STRICT_AUTH": "true", "VBOX_API_TOKEN": ""}):
            with self.assertRaises(PermissionError):
                server.check_auth()
            res = server.list_vms()
            self.assertIn("401 Unauthorized", res)

        with patch.dict(os.environ, {"VBOX_REQUIRE_STRICT_AUTH": "true", "VBOX_API_TOKEN": "tok"}):
            server.check_auth()

    def test_validate_identifier_rejects_injection_and_bad_values(self) -> None:
        for bad in ("", "   ", "--flag", "-h", "vm\nname", "vm\x00id"):
            with self.assertRaises(ValueError):
                server._validate_identifier(bad, "vm_name")
        self.assertEqual(server._validate_identifier("  Ubuntu-Dev  ", "vm_name"), "Ubuntu-Dev")

    # --- Tool Tests ---

    @patch("server.run_vbox_cmd")
    def test_list_vms_mixed_running_and_stopped(self, mock_cmd: MagicMock) -> None:
        mock_cmd.side_effect = [
            server.CommandResult(0, '"DevVM" {aaaa-bbbb}', ""),
            server.CommandResult(0, '"DevVM" {aaaa-bbbb}\n"TestVM" {cccc-dddd}', ""),
        ]
        out = server.list_vms()
        self.assertIn("**DevVM** (`aaaa-bbbb`) [RUNNING]", out)
        self.assertIn("**TestVM** (`cccc-dddd`) [STOPPED]", out)

    @patch("server.run_vbox_cmd")
    def test_list_vms_running_only(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, '"DevVM" {aaaa-bbbb}', "")
        out = server.list_vms(running_only=True)
        self.assertIn("### Running VirtualBox VMs", out)
        self.assertIn("**DevVM** (`aaaa-bbbb`) [RUNNING]", out)
        mock_cmd.assert_called_once_with(["list", "runningvms"])

    @patch("server.run_vbox_cmd")
    def test_list_vms_empty(self, mock_cmd: MagicMock) -> None:
        mock_cmd.side_effect = [
            server.CommandResult(0, "", ""),
            server.CommandResult(0, "", ""),
        ]
        self.assertIn("No VirtualBox VMs found", server.list_vms())

    @patch("server.run_vbox_cmd")
    def test_get_vm_info_machinereadable_summary(self, mock_cmd: MagicMock) -> None:
        mr = "\n".join(
            [
                'name="DevVM"',
                'UUID="1234-5678"',
                'ostype="Ubuntu_64"',
                'VMState="running"',
                "cpus=4",
                "memory=4096",
                "vram=32",
                'clipboard="bidirectional"',
                'CurrentSnapshotName="CleanBase"',
                'nic1="nat"',
                'macaddress1="080027ABCDEF"',
                'Forwarding(0)="ssh,tcp,127.0.0.1,2222,,22"',
                'SharedFolderNameMachineMapping1="workspace"',
                'SharedFolderPathMachineMapping1="/home/user/proj"',
            ]
        )
        mock_cmd.return_value = server.CommandResult(0, mr, "")
        out = server.get_vm_info("DevVM")
        mock_cmd.assert_called_once_with(["showvminfo", "DevVM", "--machinereadable"])
        self.assertIn("### VM Summary: DevVM", out)
        self.assertIn("4 vCPU(s), 4096 MB RAM, 32 MB VRAM", out)
        self.assertIn("`ssh` (TCP): 127.0.0.1:2222 -> *:22", out)
        self.assertIn("`workspace` (permanent) -> `/home/user/proj`", out)
        self.assertIn("CleanBase", out)

    @patch("server.run_vbox_cmd")
    def test_get_vm_info_verbose(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "Memory size: 2048MB", "")
        out = server.get_vm_info("DevVM", verbose=True)
        mock_cmd.assert_called_once_with(["showvminfo", "DevVM"])
        self.assertIn("Memory size: 2048MB", out)

    def test_get_vm_info_rejects_flag_injection(self) -> None:
        out = server.get_vm_info("--help")
        self.assertTrue(out.startswith("Error:"))

    @patch("server.run_vbox_cmd")
    def test_get_vm_ip_parses_addresses(self, mock_cmd: MagicMock) -> None:
        enum_out = "\n".join(
            [
                "Name: /VirtualBox/GuestAdd/Version, value: 7.0.14, timestamp: 1234",
                "/VirtualBox/GuestAdd/Version, value: 7.0.14, timestamp: 1234",
                "/VirtualBox/GuestInfo/Net/0/V4/IP, value: 10.0.2.15, timestamp: 1234",
                "/VirtualBox/GuestInfo/Net/0/V4/Netmask, value: 255.255.255.0, timestamp: 1234",
                "/VirtualBox/GuestInfo/Net/1/V6/IP, value: fe80::1, timestamp: 1234",
            ]
        )
        mock_cmd.return_value = server.CommandResult(0, enum_out, "")
        out = server.get_vm_ip("DevVM")
        self.assertIn("7.0.14", out)
        self.assertIn("`10.0.2.15`", out)
        self.assertIn("`fe80::1`", out)

    @patch("server.run_vbox_cmd")
    def test_get_vm_ip_none_reported(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "", "")
        out = server.get_vm_ip("DevVM")
        self.assertIn("No IP addresses reported yet", out)

    @patch("server.run_vbox_cmd")
    def test_manage_power_start_modes_and_actions(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "", "")
        self.assertIn("Successfully", server.manage_power("DevVM", "start", mode="gui"))
        mock_cmd.assert_called_with(["startvm", "DevVM", "--type", "gui"])

        expected = {
            "stop": "acpipowerbutton",
            "force-stop": "poweroff",
            "reset": "reset",
            "savestate": "savestate",
            "pause": "pause",
            "resume": "resume",
        }
        for action, vbox_arg in expected.items():
            out = server.manage_power("DevVM", action)  # type: ignore[arg-type]
            self.assertIn("Successfully", out)
            mock_cmd.assert_called_with(["controlvm", "DevVM", vbox_arg])

    def test_manage_power_invalid_action(self) -> None:
        out = server.manage_power("DevVM", "destroy")  # type: ignore[arg-type]
        self.assertIn("Error: Invalid action", out)

    @patch("server.run_vbox_cmd")
    def test_manage_snapshot_list_and_take_flags(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "Name: BaseSnap", "")
        out_list = server.manage_snapshot("DevVM", "list")
        mock_cmd.assert_called_with(["snapshot", "DevVM", "list"], timeout=120)
        self.assertIn("BaseSnap", out_list)

        out_take = server.manage_snapshot(
            "DevVM", "take", snapshot_name="PrePatch", description="Before update", live=True
        )
        mock_cmd.assert_called_with(
            ["snapshot", "DevVM", "take", "PrePatch", "--description", "Before update", "--live"],
            timeout=120,
        )
        self.assertIn("Successfully", out_take)

    def test_manage_snapshot_missing_name(self) -> None:
        out = server.manage_snapshot("DevVM", "restore")
        self.assertIn("Error: snapshot_name cannot be empty", out)

    @patch("server.run_vbox_cmd")
    def test_manage_snapshot_restore_and_delete(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "", "")
        res_restore = server.manage_snapshot("DevVM", "restore", snapshot_name="PrePatch")
        mock_cmd.assert_called_with(["snapshot", "DevVM", "restore", "PrePatch"], timeout=120)
        self.assertIn("Successfully", res_restore)

        res_delete = server.manage_snapshot("DevVM", "delete", snapshot_name="PrePatch")
        mock_cmd.assert_called_with(["snapshot", "DevVM", "delete", "PrePatch"], timeout=120)
        self.assertIn("Successfully", res_delete)

    @patch("server.run_vbox_cmd")
    def test_execute_guest_command_explicit_cwd_and_env(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "hello", "")
        out = server.execute_guest_command(
            "DevVM",
            "/bin/echo",
            args=["hello"],
            username="dev",
            password="pw",
            cwd="/tmp",
            env={"FOO": "bar"},
            timeout=30,
        )
        mock_cmd.assert_called_once_with(
            [
                "guestcontrol",
                "DevVM",
                "run",
                "--exe",
                "/bin/echo",
                "--username",
                "dev",
                "--password",
                "pw",
                "--cwd",
                "/tmp",
                "--putenv",
                "FOO=bar",
                "--",
                "hello",
            ],
            timeout=30,
        )
        self.assertIn("hello", out)

    @patch.dict(os.environ, {"VBOX_GUEST_USER": "envuser", "VBOX_GUEST_PASSWORD": "envpw"}, clear=False)
    @patch("server.run_vbox_cmd")
    def test_execute_guest_command_uses_env_creds(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "ok", "")
        out = server.execute_guest_command("DevVM", "/usr/bin/id")
        self.assertIn("exit code 0", out)
        called_args = mock_cmd.call_args.args[0]
        self.assertIn("envuser", called_args)
        self.assertIn("envpw", called_args)

    @patch.dict(os.environ, {"VBOX_GUEST_USER": "", "VBOX_GUEST_PASSWORD": ""}, clear=False)
    def test_execute_guest_command_missing_username(self) -> None:
        out = server.execute_guest_command("DevVM", "/usr/bin/id")
        self.assertIn("Error: username cannot be empty", out)

    @patch("server.get_vboxmanage_path", return_value="VBoxManage")
    @patch("server.subprocess.run")
    def test_execute_guest_command_error_hides_password(
        self, mock_run: MagicMock, _mock_path: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Guest error")
        out = server.execute_guest_command(
            "DevVM", "/bin/false", username="dev", password="UltraSecretPassword!"
        )
        self.assertNotIn("UltraSecretPassword!", out)
        self.assertIn("--password ***", out)

    @patch("server.os.path.exists", return_value=True)
    @patch("server.run_vbox_cmd")
    def test_copy_to_guest_success(self, mock_cmd: MagicMock, _mock_exists: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "", "")
        out = server.copy_to_guest(
            "DevVM", "/host/app", "/guest/dir", username="dev", recursive=True
        )
        mock_cmd.assert_called_once_with(
            [
                "guestcontrol",
                "DevVM",
                "copyto",
                "--username",
                "dev",
                "--recursive",
                "--target-directory",
                "/guest/dir",
                "/host/app",
            ],
            timeout=120,
        )
        self.assertIn("Successfully transferred", out)

    @patch("server.os.path.exists", return_value=False)
    def test_copy_to_guest_missing_host_file(self, _mock_exists: MagicMock) -> None:
        out = server.copy_to_guest("DevVM", "/missing/file", "/tmp", username="dev")
        self.assertIn("does not exist", out)

    @patch("server.run_vbox_cmd")
    def test_copy_from_guest_success(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "", "")
        out = server.copy_from_guest(
            "DevVM", "/var/log/app.log", "/host/logs", username="dev"
        )
        mock_cmd.assert_called_once_with(
            [
                "guestcontrol",
                "DevVM",
                "copyfrom",
                "--username",
                "dev",
                "--target-directory",
                "/host/logs",
                "/var/log/app.log",
            ],
            timeout=120,
        )
        self.assertIn("Successfully transferred", out)

    @patch.dict(os.environ, {"VBOX_GUEST_USER": "", "VBOX_GUEST_PASSWORD": ""}, clear=False)
    def test_copy_from_guest_missing_username(self) -> None:
        out = server.copy_from_guest("DevVM", "/var/log/app.log", "/host/logs")
        self.assertIn("Error: username cannot be empty", out)

    @patch("server.run_vbox_cmd")
    def test_manage_port_forwarding_list_add_delete(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(
            0, 'Forwarding(0)="web,tcp,127.0.0.1,8080,,80"', ""
        )
        listed = server.manage_port_forwarding("DevVM", "list")
        self.assertIn("`web` (TCP): 127.0.0.1:8080 -> *:80", listed)

        mock_cmd.return_value = server.CommandResult(0, "", "")
        added = server.manage_port_forwarding(
            "DevVM",
            "add",
            adapter=1,
            rule_name="ssh",
            protocol="tcp",
            host_port=2222,
            guest_port=22,
            is_running=False,
        )
        mock_cmd.assert_called_with(
            ["modifyvm", "DevVM", "--natpf1", "ssh,tcp,127.0.0.1,2222,,22"]
        )
        self.assertIn("Successfully executed port-forwarding 'add'", added)

        deleted = server.manage_port_forwarding(
            "DevVM", "delete", adapter=2, rule_name="ssh", is_running=True
        )
        mock_cmd.assert_called_with(["controlvm", "DevVM", "natpf2", "delete", "ssh"])
        self.assertIn("Successfully executed port-forwarding 'delete'", deleted)

    def test_manage_port_forwarding_invalid_port(self) -> None:
        out = server.manage_port_forwarding(
            "DevVM", "add", rule_name="bad", host_port=70000, guest_port=22
        )
        self.assertIn("Error: host_port must be between 1 and 65535", out)

    @patch("server.os.path.isdir", return_value=True)
    @patch("server.run_vbox_cmd")
    def test_manage_shared_folders_list_add_remove(
        self, mock_cmd: MagicMock, _mock_isdir: MagicMock
    ) -> None:
        mock_cmd.return_value = server.CommandResult(
            0,
            'SharedFolderNameMachineMapping1="code"\nSharedFolderPathMachineMapping1="/src"',
            "",
        )
        listed = server.manage_shared_folders("DevVM", "list")
        self.assertIn("`code` (permanent) -> `/src`", listed)

        mock_cmd.return_value = server.CommandResult(0, "", "")
        added = server.manage_shared_folders(
            "DevVM", "add", folder_name="code", host_path="/src", readonly=True, automount=True
        )
        mock_cmd.assert_called_with(
            ["sharedfolder", "add", "DevVM", "--name", "code", "--hostpath", "/src", "--readonly", "--automount"]
        )
        self.assertIn("Successfully", added)

        removed = server.manage_shared_folders(
            "DevVM", "remove", folder_name="code", transient=True
        )
        mock_cmd.assert_called_with(
            ["sharedfolder", "remove", "DevVM", "--name", "code", "--transient"]
        )
        self.assertIn("Successfully", removed)

    @patch("server.os.path.isdir", return_value=False)
    def test_manage_shared_folders_missing_dir(self, _mock_isdir: MagicMock) -> None:
        out = server.manage_shared_folders(
            "DevVM", "add", folder_name="code", host_path="/does/not/exist"
        )
        self.assertIn("does not exist or is not a directory", out)

    @patch("server.run_vbox_cmd")
    def test_configure_vm_resources_success_and_validation(self, mock_cmd: MagicMock) -> None:
        self.assertIn("Specify at least one", server.configure_vm_resources("DevVM"))
        self.assertIn("must be between 1 and 128", server.configure_vm_resources("DevVM", cpus=0))
        self.assertIn(
            "must be between 128 and 262144",
            server.configure_vm_resources("DevVM", memory_mb=64),
        )

        mock_cmd.return_value = server.CommandResult(0, "", "")
        out = server.configure_vm_resources(
            "DevVM", cpus=4, memory_mb=4096, vram_mb=64, clipboard_mode="bidirectional"
        )
        mock_cmd.assert_called_once_with(
            [
                "modifyvm",
                "DevVM",
                "--cpus",
                "4",
                "--memory",
                "4096",
                "--vram",
                "64",
                "--clipboard-mode",
                "bidirectional",
            ]
        )
        self.assertIn("Successfully updated VM 'DevVM'", out)

    @patch("server.run_vbox_cmd")
    def test_clone_vm_full_linked_and_validation(self, mock_cmd: MagicMock) -> None:
        no_snap = server.clone_vm("BaseVM", "CloneVM", linked=True)
        self.assertIn("snapshot_name is required", no_snap)

        mock_cmd.return_value = server.CommandResult(0, "", "")
        linked_out = server.clone_vm(
            "BaseVM", "CloneVM", mode="machine", linked=True, snapshot_name="Gold"
        )
        mock_cmd.assert_called_with(
            [
                "clonevm",
                "BaseVM",
                "--name",
                "CloneVM",
                "--mode",
                "machine",
                "--register",
                "--snapshot",
                "Gold",
                "--options",
                "link",
            ],
            timeout=300,
        )
        self.assertIn("linked clone", linked_out)

    @patch("server.os.makedirs")
    @patch("server.run_vbox_cmd")
    def test_take_vm_screenshot(self, mock_cmd: MagicMock, mock_makedirs: MagicMock) -> None:
        mock_cmd.return_value = server.CommandResult(0, "", "")
        out = server.take_vm_screenshot("DevVM", "shots/screen")
        mock_makedirs.assert_called()
        called_args = mock_cmd.call_args.args[0]
        self.assertEqual(called_args[:3], ["controlvm", "DevVM", "screenshotpng"])
        self.assertTrue(called_args[3].endswith("screen.png"))
        self.assertIn("Screenshot saved", out)

    @patch("server.run_vbox_cmd")
    def test_resource_vms(self, mock_cmd: MagicMock) -> None:
        mock_cmd.side_effect = [
            server.CommandResult(0, "", ""),
            server.CommandResult(0, '"LabVM" {9999}', ""),
        ]
        out = server.resource_vms()
        self.assertIn("**LabVM** (`9999`) [STOPPED]", out)

    def test_native_tool_annotations_and_no_monkey_patch(self) -> None:
        self.assertFalse(hasattr(server, "_patched_tool"))
        tools = asyncio.run(server.mcp.list_tools())
        self.assertEqual(len(tools), 13)
        by_name = {t.name: t for t in tools}

        for ro_name in ("list_vms", "get_vm_info", "get_vm_ip"):
            ann = by_name[ro_name].annotations
            assert ann is not None
            self.assertTrue(ann.read_only_hint)
            self.assertFalse(ann.destructive_hint)

        for dest_name in ("manage_power", "manage_snapshot", "execute_guest_command"):
            ann = by_name[dest_name].annotations
            assert ann is not None
            self.assertFalse(ann.read_only_hint)
            self.assertTrue(ann.destructive_hint)

        self.assertTrue(by_name["execute_guest_command"].annotations.open_world_hint)
        resources = asyncio.run(server.mcp.list_resources())
        self.assertEqual([str(r.uri) for r in resources], ["vbox://vms"])


if __name__ == "__main__":
    unittest.main()
