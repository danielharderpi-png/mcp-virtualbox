import asyncio
import hashlib
import io
import os
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
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

    @patch("server.run_vbox_cmd")
    def test_list_os_types_all_and_filtered(self, mock_cmd: MagicMock) -> None:
        raw = "\n".join(
            [
                "ID:          Ubuntu_64",
                "Description: Ubuntu (64-bit)",
                "Family ID:   Linux",
                "Family Desc: Linux",
                "",
                "ID:          Windows11_64",
                "Description: Windows 11 (64-bit)",
                "Family ID:   Windows",
                "Family Desc: Microsoft Windows",
            ]
        )
        mock_cmd.return_value = server.CommandResult(0, raw, "")

        all_out = server.list_os_types()
        self.assertIn("Supported Guest OS Types (2)", all_out)
        self.assertIn("Ubuntu_64", all_out)
        self.assertIn("Windows11_64", all_out)

        filtered = server.list_os_types(search="ubuntu")
        self.assertIn("Ubuntu_64", filtered)
        self.assertNotIn("Windows11_64", filtered)

        none_found = server.list_os_types(search="plan9")
        self.assertIn("No guest OS types matching", none_found)

    @patch("server.os.path.isfile", return_value=True)
    @patch("server.run_vbox_cmd")
    def test_create_vm_with_disk_and_iso(
        self, mock_cmd: MagicMock, _mock_isfile: MagicMock
    ) -> None:
        mock_cmd.side_effect = [
            server.CommandResult(0, "", ""),  # createvm
            server.CommandResult(0, "", ""),  # modifyvm
            server.CommandResult(0, 'CfgFile="/vms/NewBox/NewBox.vbox"', ""),  # showvminfo
            server.CommandResult(0, "", ""),  # storagectl SATA
            server.CommandResult(0, "", ""),  # createmedium
            server.CommandResult(0, "", ""),  # storageattach hdd
            server.CommandResult(0, "", ""),  # storagectl IDE
            server.CommandResult(0, "", ""),  # storageattach dvddrive
        ]

        out = server.create_vm(
            "NewBox",
            os_type="Ubuntu_64",
            cpus=4,
            memory_mb=4096,
            vram_mb=32,
            disk_size_mb=32768,
            nic_mode="bridged",
            iso_path="/isos/ubuntu.iso",
        )
        self.assertIn("### Created VM: NewBox", out)
        self.assertIn("32768 MB", out)
        self.assertIn("/isos/ubuntu.iso", out)

        calls = [c.args[0] for c in mock_cmd.call_args_list]
        self.assertEqual(calls[0], ["createvm", "--name", "NewBox", "--ostype", "Ubuntu_64", "--register"])
        self.assertEqual(
            calls[1],
            ["modifyvm", "NewBox", "--cpus", "4", "--memory", "4096", "--vram", "32", "--nic1", "bridged"],
        )
        self.assertEqual(calls[2], ["showvminfo", "NewBox", "--machinereadable"])
        self.assertEqual(
            calls[3],
            ["storagectl", "NewBox", "--name", "SATA Controller", "--add", "sata", "--controller", "IntelAhci"],
        )
        expected_vdi = os.path.join("/vms/NewBox", "NewBox.vdi")
        self.assertEqual(
            calls[4],
            ["createmedium", "disk", "--filename", expected_vdi, "--size", "32768", "--format", "VDI"],
        )
        self.assertEqual(
            calls[5],
            [
                "storageattach",
                "NewBox",
                "--storagectl",
                "SATA Controller",
                "--port",
                "0",
                "--device",
                "0",
                "--type",
                "hdd",
                "--medium",
                expected_vdi,
            ],
        )
        self.assertEqual(calls[6], ["storagectl", "NewBox", "--name", "IDE Controller", "--add", "ide"])
        self.assertEqual(
            calls[7],
            [
                "storageattach",
                "NewBox",
                "--storagectl",
                "IDE Controller",
                "--port",
                "0",
                "--device",
                "0",
                "--type",
                "dvddrive",
                "--medium",
                "/isos/ubuntu.iso",
            ],
        )

    @patch("server.os.path.isfile", return_value=False)
    @patch("server.run_vbox_cmd")
    def test_create_vm_without_disk_and_missing_iso(
        self, mock_cmd: MagicMock, _mock_isfile: MagicMock
    ) -> None:
        err_iso = server.create_vm("NewBox", iso_path="/missing.iso")
        self.assertIn("does not exist", err_iso)
        mock_cmd.assert_not_called()

        mock_cmd.return_value = server.CommandResult(0, "", "")
        out = server.create_vm("DisklessBox", disk_size_mb=0)
        self.assertIn("**Disk:** None", out)
        self.assertEqual(mock_cmd.call_count, 2)

    @patch("server.os.path.isfile", return_value=True)
    @patch("server.get_vboxmanage_path", return_value="VBoxManage")
    @patch("server.subprocess.run")
    def test_unattended_install_success_and_password_redacted_on_error(
        self, mock_run: MagicMock, _mock_path: MagicMock, _mock_isfile: MagicMock
    ) -> None:
        with patch.dict(os.environ, {"VBOX_GUEST_USER": "", "VBOX_GUEST_PASSWORD": ""}, clear=False):
            missing_pw = server.unattended_install("NewBox", "/isos/u.iso", username="dev")
            self.assertIn("password is required", missing_pw)

        mock_run.return_value = MagicMock(returncode=0, stdout="Unattended setup OK", stderr="")
        with patch.dict(os.environ, {"VBOX_GUEST_USER": "auto", "VBOX_GUEST_PASSWORD": "EnvSecret99!"}, clear=False):
            ok_out = server.unattended_install(
                "NewBox",
                "/isos/u.iso",
                hostname="sandbox",
                full_name="Sandbox User",
                start_vm=True,
            )
        self.assertIn("Successfully configured unattended installation", ok_out)
        called_cmd = mock_run.call_args.args[0]
        self.assertIn("--user=auto", called_cmd)
        self.assertIn("--password=EnvSecret99!", called_cmd)
        self.assertIn("--install-additions", called_cmd)
        self.assertIn("--start-vm=headless", called_cmd)

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Bad password VerySecret42!")
        err_out = server.unattended_install(
            "NewBox", "/isos/u.iso", username="dev", password="VerySecret42!"
        )
        self.assertNotIn("VerySecret42!", err_out)
        self.assertIn("--password=***", err_out)

    @patch("server.os.path.isfile", return_value=True)
    @patch("server.run_vbox_cmd")
    def test_import_vm_success_dry_run_and_invalid_extension(
        self, mock_cmd: MagicMock, _mock_isfile: MagicMock
    ) -> None:
        bad_ext = server.import_vm("/tmp/image.zip")
        self.assertIn("must point to a .ova or .ovf file", bad_ext)
        mock_cmd.assert_not_called()

        mock_cmd.return_value = server.CommandResult(0, "Virtual system 0", "")
        dry_out = server.import_vm(
            "/appliances/ubuntu.ova", vm_name="ImportedBox", cpus=2, memory_mb=2048, dry_run=True
        )
        self.assertIn("Dry-run inspection completed", dry_out)
        mock_cmd.assert_called_with(
            [
                "import",
                "/appliances/ubuntu.ova",
                "--dry-run",
                "--vsys",
                "0",
                "--vmname",
                "ImportedBox",
                "--vsys",
                "0",
                "--cpus",
                "2",
                "--vsys",
                "0",
                "--memory",
                "2048",
            ],
            timeout=600,
        )

        imp_out = server.import_vm("/appliances/ubuntu.ovf")
        self.assertIn("Successfully imported appliance", imp_out)

    @patch("server.os.makedirs")
    @patch("server.run_vbox_cmd")
    def test_export_vm_success_and_ova_extension(
        self, mock_cmd: MagicMock, mock_makedirs: MagicMock
    ) -> None:
        mock_cmd.return_value = server.CommandResult(0, "", "")
        out = server.export_vm("DevVM", "exports/devbox")
        mock_makedirs.assert_called()
        called = mock_cmd.call_args.args[0]
        self.assertEqual(called[:3], ["export", "DevVM", "--output"])
        self.assertTrue(called[3].endswith("devbox.ova"))
        self.assertIn("Successfully exported VM 'DevVM'", out)

    @patch("server.os.path.isfile", return_value=True)
    @patch("server.run_vbox_cmd")
    def test_manage_storage_list_attach_and_eject_iso(
        self, mock_cmd: MagicMock, _mock_isfile: MagicMock
    ) -> None:
        mr = "\n".join(
            [
                'storagecontrollername0="SATA Controller"',
                'storagecontrollername1="IDE Controller"',
                'SATA Controller-0-0="/vms/Dev/Dev.vdi"',
                'SATA Controller-ImageUUID-0-0="uuid-1"',
                'IDE Controller-0-0="/isos/boot.iso"',
            ]
        )
        mock_cmd.return_value = server.CommandResult(0, mr, "")
        listed = server.manage_storage("DevVM", "list")
        self.assertIn("`SATA Controller`", listed)
        self.assertIn("`SATA Controller-0-0` -> `/vms/Dev/Dev.vdi`", listed)
        self.assertIn("`IDE Controller-0-0` -> `/isos/boot.iso`", listed)
        self.assertNotIn("ImageUUID", listed)

        mock_cmd.return_value = server.CommandResult(0, "", "")
        attached = server.manage_storage(
            "DevVM", "attach-iso", controller="IDE Controller", port=1, device=0, iso_path="/isos/net.iso"
        )
        mock_cmd.assert_called_with(
            [
                "storageattach",
                "DevVM",
                "--storagectl",
                "IDE Controller",
                "--port",
                "1",
                "--device",
                "0",
                "--type",
                "dvddrive",
                "--medium",
                "/isos/net.iso",
            ]
        )
        self.assertIn("Successfully attached ISO", attached)

        ejected = server.manage_storage("DevVM", "eject-iso", controller="IDE Controller", port=1, device=0)
        mock_cmd.assert_called_with(
            [
                "storageattach",
                "DevVM",
                "--storagectl",
                "IDE Controller",
                "--port",
                "1",
                "--device",
                "0",
                "--type",
                "dvddrive",
                "--medium",
                "emptydrive",
            ]
        )
        self.assertIn("Successfully ejected", ejected)

    @patch("server.run_vbox_cmd")
    def test_delete_vm_requires_confirm_and_deletes_when_confirmed(
        self, mock_cmd: MagicMock
    ) -> None:
        guard_msg = server.delete_vm("DisposableVM", delete_files=True, confirm=False)
        self.assertIn("Confirmation required", guard_msg)
        mock_cmd.assert_not_called()

        mock_cmd.return_value = server.CommandResult(0, "", "")
        del_all = server.delete_vm("DisposableVM", delete_files=True, confirm=True)
        mock_cmd.assert_called_with(["unregistervm", "DisposableVM", "--delete"], timeout=120)
        self.assertIn("permanently deleted", del_all)

        del_keep = server.delete_vm("DisposableVM", delete_files=False, confirm=True)
        mock_cmd.assert_called_with(["unregistervm", "DisposableVM"], timeout=120)
        self.assertIn("files preserved on disk", del_keep)

    # --- Kali Provisioning & Registration ---

    def test_parse_kali_sha256sums_valid_and_rejects_unsafe(self) -> None:
        h_old = "a" * 64
        h_new = "B" * 64
        h_iso = "c" * 64
        h_trav = "d" * 64
        content = "\n".join(
            [
                f"{h_iso}  kali-linux-2026.3-installer-amd64.iso",
                f"{h_old}  kali-linux-2026.2-virtualbox-amd64.7z",
                f"{h_new} *kali-linux-2026.3-virtualbox-amd64.7z",
                f"{h_trav}  ../kali-linux-2026.9-virtualbox-amd64.7z",
            ]
        )
        filename, digest = server._parse_kali_sha256sums(content)
        self.assertEqual(filename, "kali-linux-2026.3-virtualbox-amd64.7z")
        self.assertEqual(digest, h_new.lower())

        unsafe_only = "\n".join(
            [
                f"{h_trav}  ../kali-linux-2026.3-virtualbox-amd64.7z",
                f"{h_trav}  sub/kali-linux-2026.3-virtualbox-amd64.7z",
                f"{h_iso}  kali-linux-2026.3-installer-amd64.iso",
            ]
        )
        with self.assertRaises(ValueError):
            server._parse_kali_sha256sums(unsafe_only)

    def test_validate_archive_members_blocks_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server._validate_archive_members(
                [
                    "kali-linux-2026.3-virtualbox-amd64",
                    "kali-linux-2026.3-virtualbox-amd64/kali.vbox",
                    "kali-linux-2026.3-virtualbox-amd64/kali.vdi",
                    "./kali-linux-2026.3-virtualbox-amd64/Logs/VBox.log",
                ],
                tmpdir,
            )

            with self.assertRaises(ValueError):
                server._validate_archive_members([], tmpdir)

            for bad in (
                "../evil.txt",
                "/etc/passwd",
                r"C:\Windows\evil.dll",
                "sub/../../escape.txt",
                "bad\x00file",
                "   ",
            ):
                with self.assertRaises(ValueError):
                    server._validate_archive_members([bad], tmpdir)

    def test_parse_vbox_metadata_namespaced_and_plain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ns_vbox = os.path.join(tmpdir, "ns.vbox")
            with open(ns_vbox, "w", encoding="utf-8") as f:
                f.write(
                    '<?xml version="1.0"?>\n'
                    '<VirtualBox xmlns="http://www.virtualbox.org/" version="1.19-windows">\n'
                    '  <Machine uuid="{11111111-2222-3333-4444-555555555555}" '
                    'name="kali-linux-2026.3-virtualbox-amd64" OSType="Debian_64"/>\n'
                    "</VirtualBox>\n"
                )
            self.assertEqual(
                server._parse_vbox_metadata(ns_vbox),
                (
                    "kali-linux-2026.3-virtualbox-amd64",
                    "11111111-2222-3333-4444-555555555555",
                    "Debian_64",
                ),
            )

            plain_vbox = os.path.join(tmpdir, "plain.vbox")
            with open(plain_vbox, "w", encoding="utf-8") as f:
                f.write('<VirtualBox><Machine uuid="{aaaa-bbbb}" name="KaliPlain" OSType="Linux_64"/></VirtualBox>')
            self.assertEqual(
                server._parse_vbox_metadata(plain_vbox),
                ("KaliPlain", "aaaa-bbbb", "Linux_64"),
            )

            no_machine = os.path.join(tmpdir, "nomachine.vbox")
            with open(no_machine, "w", encoding="utf-8") as f:
                f.write("<VirtualBox/>")
            with self.assertRaises(ValueError):
                server._parse_vbox_metadata(no_machine)

            bad_xml = os.path.join(tmpdir, "bad.vbox")
            with open(bad_xml, "w", encoding="utf-8") as f:
                f.write("<VirtualBox><broken")
            with self.assertRaises(ValueError):
                server._parse_vbox_metadata(bad_xml)

    def test_extract_7z_archive_7z_and_bsdtar_and_blocks_zipslip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = os.path.join(tmpdir, "kali.7z")
            target_7z = os.path.join(tmpdir, "out_7z")
            slt_out = "\n".join(
                [
                    "Listing archive: kali.7z",
                    "",
                    "Path = kali.7z",
                    "Type = 7z",
                    "----------",
                    "Path = kali/kali.vbox",
                    "Folder = -",
                    "",
                    "Path = kali/kali.vdi",
                    "Folder = -",
                ]
            )
            with patch("server._find_7z_extractor", return_value=("7z", "7z.exe")), patch(
                "server.subprocess.run"
            ) as mock_run:
                mock_run.side_effect = [
                    MagicMock(returncode=0, stdout=slt_out, stderr=""),
                    MagicMock(returncode=0, stdout="", stderr=""),
                ]
                res = server._extract_7z_archive(archive, target_7z, timeout=300)
                self.assertEqual(res, os.path.abspath(target_7z))
                self.assertEqual(mock_run.call_args_list[0].args[0], ["7z.exe", "l", "-slt", archive])
                self.assertEqual(
                    mock_run.call_args_list[1].args[0],
                    ["7z.exe", "x", "-y", f"-o{target_7z}", archive],
                )

            target_tar = os.path.join(tmpdir, "out_tar")
            with patch("server._find_7z_extractor", return_value=("bsdtar", "tar")), patch(
                "server.subprocess.run"
            ) as mock_run:
                mock_run.side_effect = [
                    MagicMock(returncode=0, stdout="kali/kali.vbox\nkali/kali.vdi\n", stderr=""),
                    MagicMock(returncode=0, stdout="", stderr=""),
                ]
                res = server._extract_7z_archive(archive, target_tar, timeout=300)
                self.assertEqual(res, os.path.abspath(target_tar))
                self.assertEqual(mock_run.call_args_list[0].args[0], ["tar", "-tf", archive])
                self.assertEqual(
                    mock_run.call_args_list[1].args[0],
                    ["tar", "-xf", archive, "-C", target_tar],
                )

            target_bad = os.path.join(tmpdir, "out_bad")
            with patch("server._find_7z_extractor", return_value=("bsdtar", "tar")), patch(
                "server.subprocess.run"
            ) as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="../escape.txt\n", stderr="")
                with self.assertRaises(ValueError):
                    server._extract_7z_archive(archive, target_bad, timeout=300)
                self.assertEqual(mock_run.call_count, 1)

    def test_download_kali_image_downloads_verifies_caches_and_rejects_bad_url(self) -> None:
        payload = b"fake-7z-archive-bytes-for-kali-test"
        expected_sha = hashlib.sha256(payload).hexdigest()
        sums_body = f"{expected_sha}  kali-linux-2026.3-virtualbox-amd64.7z\n".encode("utf-8")

        class _FakeResp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.close()

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_opener = MagicMock()
            fake_opener.open.side_effect = [
                _FakeResp(sums_body),
                _FakeResp(payload),
                _FakeResp(sums_body),
            ]
            with patch("server._build_https_opener", return_value=fake_opener):
                path1, sha1, cached1 = server._download_kali_image(tmpdir, verify_checksum=True)
                self.assertFalse(cached1)
                self.assertEqual(sha1, expected_sha)
                self.assertTrue(os.path.isfile(path1))
                self.assertFalse(os.path.exists(path1 + ".part"))

                # Second invocation hits verified cache without downloading the archive again.
                path2, sha2, cached2 = server._download_kali_image(tmpdir, verify_checksum=True)
                self.assertTrue(cached2)
                self.assertEqual(path2, path1)
                self.assertEqual(sha2, expected_sha)
                self.assertEqual(fake_opener.open.call_count, 3)

            # Checksum mismatch cleans up the `.part` file.
            mismatch_dir = os.path.join(tmpdir, "mismatch")
            bad_opener = MagicMock()
            bad_opener.open.side_effect = [
                _FakeResp(sums_body),
                _FakeResp(b"corrupted-payload"),
            ]
            with patch("server._build_https_opener", return_value=bad_opener):
                with self.assertRaises(ValueError) as ctx:
                    server._download_kali_image(mismatch_dir, verify_checksum=True)
                self.assertIn("checksum mismatch", str(ctx.exception))
                expected_part = os.path.join(
                    mismatch_dir, "kali-linux-2026.3-virtualbox-amd64.7z.part"
                )
                self.assertFalse(os.path.exists(expected_part))

            # Reject insecure base URL schemes and embedded credentials.
            for bad_url in (
                "http://cdimage.kali.org/current/",
                "file:///etc/passwd",
                "https://user:pass@cdimage.kali.org/current/",
            ):
                with patch.dict(os.environ, {"VBOX_KALI_IMAGE_BASE_URL": bad_url}, clear=False):
                    with self.assertRaises(ValueError):
                        server._download_kali_image(tmpdir)

            # HTTPS opener only registers HTTPSHandler (no HTTPHandler/FileHandler/FTPHandler/DataHandler).
            opener = server._build_https_opener()
            handler_types = {type(h) for h in opener.handlers}
            self.assertIn(urllib.request.HTTPSHandler, handler_types)
            self.assertNotIn(urllib.request.HTTPHandler, handler_types)
            self.assertNotIn(urllib.request.FileHandler, handler_types)
            self.assertNotIn(urllib.request.FTPHandler, handler_types)
            self.assertNotIn(urllib.request.DataHandler, handler_types)
            self.assertIn("https", opener.handle_open)
            for disallowed_scheme in ("file", "ftp", "data"):
                self.assertNotIn(disallowed_scheme, opener.handle_open)

            # Redirect handler rejects downgrades away from HTTPS.
            handler = server._HttpsOnlyRedirectHandler()
            req = urllib.request.Request("https://cdimage.kali.org/current/SHA256SUMS")
            for redir_url in ("http://mirror.example.org/file", "file:///tmp/x"):
                with self.assertRaises(urllib.error.URLError):
                    handler.redirect_request(req, None, 302, "Found", {}, redir_url)

    @patch("server.run_vbox_cmd")
    def test_register_vm_from_vbox_dir_and_7z(self, mock_cmd: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vm_dir = os.path.join(tmpdir, "KaliPrebuilt")
            os.makedirs(vm_dir)
            vbox_file = os.path.join(vm_dir, "KaliPrebuilt.vbox")
            with open(vbox_file, "w", encoding="utf-8") as f:
                f.write(
                    '<?xml version="1.0"?>'
                    '<VirtualBox xmlns="http://www.virtualbox.org/">'
                    '<Machine uuid="{aaaa-1111}" name="kali-orig" OSType="Debian_64"/>'
                    "</VirtualBox>"
                )
            # Backup `.vbox-prev` must be ignored by `_find_vbox_file`.
            with open(vbox_file + "-prev", "w", encoding="utf-8") as f:
                f.write("<VirtualBox/>")

            mock_cmd.return_value = server.CommandResult(0, "", "")
            out_vbox = server.register_vm(
                vbox_file,
                vm_name="Kali-Custom",
                cpus=4,
                memory_mb=8192,
                vram_mb=128,
                nic_mode="nat",
                clipboard_mode="bidirectional",
            )
            self.assertIn("### Registered VM: Kali-Custom", out_vbox)
            self.assertIn("`aaaa-1111`", out_vbox)
            calls = [c.args[0] for c in mock_cmd.call_args_list]
            self.assertEqual(calls[0], ["registervm", os.path.abspath(vbox_file)])
            self.assertEqual(
                calls[1],
                [
                    "modifyvm",
                    "aaaa-1111",
                    "--name",
                    "Kali-Custom",
                    "--cpus",
                    "4",
                    "--memory",
                    "8192",
                    "--vram",
                    "128",
                    "--nic1",
                    "nat",
                    "--clipboard-mode",
                    "bidirectional",
                ],
            )

            # Directory source locates the single `.vbox` file.
            mock_cmd.reset_mock()
            out_dir = server.register_vm(vm_dir)
            self.assertIn("### Registered VM: kali-orig", out_dir)
            mock_cmd.assert_called_once_with(["registervm", os.path.abspath(vbox_file)], timeout=120)

            # `.7z` extraction + registration.
            mock_cmd.reset_mock()
            archive_7z = os.path.join(tmpdir, "kali.7z")
            with open(archive_7z, "wb") as f:
                f.write(b"7z")
            extract_target = os.path.join(tmpdir, "extracted_vm")

            def _fake_extract(_arch: str, dest: str, timeout: int = 600) -> str:
                os.makedirs(dest, exist_ok=True)
                inner_vbox = os.path.join(dest, "KaliExtracted.vbox")
                with open(inner_vbox, "w", encoding="utf-8") as xf:
                    xf.write('<VirtualBox><Machine uuid="{bbbb-2222}" name="Kali7z" OSType="Debian_64"/></VirtualBox>')
                return dest

            with patch("server._extract_7z_archive", side_effect=_fake_extract) as mock_extract:
                out_7z = server.register_vm(archive_7z, extract_dir=extract_target)
                mock_extract.assert_called_once()
                self.assertIn("### Registered VM: Kali7z", out_7z)
                self.assertIn("Extracted Directory", out_7z)

            # Non-empty existing extract directory is rejected before extracting.
            non_empty = os.path.join(tmpdir, "nonempty")
            os.makedirs(non_empty)
            with open(os.path.join(non_empty, "stale.txt"), "w", encoding="utf-8") as f:
                f.write("occupied")
            err_nonempty = server.register_vm(archive_7z, extract_dir=non_empty)
            self.assertIn("already exists and is not empty", err_nonempty)

            # Invalid extension rejected.
            bad_zip = os.path.join(tmpdir, "image.zip")
            with open(bad_zip, "wb") as f:
                f.write(b"zip")
            self.assertIn("must be an existing .vbox file", server.register_vm(bad_zip))

            # Crafted `.vbox` with missing UUID and flag-prefixed name is rejected before `modifyvm`.
            mock_cmd.reset_mock()
            evil_vbox = os.path.join(tmpdir, "evil.vbox")
            with open(evil_vbox, "w", encoding="utf-8") as f:
                f.write('<VirtualBox><Machine name="--evil" OSType="Debian_64"/></VirtualBox>')
            evil_out = server.register_vm(evil_vbox, cpus=2)
            self.assertIn("cannot start with '-'", evil_out)
            mock_cmd.assert_not_called()

    @patch("server.run_vbox_cmd")
    def test_provision_kali_vm_from_local_7z_with_snapshot_and_start(
        self, mock_cmd: MagicMock
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = os.path.join(tmpdir, "kali-linux-2026.3-virtualbox-amd64.7z")
            with open(archive, "wb") as f:
                f.write(b"7z")
            vbox_root = os.path.join(tmpdir, "VirtualBox VMs")

            def _fake_extract(_arch: str, dest: str, timeout: int = 600) -> str:
                os.makedirs(dest, exist_ok=True)
                with open(os.path.join(dest, "kali.vbox"), "w", encoding="utf-8") as xf:
                    xf.write(
                        '<VirtualBox xmlns="http://www.virtualbox.org/">'
                        '<Machine uuid="{cccc-3333}" name="kali-linux-2026.3" OSType="Debian_64"/>'
                        "</VirtualBox>"
                    )
                return dest

            mock_cmd.side_effect = [
                server.CommandResult(0, "", ""),  # list vms
                server.CommandResult(0, f"Default machine folder: {vbox_root}", ""),  # systemproperties
                server.CommandResult(0, "", ""),  # registervm
                server.CommandResult(0, "", ""),  # modifyvm
                server.CommandResult(0, "", ""),  # snapshot take
                server.CommandResult(0, "", ""),  # startvm
            ]

            with patch("server._extract_7z_archive", side_effect=_fake_extract) as mock_ext:
                out = server.provision_kali_vm(
                    vm_name="Kali-Agent",
                    image_path=archive,
                    start_vm=True,
                )

            expected_dest = os.path.join(vbox_root, "Kali-Agent")
            mock_ext.assert_called_once_with(os.path.abspath(archive), expected_dest, timeout=1800)

            calls = [c.args[0] for c in mock_cmd.call_args_list]
            self.assertEqual(calls[0], ["list", "vms"])
            self.assertEqual(calls[1], ["list", "systemproperties"])
            self.assertEqual(calls[2], ["registervm", os.path.join(expected_dest, "kali.vbox")])
            self.assertEqual(
                calls[3],
                [
                    "modifyvm",
                    "cccc-3333",
                    "--name",
                    "Kali-Agent",
                    "--cpus",
                    "2",
                    "--memory",
                    "4096",
                    "--vram",
                    "128",
                    "--nic1",
                    "nat",
                    "--clipboard-mode",
                    "bidirectional",
                ],
            )
            self.assertEqual(
                calls[4],
                [
                    "snapshot",
                    "Kali-Agent",
                    "take",
                    "clean-base",
                    "--description",
                    "Clean Kali Linux agent baseline",
                ],
            )
            self.assertEqual(calls[5], ["startvm", "Kali-Agent", "--type", "headless"])

            self.assertIn("### Provisioned Kali Linux VM: Kali-Agent", out)
            self.assertIn("2 vCPU(s), 4096 MB RAM, 128 MB VRAM", out)
            self.assertIn("`clean-base` (created)", out)
            self.assertIn("RUNNING (`headless`)", out)
            self.assertIn("username `kali` / password `kali`", out)

    @patch("server.run_vbox_cmd")
    def test_provision_kali_vm_from_base_vm_linked_and_full_clone(
        self, mock_cmd: MagicMock
    ) -> None:
        mock_cmd.side_effect = [
            server.CommandResult(0, '"Kali-Base" {1111-2222}', ""),
            server.CommandResult(0, "", ""),  # clonevm
            server.CommandResult(0, "", ""),  # modifyvm
            server.CommandResult(0, "", ""),  # snapshot
            server.CommandResult(0, "", ""),  # startvm
        ]
        out_linked = server.provision_kali_vm(
            vm_name="Kali-Worker-1",
            base_vm="Kali-Base",
            linked_clone=True,
            start_vm=True,
            start_mode="gui",
        )
        calls = [c.args[0] for c in mock_cmd.call_args_list]
        self.assertEqual(
            calls[1],
            [
                "clonevm",
                "Kali-Base",
                "--name",
                "Kali-Worker-1",
                "--mode",
                "machine",
                "--register",
                "--snapshot",
                "clean-base",
                "--options",
                "link",
            ],
        )
        self.assertEqual(calls[4], ["startvm", "Kali-Worker-1", "--type", "gui"])
        self.assertIn("Linked clone from `Kali-Base`", out_linked)

        mock_cmd.reset_mock()
        mock_cmd.side_effect = [
            server.CommandResult(0, '"Kali-Base" {1111-2222}', ""),
            server.CommandResult(0, "", ""),  # clonevm
            server.CommandResult(0, "", ""),  # modifyvm
        ]
        out_full = server.provision_kali_vm(
            vm_name="Kali-Full",
            base_vm="Kali-Base",
            linked_clone=False,
            take_clean_snapshot=False,
        )
        calls_full = [c.args[0] for c in mock_cmd.call_args_list]
        self.assertEqual(
            calls_full[1],
            ["clonevm", "Kali-Base", "--name", "Kali-Full", "--mode", "machine", "--register"],
        )
        self.assertIn("Full clone from `Kali-Base`", out_full)
        self.assertIn("Baseline Snapshot:** Skipped", out_full)

    @patch("server.run_vbox_cmd")
    def test_provision_kali_vm_download_and_ova_and_env_fallbacks(
        self, mock_cmd: MagicMock
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dl_archive = os.path.join(tmpdir, "kali-linux-2026.3-virtualbox-amd64.7z")
            with open(dl_archive, "wb") as f:
                f.write(b"7z")
            vbox_dir = os.path.join(tmpdir, "vbox_out")

            def _fake_extract(_arch: str, dest: str, timeout: int = 600) -> str:
                os.makedirs(dest, exist_ok=True)
                with open(os.path.join(dest, "kali.vbox"), "w", encoding="utf-8") as xf:
                    xf.write('<VirtualBox><Machine uuid="{dddd-4444}" name="KaliDL" OSType="Debian_64"/></VirtualBox>')
                return dest

            mock_cmd.side_effect = [
                server.CommandResult(0, "", ""),  # list vms
                server.CommandResult(0, "", ""),  # registervm
                server.CommandResult(0, "", ""),  # modifyvm
            ]
            with patch.dict(os.environ, {"VBOX_KALI_CACHE_DIR": tmpdir}, clear=False), patch(
                "server._download_kali_image",
                return_value=(dl_archive, "e" * 64, False),
            ) as mock_dl, patch("server._extract_7z_archive", side_effect=_fake_extract):
                out_dl = server.provision_kali_vm(
                    vm_name="Kali-Net",
                    download=True,
                    extract_dir=vbox_dir,
                    take_clean_snapshot=False,
                )
            mock_dl.assert_called_once_with(tmpdir, verify_checksum=True, timeout=1800)
            self.assertIn("SHA-256 verified", out_dl)

            # `.ova` appliance path uses `import` + `modifyvm`.
            ova_path = os.path.join(tmpdir, "kali.ova")
            with open(ova_path, "wb") as f:
                f.write(b"ova")
            mock_cmd.reset_mock()
            mock_cmd.side_effect = [
                server.CommandResult(0, "", ""),  # list vms
                server.CommandResult(0, "", ""),  # import
                server.CommandResult(0, "", ""),  # modifyvm
            ]
            out_ova = server.provision_kali_vm(
                vm_name="Kali-OVA", image_path=ova_path, take_clean_snapshot=False
            )
            calls_ova = [c.args[0] for c in mock_cmd.call_args_list]
            self.assertEqual(
                calls_ova[1],
                [
                    "import",
                    os.path.abspath(ova_path),
                    "--vsys",
                    "0",
                    "--vmname",
                    "Kali-OVA",
                    "--vsys",
                    "0",
                    "--cpus",
                    "2",
                    "--vsys",
                    "0",
                    "--memory",
                    "4096",
                ],
            )
            self.assertEqual(
                calls_ova[2],
                ["modifyvm", "Kali-OVA", "--vram", "128", "--nic1", "nat", "--clipboard-mode", "bidirectional"],
            )
            self.assertIn("### Provisioned Kali Linux VM: Kali-OVA", out_ova)

            # `VBOX_KALI_BASE_VM` fallback.
            mock_cmd.reset_mock()
            mock_cmd.side_effect = [
                server.CommandResult(0, '"Kali-Gold" {9999}', ""),
                server.CommandResult(0, "", ""),
                server.CommandResult(0, "", ""),
            ]
            with patch.dict(
                os.environ, {"VBOX_KALI_BASE_VM": "Kali-Gold", "VBOX_KALI_IMAGE_PATH": ""}, clear=False
            ):
                out_env_base = server.provision_kali_vm(
                    vm_name="Kali-EnvClone", take_clean_snapshot=False
                )
            self.assertIn("Linked clone from `Kali-Gold`", out_env_base)

            # `VBOX_KALI_IMAGE_PATH` fallback (with `.vbox` file).
            env_vbox = os.path.join(tmpdir, "env_kali.vbox")
            with open(env_vbox, "w", encoding="utf-8") as xf:
                xf.write('<VirtualBox><Machine uuid="{eeee-5555}" name="KaliEnv" OSType="Debian_64"/></VirtualBox>')
            mock_cmd.reset_mock()
            mock_cmd.side_effect = [
                server.CommandResult(0, "", ""),
                server.CommandResult(0, "", ""),
                server.CommandResult(0, "", ""),
            ]
            with patch.dict(
                os.environ, {"VBOX_KALI_BASE_VM": "", "VBOX_KALI_IMAGE_PATH": env_vbox}, clear=False
            ):
                out_env_img = server.provision_kali_vm(
                    vm_name="Kali-EnvImg", take_clean_snapshot=False
                )
            self.assertIn("Configured VBOX_KALI_IMAGE_PATH", out_env_img)

            # Cached `.7z` in `VBOX_KALI_CACHE_DIR` fallback when no args/env image/base given.
            mock_cmd.reset_mock()
            mock_cmd.side_effect = [
                server.CommandResult(0, "", ""),  # list vms
                server.CommandResult(0, "", ""),  # systemproperties
                server.CommandResult(0, "", ""),  # registervm
                server.CommandResult(0, "", ""),  # modifyvm
            ]
            cache_extract = os.path.join(tmpdir, "cache_vm_extract")
            with patch.dict(
                os.environ,
                {
                    "VBOX_KALI_BASE_VM": "",
                    "VBOX_KALI_IMAGE_PATH": "",
                    "VBOX_KALI_CACHE_DIR": tmpdir,
                },
                clear=False,
            ), patch("server._extract_7z_archive", side_effect=_fake_extract):
                out_cached = server.provision_kali_vm(
                    vm_name="Kali-Cached",
                    extract_dir=cache_extract,
                    take_clean_snapshot=False,
                )
            self.assertIn("Cached Kali Linux VirtualBox archive", out_cached)

    @patch("server.run_vbox_cmd")
    def test_provision_kali_vm_guards_collisions_iso_and_missing_source(
        self, mock_cmd: MagicMock
    ) -> None:
        # Duplicate VM name aborts before touching downloads or extraction.
        mock_cmd.return_value = server.CommandResult(0, '"Kali-Agent" {1111-2222}', "")
        dup_out = server.provision_kali_vm(vm_name="Kali-Agent", download=True)
        self.assertIn("already registered", dup_out)
        mock_cmd.assert_called_once_with(["list", "vms"])

        with tempfile.TemporaryDirectory() as tmpdir:
            # UUID collision on `.vbox` gives actionable `base_vm` / `clone_vm` guidance.
            vbox_file = os.path.join(tmpdir, "dup.vbox")
            with open(vbox_file, "w", encoding="utf-8") as xf:
                xf.write(
                    '<VirtualBox><Machine uuid="{1111-2222}" name="Kali-Orig" OSType="Debian_64"/></VirtualBox>'
                )
            mock_cmd.reset_mock()
            mock_cmd.return_value = server.CommandResult(0, '"Kali-Orig" {1111-2222}', "")
            uuid_err = server.provision_kali_vm(vm_name="Kali-Second", image_path=vbox_file)
            self.assertIn("already registered under VM 'Kali-Orig'", uuid_err)
            self.assertIn("base_vm='Kali-Orig'", uuid_err)
            mock_cmd.assert_called_once_with(["list", "vms"])

            # `.iso` directs caller to `create_vm(..., os_type='Debian_64', ...)`.
            mock_cmd.reset_mock()
            mock_cmd.return_value = server.CommandResult(0, "", "")
            iso_err = server.provision_kali_vm(
                vm_name="Kali-ISO", image_path=os.path.join(tmpdir, "kali-installer.iso")
            )
            self.assertIn("os_type='Debian_64'", iso_err)

            # Missing source with `download=False`, no env, and empty cache returns clear instructions.
            mock_cmd.reset_mock()
            mock_cmd.return_value = server.CommandResult(0, "", "")
            with patch.dict(
                os.environ,
                {
                    "VBOX_KALI_BASE_VM": "",
                    "VBOX_KALI_IMAGE_PATH": "",
                    "VBOX_KALI_CACHE_DIR": tmpdir,
                },
                clear=False,
            ):
                missing_err = server.provision_kali_vm(vm_name="Kali-None", download=False)
            self.assertIn("No Kali Linux provisioning source found", missing_err)
            self.assertIn("download=True", missing_err)

    def test_native_tool_annotations_and_no_monkey_patch(self) -> None:
        self.assertFalse(hasattr(server, "_patched_tool"))
        tools = asyncio.run(server.mcp.list_tools())
        self.assertEqual(len(tools), 22)
        by_name = {t.name: t for t in tools}

        for ro_name in ("list_vms", "get_vm_info", "get_vm_ip", "list_os_types", "export_vm"):
            ann = by_name[ro_name].annotations
            assert ann is not None
            self.assertTrue(ann.read_only_hint)
            self.assertFalse(ann.destructive_hint)

        for dest_name in (
            "manage_power",
            "manage_snapshot",
            "execute_guest_command",
            "unattended_install",
            "delete_vm",
        ):
            ann = by_name[dest_name].annotations
            assert ann is not None
            self.assertFalse(ann.read_only_hint)
            self.assertTrue(ann.destructive_hint)

        reg_ann = by_name["register_vm"].annotations
        assert reg_ann is not None
        self.assertFalse(reg_ann.read_only_hint)
        self.assertFalse(reg_ann.destructive_hint)
        self.assertFalse(reg_ann.open_world_hint)

        kali_ann = by_name["provision_kali_vm"].annotations
        assert kali_ann is not None
        self.assertFalse(kali_ann.read_only_hint)
        self.assertFalse(kali_ann.destructive_hint)
        self.assertTrue(kali_ann.open_world_hint)

        self.assertTrue(by_name["execute_guest_command"].annotations.open_world_hint)
        resources = asyncio.run(server.mcp.list_resources())
        self.assertEqual([str(r.uri) for r in resources], ["vbox://vms"])


if __name__ == "__main__":
    unittest.main()
