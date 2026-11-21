from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from functools import wraps
from typing import Callable, Literal, Optional, TypeVar

from fastmcp import FastMCP

# Configure logging exclusively to stderr so stdout remains clean for MCP stdio JSON-RPC.
logger = logging.getLogger("mcp-virtualbox")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(_handler)
logger.setLevel(
    getattr(logging, os.environ.get("VBOX_LOG_LEVEL", "WARNING").upper(), logging.WARNING)
)
logger.propagate = False

mcp = FastMCP("VirtualBox Manager")

F = TypeVar("F", bound=Callable[..., str])

VALID_POWER_ACTIONS = ("start", "stop", "force-stop", "reset", "savestate", "pause", "resume")
VALID_START_MODES = ("headless", "gui", "separate")
VALID_SNAPSHOT_ACTIONS = ("list", "take", "restore", "delete")
VALID_PORT_ACTIONS = ("list", "add", "delete")
VALID_PROTOCOLS = ("tcp", "udp")
VALID_FOLDER_ACTIONS = ("list", "add", "remove")
VALID_CLIPBOARD_MODES = ("disabled", "hosttoguest", "guesttohost", "bidirectional")
VALID_CLONE_MODES = ("machine", "machineandchildren", "all")
VALID_NIC_MODES = ("nat", "bridged", "hostonly", "intnet", "none")
VALID_STORAGE_ACTIONS = ("list", "attach-iso", "eject-iso")

_VM_LINE_RE = re.compile(r'^"(?P<name>.*)"\s+\{(?P<uuid>[^}]+)\}\s*$')


@dataclass
class CommandResult:
    """Structured result of a VBoxManage subprocess execution."""

    returncode: int
    stdout: str
    stderr: str
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and self.error is None


class RateLimiter:
    """Thread-safe sliding-window rate limiter applied at the MCP tool boundary."""

    def __init__(self, max_calls: Optional[int] = None, window_seconds: float = 60.0) -> None:
        self._explicit_max_calls = max_calls
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def _effective_limit(self) -> int:
        if self._explicit_max_calls is not None:
            return self._explicit_max_calls
        raw = os.environ.get("VBOX_MAX_CALLS_PER_MINUTE", "60").strip()
        try:
            return int(raw)
        except ValueError:
            logger.warning("Invalid VBOX_MAX_CALLS_PER_MINUTE=%r; defaulting to 60", raw)
            return 60

    def acquire(self) -> None:
        limit = self._effective_limit()
        if limit <= 0:
            return

        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            while self._timestamps and self._timestamps[0] <= cutoff:
                self._timestamps.popleft()
            if len(self._timestamps) >= limit:
                raise RuntimeError(
                    f"429 Too Many Requests: Rate limit exceeded (max {limit} calls per {int(self.window_seconds)}s)."
                )
            self._timestamps.append(now)

    def reset(self) -> None:
        """Clear recorded timestamps (primarily for isolated unit tests)."""
        with self._lock:
            self._timestamps.clear()


rate_limiter = RateLimiter()


def check_auth() -> None:
    """Enforce optional strict local token authentication via environment variables."""
    if os.environ.get("VBOX_REQUIRE_STRICT_AUTH", "").strip().lower() == "true":
        if not os.environ.get("VBOX_API_TOKEN", "").strip():
            raise PermissionError(
                "401 Unauthorized: VBOX_API_TOKEN is required when VBOX_REQUIRE_STRICT_AUTH=true."
            )


def tool_guard(func: F) -> F:
    """Enforce auth and rate limiting once per MCP tool invocation."""

    @wraps(func)
    def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        try:
            check_auth()
            rate_limiter.acquire()
        except (PermissionError, RuntimeError) as exc:
            return f"Error: {exc}"
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _validate_identifier(value: str, field_name: str) -> str:
    """Validate a VM, snapshot, rule, or folder identifier and block CLI flag injection."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty.")
    if cleaned.startswith("-"):
        raise ValueError(f"{field_name} cannot start with '-' (invalid identifier).")
    if any(ord(ch) < 32 for ch in cleaned):
        raise ValueError(f"{field_name} contains invalid control characters.")
    return cleaned


def _validate_path_arg(value: str, field_name: str) -> str:
    """Validate a filesystem or executable path argument."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty.")
    if cleaned.startswith("-"):
        raise ValueError(f"{field_name} cannot start with '-'.")
    if any(ch in cleaned for ch in ("\x00", "\r", "\n")):
        raise ValueError(f"{field_name} contains invalid control characters.")
    return cleaned


def _validate_int_range(value: int, field_name: str, minimum: int, maximum: int) -> int:
    """Validate an integer parameter within [minimum, maximum] (excluding bool)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer between {minimum} and {maximum}.")
    if value < minimum or value > maximum:
        raise ValueError(f"{field_name} must be between {minimum} and {maximum} (got {value}).")
    return value


def _validate_port(port: Optional[int], field_name: str) -> int:
    """Validate a TCP/UDP port number (1-65535)."""
    if port is None:
        raise ValueError(f"{field_name} is required.")
    return _validate_int_range(port, field_name, 1, 65535)


def _redact_cmd(cmd: list[str]) -> str:
    """Format a command line with any password or password-file values masked."""
    redacted: list[str] = []
    mask_next = False
    for token in cmd:
        if mask_next:
            redacted.append("***")
            mask_next = False
            continue
        if token in ("--password", "--password-file"):
            redacted.append(token)
            mask_next = True
        elif token.startswith("--password="):
            redacted.append("--password=***")
        elif token.startswith("--password-file="):
            redacted.append("--password-file=***")
        else:
            redacted.append(token)
    return " ".join(redacted)


def _extract_secrets(args: list[str]) -> list[str]:
    """Collect any sensitive password values from CLI args for output scrubbing."""
    secrets: list[str] = []
    capture_next = False
    for token in args:
        if capture_next:
            if token:
                secrets.append(token)
            capture_next = False
            continue
        if token == "--password":
            capture_next = True
        elif token.startswith("--password="):
            val = token.split("=", 1)[1]
            if val:
                secrets.append(val)
    return secrets


def _scrub_secrets(text: str, secrets: list[str]) -> str:
    """Scrub secret strings from subprocess output or error text."""
    for secret in secrets:
        text = text.replace(secret, "***")
    return text


def _resolve_guest_credentials(
    username: Optional[str], password: Optional[str]
) -> tuple[str, Optional[str]]:
    """Resolve guest credentials from explicit arguments or environment fallbacks."""
    raw_user = username if username is not None else os.environ.get("VBOX_GUEST_USER", "")
    resolved_user = _validate_identifier(raw_user, "username")
    resolved_pass = password if password is not None else os.environ.get("VBOX_GUEST_PASSWORD")
    if resolved_pass is not None and any(ch in resolved_pass for ch in ("\x00", "\r", "\n")):
        raise ValueError("password contains invalid control characters.")
    return resolved_user, resolved_pass


def get_vboxmanage_path() -> str:
    """Locate and return the absolute path to the VBoxManage executable."""
    env_path = os.environ.get("VBOXMANAGE_PATH", "").strip()
    if env_path:
        if os.path.exists(env_path):
            return env_path
        raise FileNotFoundError(
            f"VBOXMANAGE_PATH is set to '{env_path}', but the executable was not found."
        )

    path_hit = shutil.which("VBoxManage")
    if path_hit:
        return path_hit

    candidates: list[str] = []
    if sys.platform == "win32":
        prog_files = os.environ.get("ProgramFiles")
        if prog_files:
            candidates.append(os.path.join(prog_files, "Oracle", "VirtualBox", "VBoxManage.exe"))
        candidates.append(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
    else:
        candidates.extend(
            [
                "/Applications/VirtualBox.app/Contents/MacOS/VBoxManage",
                "/usr/bin/VBoxManage",
                "/usr/local/bin/VBoxManage",
                "/opt/VirtualBox/VBoxManage",
            ]
        )

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    raise FileNotFoundError(
        "VBoxManage executable not found in PATH or standard locations. "
        "Install Oracle VirtualBox or set VBOXMANAGE_PATH."
    )


def run_vbox_cmd(args: list[str], timeout: int = 60) -> CommandResult:
    """Execute a VBoxManage command safely without invoking a shell."""
    try:
        vbox_path = get_vboxmanage_path()
    except FileNotFoundError as exc:
        return CommandResult(returncode=-1, stdout="", stderr="", error=str(exc))

    cmd = [vbox_path, *args]
    redacted = _redact_cmd(cmd)
    secrets = _extract_secrets(args)
    logger.debug("Executing: %s", redacted)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr="",
            error=f"Command '{redacted}' timed out after {timeout} seconds.",
        )
    except Exception as exc:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr="",
            error=_scrub_secrets(f"Unexpected error running '{redacted}': {exc}", secrets),
        )

    stdout = _scrub_secrets(proc.stdout.strip(), secrets)
    stderr = _scrub_secrets(proc.stderr.strip(), secrets)

    if proc.returncode != 0:
        details = stderr or stdout or "No error details provided."
        return CommandResult(
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            error=f"Command '{redacted}' failed (exit code {proc.returncode}): {details}",
        )

    return CommandResult(returncode=0, stdout=stdout, stderr=stderr, error=None)


def parse_machinereadable(output: str) -> dict[str, str]:
    """Parse VBoxManage `--machinereadable` key=value output into a dictionary."""
    data: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, raw_val = line.split("=", 1)
        key = key.strip()
        val = raw_val.strip()
        if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
            val = val[1:-1].replace('\\"', '"')
        data[key] = val
    return data


def _parse_vm_entries(output: str) -> list[tuple[str, str]]:
    """Parse lines like '"Ubuntu-Dev" {uuid}' into (name, uuid) pairs."""
    entries: list[tuple[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _VM_LINE_RE.match(line)
        if match:
            entries.append((match.group("name"), match.group("uuid")))
        else:
            entries.append((line, ""))
    return entries


def _extract_forwarding_rules(parsed: dict[str, str]) -> list[str]:
    """Extract formatted NAT port forwarding rules from parsed showvminfo output."""
    rules: list[str] = []
    for key, val in parsed.items():
        if key.startswith("Forwarding(") and val:
            parts = val.split(",")
            if len(parts) >= 6:
                rule_name, proto, host_ip, host_port, guest_ip, guest_port = parts[:6]
                host_bind = f"{host_ip or '*'}:{host_port}"
                guest_bind = f"{guest_ip or '*'}:{guest_port}"
                rules.append(f"- `{rule_name}` ({proto.upper()}): {host_bind} -> {guest_bind}")
            else:
                rules.append(f"- {val}")
    return rules


def _extract_shared_folders(parsed: dict[str, str]) -> list[str]:
    """Extract formatted shared folder mappings from parsed showvminfo output."""
    folders: list[str] = []
    for scope, prefix in (("permanent", "MachineMapping"), ("transient", "TransientMapping")):
        name_prefix = f"SharedFolderName{prefix}"
        path_prefix = f"SharedFolderPath{prefix}"
        for key, name in parsed.items():
            if key.startswith(name_prefix):
                idx = key[len(name_prefix) :]
                host_path = parsed.get(f"{path_prefix}{idx}", "<unknown>")
                folders.append(f"- `{name}` ({scope}) -> `{host_path}`")
    return folders


@mcp.tool(
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def list_vms(running_only: bool = False) -> str:
    """
    List registered VirtualBox virtual machines and their power states.

    Args:
        running_only (bool): When True, only return currently running VMs.

    Returns:
        str: Markdown-formatted list of VMs with UUIDs and RUNNING/STOPPED status.
    """
    running_res = run_vbox_cmd(["list", "runningvms"])
    if not running_res.ok:
        return f"Error: {running_res.error}"

    running_entries = _parse_vm_entries(running_res.stdout)
    running_uuids = {uuid for _, uuid in running_entries if uuid}
    running_names = {name for name, _ in running_entries}

    if running_only:
        if not running_entries:
            return "No running VirtualBox VMs found."
        lines = [
            f"- **{name}** (`{uuid}`) [RUNNING]" if uuid else f"- **{name}** [RUNNING]"
            for name, uuid in running_entries
        ]
        return "### Running VirtualBox VMs\n" + "\n".join(lines)

    all_res = run_vbox_cmd(["list", "vms"])
    if not all_res.ok:
        return f"Error: {all_res.error}"

    all_entries = _parse_vm_entries(all_res.stdout)
    if not all_entries:
        return "No VirtualBox VMs found on this system."

    lines = []
    for name, uuid in all_entries:
        is_running = (uuid in running_uuids) if uuid else (name in running_names)
        state = "RUNNING" if is_running else "STOPPED"
        lines.append(
            f"- **{name}** (`{uuid}`) [{state}]" if uuid else f"- **{name}** [{state}]"
        )
    return "### Registered VirtualBox VMs\n" + "\n".join(lines)


@mcp.tool(
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def get_vm_info(vm_name: str, verbose: bool = False) -> str:
    """
    Return configuration and state details for a virtual machine.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        verbose (bool): If True, return the raw `VBoxManage showvminfo` output.

    Returns:
        str: Structured Markdown summary (or raw output when verbose=True).
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
    except ValueError as exc:
        return f"Error: {exc}"

    args = ["showvminfo", vm] if verbose else ["showvminfo", vm, "--machinereadable"]
    res = run_vbox_cmd(args)
    if not res.ok:
        return f"Error: Failed to get info for VM '{vm}': {res.error}"

    if verbose:
        return f"### Info for VM: {vm}\n```\n{res.stdout}\n```"

    parsed = parse_machinereadable(res.stdout)
    name = parsed.get("name", vm)
    uuid = parsed.get("UUID", "unknown")
    os_type = parsed.get("ostype", "unknown")
    state = parsed.get("VMState", "unknown")
    cpus = parsed.get("cpus", "unknown")
    memory = parsed.get("memory", "unknown")
    vram = parsed.get("vram", "unknown")
    clipboard = parsed.get("clipboard", "unknown")
    current_snap = parsed.get("CurrentSnapshotName", "None")

    nic_lines = []
    for idx in range(1, 9):
        nic_type = parsed.get(f"nic{idx}")
        if nic_type and nic_type.lower() != "none":
            mac = parsed.get(f"macaddress{idx}", "")
            nic_lines.append(f"- NIC {idx}: `{nic_type}`" + (f" (MAC: `{mac}`)" if mac else ""))

    forwards = _extract_forwarding_rules(parsed)
    folders = _extract_shared_folders(parsed)

    sections = [
        f"### VM Summary: {name}",
        f"- **UUID:** `{uuid}`",
        f"- **State:** `{state}`",
        f"- **OS Type:** {os_type}",
        f"- **Resources:** {cpus} vCPU(s), {memory} MB RAM, {vram} MB VRAM",
        f"- **Clipboard Mode:** `{clipboard}`",
        f"- **Current Snapshot:** {current_snap}",
    ]
    if nic_lines:
        sections.append("\n#### Network Adapters\n" + "\n".join(nic_lines))
    if forwards:
        sections.append("\n#### NAT Port Forwarding\n" + "\n".join(forwards))
    if folders:
        sections.append("\n#### Shared Folders\n" + "\n".join(folders))

    return "\n".join(sections)


@mcp.tool(
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def get_vm_ip(vm_name: str) -> str:
    """
    Discover guest IP addresses and Guest Additions version via guest properties.

    Args:
        vm_name (str): The name or UUID of the virtual machine.

    Returns:
        str: Reported IPv4/IPv6 addresses per network interface and Guest Additions version.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
    except ValueError as exc:
        return f"Error: {exc}"

    res = run_vbox_cmd(["guestproperty", "enumerate", vm])
    if not res.ok:
        return f"Error: Failed to query guest properties for '{vm}': {res.error}"

    props: dict[str, str] = {}
    prop_re = re.compile(r"^([^,]+),\s*value:\s*([^,]*?)(?:,\s*timestamp:|$)")
    for line in res.stdout.splitlines():
        match = prop_re.match(line.strip())
        if match:
            props[match.group(1).strip()] = match.group(2).strip()

    ga_version = props.get("/VirtualBox/GuestAdd/Version")
    net_indices = sorted(
        {
            m.group(1)
            for k in props
            if (m := re.match(r"^/VirtualBox/GuestInfo/Net/(\d+)/", k)) is not None
        },
        key=int,
    )

    iface_lines: list[str] = []
    for idx in net_indices:
        v4 = props.get(f"/VirtualBox/GuestInfo/Net/{idx}/V4/IP", "")
        mask = props.get(f"/VirtualBox/GuestInfo/Net/{idx}/V4/Netmask", "")
        v6 = props.get(f"/VirtualBox/GuestInfo/Net/{idx}/V6/IP", "")
        if v4 or v6:
            parts = []
            if v4:
                parts.append(f"IPv4: `{v4}`" + (f" (netmask `{mask}`)" if mask else ""))
            if v6:
                parts.append(f"IPv6: `{v6}`")
            iface_lines.append(f"- Interface {idx}: " + ", ".join(parts))

    if not iface_lines:
        hint = (
            f" Guest Additions version detected: `{ga_version}`."
            if ga_version
            else " Ensure the VM is running and VirtualBox Guest Additions are installed."
        )
        return f"No IP addresses reported yet for VM '{vm}'.{hint}"

    header = f"### Network Addresses for VM: {vm}"
    if ga_version:
        header += f"\n- **Guest Additions Version:** `{ga_version}`"
    return header + "\n" + "\n".join(iface_lines)


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    }
)
@tool_guard
def manage_power(
    vm_name: str,
    action: Literal["start", "stop", "force-stop", "reset", "savestate", "pause", "resume"],
    mode: Literal["headless", "gui", "separate"] = "headless",
) -> str:
    """
    Control the power state of a virtual machine.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        action (str): One of "start", "stop", "force-stop", "reset", "savestate", "pause", "resume".
        mode (str): Launch UI mode when action is "start" ("headless", "gui", or "separate").

    Returns:
        str: Operation confirmation or error details.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
    except ValueError as exc:
        return f"Error: {exc}"

    if action not in VALID_POWER_ACTIONS:
        return f"Error: Invalid action '{action}'. Must be one of {list(VALID_POWER_ACTIONS)}."
    if mode not in VALID_START_MODES:
        return f"Error: Invalid start mode '{mode}'. Must be one of {list(VALID_START_MODES)}."

    if action == "start":
        cmd = ["startvm", vm, "--type", mode]
    else:
        control_map = {
            "stop": "acpipowerbutton",
            "force-stop": "poweroff",
            "reset": "reset",
            "savestate": "savestate",
            "pause": "pause",
            "resume": "resume",
        }
        cmd = ["controlvm", vm, control_map[action]]

    res = run_vbox_cmd(cmd)
    if not res.ok:
        return f"Error: Failed to '{action}' VM '{vm}': {res.error}"

    details = f"\n```\n{res.stdout}\n```" if res.stdout else ""
    return f"Successfully executed power action '{action}' on VM '{vm}'.{details}"


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    }
)
@tool_guard
def manage_snapshot(
    vm_name: str,
    action: Literal["list", "take", "restore", "delete"],
    snapshot_name: str = "",
    description: str = "",
    live: bool = False,
) -> str:
    """
    List, take, restore, or delete snapshots for a virtual machine.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        action (str): One of "list", "take", "restore", "delete".
        snapshot_name (str): Required for "take", "restore", and "delete".
        description (str): Optional description when taking a snapshot.
        live (bool): Take a live snapshot without pausing a running VM (only for "take").

    Returns:
        str: Snapshot list or confirmation message.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
    except ValueError as exc:
        return f"Error: {exc}"

    if action not in VALID_SNAPSHOT_ACTIONS:
        return f"Error: Invalid action '{action}'. Must be one of {list(VALID_SNAPSHOT_ACTIONS)}."

    if action == "list":
        cmd = ["snapshot", vm, "list"]
    else:
        try:
            snap = _validate_identifier(snapshot_name, "snapshot_name")
        except ValueError as exc:
            return f"Error: {exc}"

        cmd = ["snapshot", vm, action, snap]
        if action == "take":
            if description:
                cmd.extend(["--description", description])
            if live:
                cmd.append("--live")

    res = run_vbox_cmd(cmd, timeout=120)
    if not res.ok:
        return f"Error: Failed to '{action}' snapshot on VM '{vm}': {res.error}"

    if action == "list":
        body = res.stdout or "No snapshots found."
        return f"### Snapshots for VM: {vm}\n```\n{body}\n```"

    details = f"\n```\n{res.stdout}\n```" if res.stdout else ""
    return f"Successfully executed snapshot action '{action}' on VM '{vm}'.{details}"


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    }
)
@tool_guard
def execute_guest_command(
    vm_name: str,
    command: str,
    args: Optional[list[str]] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    timeout: int = 120,
) -> str:
    """
    Execute a command inside a running guest VM via VirtualBox Guest Additions.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        command (str): Path to the executable inside the guest OS.
        args (list[str], optional): Command arguments passed to the executable.
        username (str, optional): Guest username (falls back to VBOX_GUEST_USER env var).
        password (str, optional): Guest password (falls back to VBOX_GUEST_PASSWORD env var).
        cwd (str, optional): Working directory inside the guest OS.
        env (dict[str, str], optional): Environment variables to inject into the guest process.
        timeout (int): Maximum execution wait time in seconds (1-3600).

    Returns:
        str: Command output or redacted error details.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        exe = _validate_path_arg(command, "command")
        resolved_user, resolved_pass = _resolve_guest_credentials(username, password)
        validated_timeout = _validate_int_range(timeout, "timeout", 1, 3600)
        if cwd is not None:
            cwd = _validate_path_arg(cwd, "cwd")
    except ValueError as exc:
        return f"Error: {exc}"

    cmd = [
        "guestcontrol",
        vm,
        "run",
        "--exe",
        exe,
        "--username",
        resolved_user,
    ]
    if resolved_pass:
        cmd.extend(["--password", resolved_pass])
    if cwd:
        cmd.extend(["--cwd", cwd])
    if env:
        for key, val in env.items():
            if any(ch in f"{key}{val}" for ch in ("\x00", "\r", "\n")):
                return "Error: Environment variable keys/values cannot contain control characters."
            cmd.extend(["--putenv", f"{key}={val}"])

    cmd.append("--")
    if args:
        cmd.extend(args)

    res = run_vbox_cmd(cmd, timeout=validated_timeout)
    if not res.ok:
        return f"Error: Failed to execute guest command on VM '{vm}': {res.error}"

    parts = [f"Guest command executed successfully on VM '{vm}' (exit code 0)."]
    if res.stdout:
        parts.append(f"### Output\n```\n{res.stdout}\n```")
    if res.stderr:
        parts.append(f"### Stderr\n```\n{res.stderr}\n```")
    return "\n".join(parts)


def _run_guest_transfer(
    direction: Literal["copyto", "copyfrom"],
    vm_name: str,
    source_path: str,
    dest_path: str,
    username: Optional[str],
    password: Optional[str],
    recursive: bool,
    timeout: int,
) -> str:
    """Shared implementation for copy_to_guest and copy_from_guest."""
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        src = _validate_path_arg(source_path, "host_path" if direction == "copyto" else "guest_path")
        dst = _validate_path_arg(dest_path, "guest_path" if direction == "copyto" else "host_path")
        resolved_user, resolved_pass = _resolve_guest_credentials(username, password)
        validated_timeout = _validate_int_range(timeout, "timeout", 1, 3600)
    except ValueError as exc:
        return f"Error: {exc}"

    if direction == "copyto" and not os.path.exists(src):
        return f"Error: Host source path '{src}' does not exist."

    cmd = [
        "guestcontrol",
        vm,
        direction,
        "--username",
        resolved_user,
    ]
    if resolved_pass:
        cmd.extend(["--password", resolved_pass])
    if recursive:
        cmd.append("--recursive")
    cmd.extend(["--target-directory", dst, src])

    res = run_vbox_cmd(cmd, timeout=validated_timeout)
    if not res.ok:
        return f"Error: Guest file transfer ({direction}) failed on VM '{vm}': {res.error}"

    return f"Successfully transferred '{src}' -> '{dst}' ({direction}) on VM '{vm}'."


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def copy_to_guest(
    vm_name: str,
    host_path: str,
    guest_path: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    recursive: bool = False,
    timeout: int = 120,
) -> str:
    """
    Copy a file or directory from the host into a running guest VM.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        host_path (str): Existing file or directory path on the host.
        guest_path (str): Destination directory inside the guest OS.
        username (str, optional): Guest username (falls back to VBOX_GUEST_USER).
        password (str, optional): Guest password (falls back to VBOX_GUEST_PASSWORD).
        recursive (bool): Recursively copy directories.
        timeout (int): Transfer timeout in seconds (1-3600).

    Returns:
        str: Transfer confirmation or error details.
    """
    return _run_guest_transfer(
        "copyto", vm_name, host_path, guest_path, username, password, recursive, timeout
    )


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def copy_from_guest(
    vm_name: str,
    guest_path: str,
    host_path: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    recursive: bool = False,
    timeout: int = 120,
) -> str:
    """
    Copy a file or directory from a running guest VM to the host.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        guest_path (str): File or directory path inside the guest OS.
        host_path (str): Destination directory on the host.
        username (str, optional): Guest username (falls back to VBOX_GUEST_USER).
        password (str, optional): Guest password (falls back to VBOX_GUEST_PASSWORD).
        recursive (bool): Recursively copy directories.
        timeout (int): Transfer timeout in seconds (1-3600).

    Returns:
        str: Transfer confirmation or error details.
    """
    return _run_guest_transfer(
        "copyfrom", vm_name, guest_path, host_path, username, password, recursive, timeout
    )


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }
)
@tool_guard
def manage_port_forwarding(
    vm_name: str,
    action: Literal["list", "add", "delete"],
    adapter: int = 1,
    rule_name: str = "",
    protocol: Literal["tcp", "udp"] = "tcp",
    host_ip: str = "127.0.0.1",
    host_port: Optional[int] = None,
    guest_ip: str = "",
    guest_port: Optional[int] = None,
    is_running: bool = False,
) -> str:
    """
    List, add, or delete NAT port-forwarding rules on a VM network adapter.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        action (str): One of "list", "add", "delete".
        adapter (int): VirtualBox NIC index (1-8).
        rule_name (str): Rule name (required for "add" and "delete").
        protocol (str): Transport protocol ("tcp" or "udp").
        host_ip (str): Host bind IP address (default "127.0.0.1").
        host_port (int, optional): Host port (1-65535, required for "add").
        guest_ip (str): Optional guest IP address.
        guest_port (int, optional): Guest port (1-65535, required for "add").
        is_running (bool): Set True to apply dynamically via `controlvm` on a running VM.

    Returns:
        str: List of rules or confirmation message.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        nic = _validate_int_range(adapter, "adapter", 1, 8)
    except ValueError as exc:
        return f"Error: {exc}"

    if action not in VALID_PORT_ACTIONS:
        return f"Error: Invalid action '{action}'. Must be one of {list(VALID_PORT_ACTIONS)}."

    if action == "list":
        res = run_vbox_cmd(["showvminfo", vm, "--machinereadable"])
        if not res.ok:
            return f"Error: Failed to inspect port forwarding for VM '{vm}': {res.error}"
        rules = _extract_forwarding_rules(parse_machinereadable(res.stdout))
        if not rules:
            return f"No NAT port-forwarding rules configured on VM '{vm}'."
        return f"### NAT Port Forwarding for VM: {vm}\n" + "\n".join(rules)

    try:
        rule = _validate_identifier(rule_name, "rule_name")
    except ValueError as exc:
        return f"Error: {exc}"

    if any(ch in rule for ch in (",", '"', "'")):
        return "Error: rule_name cannot contain commas or quotes."

    if action == "add":
        if protocol not in VALID_PROTOCOLS:
            return f"Error: Invalid protocol '{protocol}'. Must be 'tcp' or 'udp'."
        try:
            h_port = _validate_port(host_port, "host_port")
            g_port = _validate_port(guest_port, "guest_port")
        except ValueError as exc:
            return f"Error: {exc}"
        if any(ch in f"{host_ip}{guest_ip}" for ch in (",", "\x00", "\r", "\n")):
            return "Error: host_ip/guest_ip contains invalid characters."
        spec = f"{rule},{protocol},{host_ip},{h_port},{guest_ip},{g_port}"
        if is_running:
            cmd = ["controlvm", vm, f"natpf{nic}", spec]
        else:
            cmd = ["modifyvm", vm, f"--natpf{nic}", spec]
    else:
        if is_running:
            cmd = ["controlvm", vm, f"natpf{nic}", "delete", rule]
        else:
            cmd = ["modifyvm", vm, f"--natpf{nic}", "delete", rule]

    res = run_vbox_cmd(cmd)
    if not res.ok:
        return f"Error: Failed to {action} port-forwarding rule '{rule}' on VM '{vm}': {res.error}"

    return f"Successfully executed port-forwarding '{action}' for rule '{rule}' on VM '{vm}' (NIC {nic})."


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }
)
@tool_guard
def manage_shared_folders(
    vm_name: str,
    action: Literal["list", "add", "remove"],
    folder_name: str = "",
    host_path: str = "",
    readonly: bool = False,
    automount: bool = True,
    transient: bool = False,
) -> str:
    """
    List, add, or remove VirtualBox shared folders for a virtual machine.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        action (str): One of "list", "add", "remove".
        folder_name (str): Share name (required for "add" and "remove").
        host_path (str): Existing host directory path (required for "add").
        readonly (bool): Mount the shared folder read-only in the guest.
        automount (bool): Automatically mount the shared folder at boot.
        transient (bool): Apply only to the currently running VM session.

    Returns:
        str: Shared folder list or confirmation message.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
    except ValueError as exc:
        return f"Error: {exc}"

    if action not in VALID_FOLDER_ACTIONS:
        return f"Error: Invalid action '{action}'. Must be one of {list(VALID_FOLDER_ACTIONS)}."

    if action == "list":
        res = run_vbox_cmd(["showvminfo", vm, "--machinereadable"])
        if not res.ok:
            return f"Error: Failed to list shared folders for VM '{vm}': {res.error}"
        folders = _extract_shared_folders(parse_machinereadable(res.stdout))
        if not folders:
            return f"No shared folders configured on VM '{vm}'."
        return f"### Shared Folders for VM: {vm}\n" + "\n".join(folders)

    try:
        name = _validate_identifier(folder_name, "folder_name")
    except ValueError as exc:
        return f"Error: {exc}"

    if action == "add":
        try:
            path = _validate_path_arg(host_path, "host_path")
        except ValueError as exc:
            return f"Error: {exc}"
        if not os.path.isdir(path):
            return f"Error: Host directory '{path}' does not exist or is not a directory."

        cmd = ["sharedfolder", "add", vm, "--name", name, "--hostpath", path]
        if readonly:
            cmd.append("--readonly")
        if automount:
            cmd.append("--automount")
        if transient:
            cmd.append("--transient")
    else:
        cmd = ["sharedfolder", "remove", vm, "--name", name]
        if transient:
            cmd.append("--transient")

    res = run_vbox_cmd(cmd)
    if not res.ok:
        return f"Error: Failed to {action} shared folder '{name}' on VM '{vm}': {res.error}"

    return f"Successfully executed shared folder '{action}' for '{name}' on VM '{vm}'."


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def configure_vm_resources(
    vm_name: str,
    cpus: Optional[int] = None,
    memory_mb: Optional[int] = None,
    vram_mb: Optional[int] = None,
    clipboard_mode: Optional[
        Literal["disabled", "hosttoguest", "guesttohost", "bidirectional"]
    ] = None,
) -> str:
    """
    Modify CPU, RAM, VRAM, or shared clipboard settings on a stopped VM.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        cpus (int, optional): Number of virtual CPUs (1-128).
        memory_mb (int, optional): Base memory in MB (128-262144).
        vram_mb (int, optional): Video memory in MB (1-256).
        clipboard_mode (str, optional): One of "disabled", "hosttoguest", "guesttohost", "bidirectional".

    Returns:
        str: Confirmation of updated settings or error details.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        cmd = ["modifyvm", vm]
        changes: list[str] = []

        if cpus is not None:
            valid_cpus = _validate_int_range(cpus, "cpus", 1, 128)
            cmd.extend(["--cpus", str(valid_cpus)])
            changes.append(f"cpus={valid_cpus}")
        if memory_mb is not None:
            valid_mem = _validate_int_range(memory_mb, "memory_mb", 128, 262144)
            cmd.extend(["--memory", str(valid_mem)])
            changes.append(f"memory_mb={valid_mem}")
        if vram_mb is not None:
            valid_vram = _validate_int_range(vram_mb, "vram_mb", 1, 256)
            cmd.extend(["--vram", str(valid_vram)])
            changes.append(f"vram_mb={valid_vram}")
        if clipboard_mode is not None:
            if clipboard_mode not in VALID_CLIPBOARD_MODES:
                return (
                    f"Error: Invalid clipboard_mode '{clipboard_mode}'. "
                    f"Must be one of {list(VALID_CLIPBOARD_MODES)}."
                )
            cmd.extend(["--clipboard-mode", clipboard_mode])
            changes.append(f"clipboard_mode={clipboard_mode}")
    except ValueError as exc:
        return f"Error: {exc}"

    if not changes:
        return "Error: Specify at least one resource option (cpus, memory_mb, vram_mb, or clipboard_mode)."

    res = run_vbox_cmd(cmd)
    if not res.ok:
        return f"Error: Failed to configure resources for VM '{vm}': {res.error}"

    return f"Successfully updated VM '{vm}': {', '.join(changes)}."


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }
)
@tool_guard
def clone_vm(
    source_vm: str,
    new_name: str,
    mode: Literal["machine", "machineandchildren", "all"] = "machine",
    linked: bool = False,
    snapshot_name: str = "",
) -> str:
    """
    Clone an existing virtual machine (full or linked clone) and register it.

    Args:
        source_vm (str): Source VM name or UUID.
        new_name (str): Name for the new cloned VM.
        mode (str): Clone mode ("machine", "machineandchildren", or "all").
        linked (bool): Create a fast linked clone (requires snapshot_name).
        snapshot_name (str): Snapshot name to clone from (required when linked=True).

    Returns:
        str: Clone confirmation or error details.
    """
    try:
        src = _validate_identifier(source_vm, "source_vm")
        dst = _validate_identifier(new_name, "new_name")
    except ValueError as exc:
        return f"Error: {exc}"

    if mode not in VALID_CLONE_MODES:
        return f"Error: Invalid clone mode '{mode}'. Must be one of {list(VALID_CLONE_MODES)}."

    snap = snapshot_name.strip()
    if linked and not snap:
        return "Error: snapshot_name is required when creating a linked clone (linked=True)."

    cmd = ["clonevm", src, "--name", dst, "--mode", mode, "--register"]
    if snap:
        try:
            valid_snap = _validate_identifier(snap, "snapshot_name")
        except ValueError as exc:
            return f"Error: {exc}"
        cmd.extend(["--snapshot", valid_snap])
    if linked:
        cmd.extend(["--options", "link"])

    res = run_vbox_cmd(cmd, timeout=300)
    if not res.ok:
        return f"Error: Failed to clone VM '{src}' to '{dst}': {res.error}"

    clone_type = "linked clone" if linked else "clone"
    return f"Successfully created {clone_type} '{dst}' from '{src}'."


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def take_vm_screenshot(vm_name: str, output_path: str) -> str:
    """
    Capture a PNG screenshot of a running virtual machine's display.

    Args:
        vm_name (str): The name or UUID of the virtual machine.
        output_path (str): Host file path where the PNG screenshot will be saved.

    Returns:
        str: Saved screenshot path or error details.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        path = _validate_path_arg(output_path, "output_path")
    except ValueError as exc:
        return f"Error: {exc}"

    if not path.lower().endswith(".png"):
        path = f"{path}.png"

    abs_path = os.path.abspath(path)
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    res = run_vbox_cmd(["controlvm", vm, "screenshotpng", abs_path])
    if not res.ok:
        return f"Error: Failed to capture screenshot for VM '{vm}': {res.error}"

    return f"Screenshot saved for VM '{vm}' at '{abs_path}'."


def _parse_os_types(output: str) -> list[tuple[str, str, str]]:
    """Parse `VBoxManage list ostypes` blocks into (id, description, family) tuples."""
    entries: list[tuple[str, str, str]] = []
    current: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            if "ID" in current:
                entries.append(
                    (
                        current["ID"],
                        current.get("Description", ""),
                        current.get("Family Desc") or current.get("Family ID", "Unknown"),
                    )
                )
                current = {}
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            if key == "ID" and "ID" in current:
                entries.append(
                    (
                        current["ID"],
                        current.get("Description", ""),
                        current.get("Family Desc") or current.get("Family ID", "Unknown"),
                    )
                )
                current = {}
            current[key] = val.strip()
    if "ID" in current:
        entries.append(
            (
                current["ID"],
                current.get("Description", ""),
                current.get("Family Desc") or current.get("Family ID", "Unknown"),
            )
        )
    return entries


@mcp.tool(
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def list_os_types(search: str = "") -> str:
    """
    List supported VirtualBox guest OS type IDs (for use with `create_vm`).

    Args:
        search (str): Optional case-insensitive filter matched against OS ID, description, or family.

    Returns:
        str: Markdown list of matching guest OS types.
    """
    res = run_vbox_cmd(["list", "ostypes"])
    if not res.ok:
        return f"Error: Failed to list guest OS types: {res.error}"

    entries = _parse_os_types(res.stdout)
    if not entries:
        return "No guest OS types returned by VBoxManage."

    query = search.strip().lower()
    if query:
        entries = [
            item
            for item in entries
            if query in item[0].lower() or query in item[1].lower() or query in item[2].lower()
        ]
        if not entries:
            return f"No guest OS types matching '{search.strip()}'."

    lines = [f"- `{os_id}` — {desc} [{family}]" for os_id, desc, family in entries]
    header = f"### Supported Guest OS Types ({len(lines)})"
    return header + "\n" + "\n".join(lines)


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }
)
@tool_guard
def create_vm(
    vm_name: str,
    os_type: str = "Ubuntu_64",
    cpus: int = 2,
    memory_mb: int = 2048,
    vram_mb: int = 16,
    disk_size_mb: int = 20480,
    nic_mode: Literal["nat", "bridged", "hostonly", "intnet", "none"] = "nat",
    iso_path: str = "",
    base_folder: str = "",
) -> str:
    """
    Create and register a new VirtualBox VM with optional virtual disk and installer ISO.

    Args:
        vm_name (str): Name for the new virtual machine.
        os_type (str): VirtualBox OS type ID (e.g. "Ubuntu_64", "Debian_64", "Windows11_64").
        cpus (int): Virtual CPU count (1-128).
        memory_mb (int): Base RAM in MB (128-262144).
        vram_mb (int): Video memory in MB (1-256).
        disk_size_mb (int): New VDI disk size in MB (0 skips disk creation; max 2097152).
        nic_mode (str): NIC 1 mode ("nat", "bridged", "hostonly", "intnet", or "none").
        iso_path (str): Optional host path to an installer `.iso` file to attach to IDE.
        base_folder (str): Optional base directory where VM files are stored.

    Returns:
        str: Markdown summary of the created VM or error details.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        os_id = _validate_identifier(os_type, "os_type")
        valid_cpus = _validate_int_range(cpus, "cpus", 1, 128)
        valid_mem = _validate_int_range(memory_mb, "memory_mb", 128, 262144)
        valid_vram = _validate_int_range(vram_mb, "vram_mb", 1, 256)
        valid_disk = _validate_int_range(disk_size_mb, "disk_size_mb", 0, 2097152)
        iso = _validate_path_arg(iso_path, "iso_path") if iso_path.strip() else ""
        base_dir = _validate_path_arg(base_folder, "base_folder") if base_folder.strip() else ""
    except ValueError as exc:
        return f"Error: {exc}"

    if nic_mode not in VALID_NIC_MODES:
        return f"Error: Invalid nic_mode '{nic_mode}'. Must be one of {list(VALID_NIC_MODES)}."
    if iso and not os.path.isfile(iso):
        return f"Error: ISO file '{iso}' does not exist."

    create_cmd = ["createvm", "--name", vm, "--ostype", os_id, "--register"]
    if base_dir:
        create_cmd.extend(["--basefolder", base_dir])
    res = run_vbox_cmd(create_cmd)
    if not res.ok:
        return f"Error: Failed to create VM '{vm}': {res.error}"

    def _run_step(step_name: str, args: list[str], timeout: int = 60) -> Optional[str]:
        step_res = run_vbox_cmd(args, timeout=timeout)
        if not step_res.ok:
            return (
                f"Error: VM '{vm}' was registered, but step '{step_name}' failed: "
                f"{step_res.error}"
            )
        return None

    err = _run_step(
        "modifyvm",
        [
            "modifyvm",
            vm,
            "--cpus",
            str(valid_cpus),
            "--memory",
            str(valid_mem),
            "--vram",
            str(valid_vram),
            "--nic1",
            nic_mode,
        ],
    )
    if err:
        return err

    vdi_path = "None (skipped)"
    if valid_disk > 0:
        info_res = run_vbox_cmd(["showvminfo", vm, "--machinereadable"])
        cfg_file = parse_machinereadable(info_res.stdout).get("CfgFile", "") if info_res.ok else ""
        if cfg_file:
            vm_dir = os.path.dirname(cfg_file)
        elif base_dir:
            vm_dir = os.path.join(base_dir, vm)
        else:
            vm_dir = os.path.abspath(vm)
        vdi_path = os.path.join(vm_dir, f"{vm}.vdi")

        for step_name, args in (
            (
                "add SATA controller",
                ["storagectl", vm, "--name", "SATA Controller", "--add", "sata", "--controller", "IntelAhci"],
            ),
            (
                "create VDI disk",
                ["createmedium", "disk", "--filename", vdi_path, "--size", str(valid_disk), "--format", "VDI"],
            ),
            (
                "attach VDI disk",
                [
                    "storageattach",
                    vm,
                    "--storagectl",
                    "SATA Controller",
                    "--port",
                    "0",
                    "--device",
                    "0",
                    "--type",
                    "hdd",
                    "--medium",
                    vdi_path,
                ],
            ),
        ):
            err = _run_step(step_name, args, timeout=120)
            if err:
                return err

    if iso:
        for step_name, args in (
            ("add IDE controller", ["storagectl", vm, "--name", "IDE Controller", "--add", "ide"]),
            (
                "attach ISO",
                [
                    "storageattach",
                    vm,
                    "--storagectl",
                    "IDE Controller",
                    "--port",
                    "0",
                    "--device",
                    "0",
                    "--type",
                    "dvddrive",
                    "--medium",
                    iso,
                ],
            ),
        ):
            err = _run_step(step_name, args)
            if err:
                return err

    disk_summary = f"`{vdi_path}` ({valid_disk} MB)" if valid_disk > 0 else "None"
    return "\n".join(
        [
            f"### Created VM: {vm}",
            f"- **OS Type:** `{os_id}`",
            f"- **Resources:** {valid_cpus} vCPU(s), {valid_mem} MB RAM, {valid_vram} MB VRAM",
            f"- **NIC 1:** `{nic_mode}`",
            f"- **Disk:** {disk_summary}",
            f"- **ISO:** {f'`{iso}`' if iso else 'None'}",
        ]
    )


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    }
)
@tool_guard
def unattended_install(
    vm_name: str,
    iso_path: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    full_name: str = "",
    hostname: str = "",
    time_zone: str = "UTC",
    install_additions: bool = True,
    start_vm: bool = False,
) -> str:
    """
    Configure an unattended OS installation on a VM from an installer ISO.

    Args:
        vm_name (str): Name or UUID of an existing VM.
        iso_path (str): Host path to a supported OS installer `.iso`.
        username (str, optional): Guest admin/user account name (falls back to VBOX_GUEST_USER).
        password (str, optional): Account password (falls back to VBOX_GUEST_PASSWORD).
        full_name (str): Optional full name for the created guest user.
        hostname (str): Optional guest hostname.
        time_zone (str): Guest timezone (default "UTC").
        install_additions (bool): Install VirtualBox Guest Additions automatically.
        start_vm (bool): Immediately boot the VM headless to begin installation.

    Returns:
        str: Unattended setup confirmation or redacted error details.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        iso = _validate_path_arg(iso_path, "iso_path")
        resolved_user, resolved_pass = _resolve_guest_credentials(username, password)
        valid_host = _validate_identifier(hostname, "hostname") if hostname.strip() else ""
    except ValueError as exc:
        return f"Error: {exc}"

    if not os.path.isfile(iso):
        return f"Error: ISO file '{iso}' does not exist."
    if not resolved_pass:
        return (
            "Error: password is required for unattended installation "
            "(pass password or set VBOX_GUEST_PASSWORD)."
        )

    tz = time_zone.strip()
    if tz and (tz.startswith("-") or any(ord(ch) < 32 for ch in tz)):
        return "Error: time_zone contains invalid characters."
    clean_full = full_name.strip()
    if clean_full and any(ord(ch) < 32 for ch in clean_full):
        return "Error: full_name contains invalid control characters."

    cmd = [
        "unattended",
        "install",
        vm,
        f"--iso={iso}",
        f"--user={resolved_user}",
        f"--password={resolved_pass}",
    ]
    if clean_full:
        cmd.append(f"--full-user-name={clean_full}")
    if valid_host:
        cmd.append(f"--hostname={valid_host}")
    if tz:
        cmd.append(f"--time-zone={tz}")
    if install_additions:
        cmd.append("--install-additions")
    if start_vm:
        cmd.append("--start-vm=headless")

    res = run_vbox_cmd(cmd, timeout=180)
    if not res.ok:
        return f"Error: Unattended install setup failed for VM '{vm}': {res.error}"

    details = f"\n```\n{res.stdout}\n```" if res.stdout else ""
    return f"Successfully configured unattended installation for VM '{vm}' using '{iso}'.{details}"


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }
)
@tool_guard
def import_vm(
    appliance_path: str,
    vm_name: str = "",
    cpus: Optional[int] = None,
    memory_mb: Optional[int] = None,
    dry_run: bool = False,
    timeout: int = 600,
) -> str:
    """
    Import a pre-built `.ova` or `.ovf` virtual appliance into VirtualBox.

    Args:
        appliance_path (str): Host path to an `.ova` or `.ovf` file.
        vm_name (str): Optional override name for the imported VM.
        cpus (int, optional): Override vCPU count (1-128).
        memory_mb (int, optional): Override RAM in MB (128-262144).
        dry_run (bool): Inspect appliance manifest/requirements without importing.
        timeout (int): Import timeout in seconds (1-3600).

    Returns:
        str: Import summary or error details.
    """
    try:
        path = _validate_path_arg(appliance_path, "appliance_path")
        valid_name = _validate_identifier(vm_name, "vm_name") if vm_name.strip() else ""
        valid_cpus = _validate_int_range(cpus, "cpus", 1, 128) if cpus is not None else None
        valid_mem = (
            _validate_int_range(memory_mb, "memory_mb", 128, 262144)
            if memory_mb is not None
            else None
        )
        valid_timeout = _validate_int_range(timeout, "timeout", 1, 3600)
    except ValueError as exc:
        return f"Error: {exc}"

    if not os.path.isfile(path):
        return f"Error: Appliance file '{path}' does not exist."
    if not path.lower().endswith((".ova", ".ovf")):
        return "Error: appliance_path must point to a .ova or .ovf file."

    cmd = ["import", path]
    if dry_run:
        cmd.append("--dry-run")
    if valid_name:
        cmd.extend(["--vsys", "0", "--vmname", valid_name])
    if valid_cpus is not None:
        cmd.extend(["--vsys", "0", "--cpus", str(valid_cpus)])
    if valid_mem is not None:
        cmd.extend(["--vsys", "0", "--memory", str(valid_mem)])

    res = run_vbox_cmd(cmd, timeout=valid_timeout)
    if not res.ok:
        return f"Error: Failed to import appliance '{path}': {res.error}"

    action_word = "Dry-run inspection completed" if dry_run else "Successfully imported appliance"
    details = f"\n```\n{res.stdout}\n```" if res.stdout else ""
    return f"{action_word} for '{path}'.{details}"


@mcp.tool(
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def export_vm(vm_name: str, output_path: str, timeout: int = 600) -> str:
    """
    Export a stopped virtual machine to an `.ova` or `.ovf` appliance archive.

    Args:
        vm_name (str): Name or UUID of the VM to export.
        output_path (str): Host file path for the exported `.ova`/`.ovf` file (`.ova` appended if omitted).
        timeout (int): Export timeout in seconds (1-3600).

    Returns:
        str: Confirmation with output path or error details.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        path = _validate_path_arg(output_path, "output_path")
        valid_timeout = _validate_int_range(timeout, "timeout", 1, 3600)
    except ValueError as exc:
        return f"Error: {exc}"

    if not path.lower().endswith((".ova", ".ovf")):
        path = f"{path}.ova"

    abs_path = os.path.abspath(path)
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    res = run_vbox_cmd(["export", vm, "--output", abs_path], timeout=valid_timeout)
    if not res.ok:
        return f"Error: Failed to export VM '{vm}': {res.error}"

    return f"Successfully exported VM '{vm}' to '{abs_path}'."


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
@tool_guard
def manage_storage(
    vm_name: str,
    action: Literal["list", "attach-iso", "eject-iso"],
    controller: str = "IDE Controller",
    port: int = 0,
    device: int = 0,
    iso_path: str = "",
) -> str:
    """
    List storage controllers/media, mount an ISO image, or eject a virtual DVD drive.

    Args:
        vm_name (str): Name or UUID of the virtual machine.
        action (str): One of "list", "attach-iso", "eject-iso".
        controller (str): Storage controller name (default "IDE Controller").
        port (int): Controller port index (0-31).
        device (int): Device slot on port (0-3).
        iso_path (str): Host path to the `.iso` file (required for "attach-iso").

    Returns:
        str: Storage inventory or confirmation message.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        valid_port = _validate_int_range(port, "port", 0, 31)
        valid_device = _validate_int_range(device, "device", 0, 3)
    except ValueError as exc:
        return f"Error: {exc}"

    if action not in VALID_STORAGE_ACTIONS:
        return f"Error: Invalid action '{action}'. Must be one of {list(VALID_STORAGE_ACTIONS)}."

    if action == "list":
        res = run_vbox_cmd(["showvminfo", vm, "--machinereadable"])
        if not res.ok:
            return f"Error: Failed to inspect storage for VM '{vm}': {res.error}"

        parsed = parse_machinereadable(res.stdout)
        controllers = [
            val for key, val in parsed.items() if key.startswith("storagecontrollername") and val
        ]
        ctrl_set = set(controllers)
        media_lines: list[str] = []
        slot_re = re.compile(r"^(.+)-(\d+)-(\d+)$")
        ignored_suffixes = ("-ImageUUID", "-IsEjected", "-TempEject", "-HotPluggable", "-Type")
        for key, val in parsed.items():
            if not val or val.lower() == "none":
                continue
            match = slot_re.match(key)
            if not match:
                continue
            prefix = match.group(1)
            if prefix.endswith(ignored_suffixes):
                continue
            if ctrl_set and prefix not in ctrl_set:
                continue
            media_lines.append(f"- `{key}` -> `{val}`")

        sections = [f"### Storage for VM: {vm}"]
        sections.append(
            "**Controllers:** " + (", ".join(f"`{c}`" for c in controllers) if controllers else "None")
        )
        if media_lines:
            sections.append("#### Attached Media\n" + "\n".join(media_lines))
        else:
            sections.append("No attached storage media found.")
        return "\n".join(sections)

    try:
        ctrl = _validate_identifier(controller, "controller")
    except ValueError as exc:
        return f"Error: {exc}"

    if action == "attach-iso":
        try:
            iso = _validate_path_arg(iso_path, "iso_path")
        except ValueError as exc:
            return f"Error: {exc}"
        if not os.path.isfile(iso):
            return f"Error: ISO file '{iso}' does not exist."
        medium = iso
    else:
        medium = "emptydrive"

    res = run_vbox_cmd(
        [
            "storageattach",
            vm,
            "--storagectl",
            ctrl,
            "--port",
            str(valid_port),
            "--device",
            str(valid_device),
            "--type",
            "dvddrive",
            "--medium",
            medium,
        ]
    )
    if not res.ok:
        return f"Error: Failed to {action} on VM '{vm}': {res.error}"

    if action == "attach-iso":
        return f"Successfully attached ISO '{medium}' to VM '{vm}' ({ctrl} {valid_port}:{valid_device})."
    return f"Successfully ejected virtual DVD drive on VM '{vm}' ({ctrl} {valid_port}:{valid_device})."


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    }
)
@tool_guard
def delete_vm(vm_name: str, delete_files: bool = True, confirm: bool = False) -> str:
    """
    Unregister and optionally permanently delete a VirtualBox VM and its files.

    Args:
        vm_name (str): Name or UUID of the VM to delete.
        delete_files (bool): When True, also delete virtual disks, snapshots, and config files.
        confirm (bool): Safety guard — must be explicitly set to True to execute deletion.

    Returns:
        str: Deletion confirmation, safety prompt, or error details.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
    except ValueError as exc:
        return f"Error: {exc}"

    if not confirm:
        scope = (
            "unregister the VM AND permanently delete all associated disk images and snapshots"
            if delete_files
            else "unregister the VM while keeping its files on disk"
        )
        return (
            f"Confirmation required: call `delete_vm(vm_name='{vm}', delete_files={delete_files}, "
            f"confirm=True)` to {scope}."
        )

    cmd = ["unregistervm", vm, "--delete"] if delete_files else ["unregistervm", vm]
    res = run_vbox_cmd(cmd, timeout=120)
    if not res.ok:
        return f"Error: Failed to delete VM '{vm}': {res.error}"

    if delete_files:
        return f"Successfully unregistered and permanently deleted VM '{vm}' and its files."
    return f"Successfully unregistered VM '{vm}' (files preserved on disk)."


@mcp.resource("vbox://vms")
def resource_vms() -> str:
    """Expose registered VirtualBox VMs as an MCP resource."""
    return list_vms()


def main() -> None:
    """Run the VirtualBox MCP server over stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
