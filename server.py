from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
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

KALI_DEFAULT_IMAGE_BASE_URL = "https://cdimage.kali.org/current/"
KALI_DEFAULT_VM_NAME = "Kali-Agent"
KALI_DEFAULT_SNAPSHOT_NAME = "clean-base"

_VM_LINE_RE = re.compile(r'^"(?P<name>.*)"\s+\{(?P<uuid>[^}]+)\}\s*$')
_KALI_VBOX_7Z_RE = re.compile(r"^kali-linux-[A-Za-z0-9._-]+-virtualbox-amd64\.7z$")
_SHA256_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+)$")


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


def _validate_https_url(url: str, field_name: str) -> str:
    """Validate an HTTPS URL and reject insecure schemes or control characters."""
    if not isinstance(url, str):
        raise ValueError(f"{field_name} must be a string.")
    cleaned = url.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty.")
    if any(ord(ch) < 32 for ch in cleaned):
        raise ValueError(f"{field_name} contains invalid control characters.")
    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ValueError(f"{field_name} must be a valid https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError(f"{field_name} must not contain embedded credentials.")
    return cleaned


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject HTTP redirects that leave HTTPS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme.lower() != "https":
            raise urllib.error.URLError(
                f"Refusing non-HTTPS redirect to '{parsed.scheme or 'unknown'}://'."
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_https_opener() -> urllib.request.OpenerDirector:
    """Build a URL opener restricted to HTTPS requests and redirects."""
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(),
        _HttpsOnlyRedirectHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.UnknownHandler(),
    ):
        opener.add_handler(handler)
    return opener


def _parse_kali_sha256sums(content: str) -> tuple[str, str]:
    """Extract the newest official `kali-linux-*-virtualbox-amd64.7z` entry and SHA-256."""
    matches: list[tuple[str, str]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _SHA256_LINE_RE.match(line)
        if not match:
            continue
        digest = match.group(1).lower()
        filename = match.group(2).strip()
        if "/" in filename or "\\" in filename or ".." in filename:
            continue
        if _KALI_VBOX_7Z_RE.match(filename):
            matches.append((filename, digest))
    if not matches:
        raise ValueError(
            "No official 'kali-linux-*-virtualbox-amd64.7z' entry found in SHA256SUMS."
        )
    matches.sort(key=lambda item: item[0])
    return matches[-1]


def _compute_sha256(file_path: str) -> str:
    """Compute the lowercase SHA-256 hex digest of a local file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def _default_kali_cache_dir() -> str:
    """Return the cache directory for downloaded Kali VirtualBox archives."""
    env_dir = os.environ.get("VBOX_KALI_CACHE_DIR", "").strip()
    if env_dir:
        return _validate_path_arg(env_dir, "VBOX_KALI_CACHE_DIR")
    return os.path.join(os.path.expanduser("~"), ".mcp-virtualbox", "kali")


def _find_cached_kali_archive(cache_dir: str) -> Optional[str]:
    """Return the newest non-empty cached Kali VirtualBox `.7z` archive, if present."""
    if not os.path.isdir(cache_dir):
        return None
    matches: list[str] = []
    for entry in os.listdir(cache_dir):
        if ".." in entry or not _KALI_VBOX_7Z_RE.match(entry):
            continue
        full_path = os.path.join(cache_dir, entry)
        if os.path.isfile(full_path) and os.path.getsize(full_path) > 0:
            matches.append(entry)
    if not matches:
        return None
    matches.sort()
    return os.path.abspath(os.path.join(cache_dir, matches[-1]))


def _download_kali_image(
    cache_dir: str, verify_checksum: bool = True, timeout: int = 1800
) -> tuple[str, str, bool]:
    """
    Download and SHA-256-verify the official pre-built Kali Linux VirtualBox `.7z` image.

    Returns:
        tuple[str, str, bool]: `(archive_path, sha256_hex, from_cache)`.
    """
    raw_base = os.environ.get("VBOX_KALI_IMAGE_BASE_URL", "").strip() or KALI_DEFAULT_IMAGE_BASE_URL
    base_url = _validate_https_url(raw_base, "VBOX_KALI_IMAGE_BASE_URL")
    if not base_url.endswith("/"):
        base_url += "/"

    opener = _build_https_opener()
    sums_url = urllib.parse.urljoin(base_url, "SHA256SUMS")
    sums_req = urllib.request.Request(sums_url, headers={"User-Agent": "mcp-virtualbox/2.0"})
    with opener.open(sums_req, timeout=min(timeout, 60)) as resp:
        sums_text = resp.read(1024 * 1024).decode("utf-8", errors="replace")

    filename, expected_sha256 = _parse_kali_sha256sums(sums_text)
    os.makedirs(cache_dir, exist_ok=True)
    dest_path = os.path.abspath(os.path.join(cache_dir, filename))

    if os.path.isfile(dest_path):
        if verify_checksum:
            if _compute_sha256(dest_path) == expected_sha256:
                return (dest_path, expected_sha256, True)
        elif os.path.getsize(dest_path) > 0:
            return (dest_path, expected_sha256, True)

    archive_url = urllib.parse.urljoin(base_url, filename)
    archive_req = urllib.request.Request(archive_url, headers={"User-Agent": "mcp-virtualbox/2.0"})
    part_path = f"{dest_path}.part"
    deadline = time.monotonic() + timeout
    hasher = hashlib.sha256()

    try:
        with opener.open(archive_req, timeout=min(timeout, 120)) as resp, open(
            part_path, "wb"
        ) as out_file:
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        f"Downloading Kali image '{filename}' exceeded timeout of {timeout}s."
                    )
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                out_file.write(chunk)
                hasher.update(chunk)

        actual_sha256 = hasher.hexdigest().lower()
        if verify_checksum and actual_sha256 != expected_sha256:
            raise ValueError(
                f"SHA-256 checksum mismatch for '{filename}': "
                f"expected {expected_sha256}, got {actual_sha256}."
            )
        os.replace(part_path, dest_path)
        return (dest_path, actual_sha256, False)
    except Exception:
        try:
            if os.path.exists(part_path):
                os.remove(part_path)
        except OSError:
            pass
        raise


def _find_7z_extractor() -> tuple[str, str]:
    """Locate an archive extractor capable of unpacking `.7z` archives."""
    for candidate in ("7z", "7za", "7zz"):
        hit = shutil.which(candidate)
        if hit:
            return ("7z", hit)

    if sys.platform == "win32":
        for win_candidate in (
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
        ):
            if os.path.exists(win_candidate):
                return ("7z", win_candidate)

    tar_path = shutil.which("tar")
    if tar_path:
        proc = subprocess.run(
            [tar_path, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        version_text = f"{proc.stdout}\n{proc.stderr}".lower()
        if "bsdtar" in version_text or "libarchive" in version_text:
            return ("bsdtar", tar_path)

    raise FileNotFoundError(
        "No .7z extractor found. Install 7-Zip (7z / p7zip-full), or extract the .7z "
        "archive manually and pass the resulting .vbox file path."
    )


def _validate_archive_members(members: list[str], target_dir: str) -> None:
    """Validate archive member paths to prevent path traversal and Zip-Slip attacks."""
    if not members:
        raise ValueError("Archive contains no files.")

    real_target = os.path.realpath(target_dir)
    for member in members:
        if not member or not member.strip() or "\x00" in member:
            raise ValueError(f"Invalid archive member path: {member!r}")
        normalized = member.replace("\\", "/")
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
            raise ValueError(f"Unsafe absolute archive member path: {member!r}")
        raw_parts = normalized.split("/")
        if ".." in raw_parts:
            raise ValueError(f"Unsafe path traversal in archive member: {member!r}")
        parts = [part for part in raw_parts if part and part != "."]
        if parts:
            resolved = os.path.realpath(os.path.join(real_target, *parts))
            if os.path.commonpath([real_target, resolved]) != real_target:
                raise ValueError(f"Archive member escapes target directory: {member!r}")


def _list_7z_members(
    extractor_kind: str, extractor_path: str, archive_path: str, timeout: int
) -> list[str]:
    """List member paths inside a `.7z` archive before extracting."""
    if extractor_kind == "7z":
        cmd = [extractor_path, "l", "-slt", archive_path]
    else:
        cmd = [extractor_path, "-tf", archive_path]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=min(timeout, 120),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Listing archive '{archive_path}' timed out.") from exc

    if proc.returncode != 0:
        details = proc.stderr.strip() or proc.stdout.strip() or "No details provided."
        raise RuntimeError(
            f"Failed to list members of archive '{archive_path}' (exit code {proc.returncode}): {details}"
        )

    if extractor_kind == "bsdtar":
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]

    members: list[str] = []
    in_entries = False
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not in_entries:
            if re.match(r"^-{5,}$", line):
                in_entries = True
            continue
        if line.startswith("Path = "):
            member_path = line[len("Path = ") :].strip()
            if member_path:
                members.append(member_path)
    return members


def _extract_7z_archive(archive_path: str, target_dir: str, timeout: int = 600) -> str:
    """Safely inspect and extract a `.7z` archive into `target_dir`."""
    extractor_kind, extractor_path = _find_7z_extractor()
    members = _list_7z_members(extractor_kind, extractor_path, archive_path, timeout=timeout)
    _validate_archive_members(members, target_dir)

    os.makedirs(target_dir, exist_ok=True)
    if extractor_kind == "7z":
        cmd = [extractor_path, "x", "-y", f"-o{target_dir}", archive_path]
    else:
        cmd = [extractor_path, "-xf", archive_path, "-C", target_dir]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Extracting archive '{archive_path}' timed out after {timeout} seconds."
        ) from exc

    if proc.returncode != 0:
        details = proc.stderr.strip() or proc.stdout.strip() or "No error details provided."
        raise RuntimeError(
            f"Failed to extract archive '{archive_path}' (exit code {proc.returncode}): {details}"
        )

    return os.path.abspath(target_dir)


def _find_vbox_file(directory: str) -> str:
    """Locate the single `.vbox` machine definition file inside `directory`."""
    real_dir = os.path.realpath(directory)
    matches: list[str] = []
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if fname.lower().endswith(".vbox"):
                candidate = os.path.join(root, fname)
                if os.path.islink(candidate):
                    raise ValueError(f"Refusing symlinked .vbox file '{candidate}'.")
                real_candidate = os.path.realpath(candidate)
                if os.path.commonpath([real_dir, real_candidate]) != real_dir:
                    raise ValueError(
                        f"Refusing .vbox file '{candidate}' that resolves outside '{directory}'."
                    )
                matches.append(candidate)
    matches.sort()
    if not matches:
        raise ValueError(f"No .vbox machine definition file found inside '{directory}'.")
    if len(matches) > 1:
        raise ValueError(
            f"Multiple .vbox files found inside '{directory}': {', '.join(matches)}. "
            "Pass the specific .vbox file path directly."
        )
    return os.path.abspath(matches[0])


def _parse_vbox_metadata(vbox_path: str) -> tuple[str, str, str]:
    """Parse `(name, uuid, os_type)` from a `.vbox` XML machine definition."""
    try:
        tree = ET.parse(vbox_path)
    except (ET.ParseError, OSError) as exc:
        raise ValueError(f"Failed to parse .vbox file '{vbox_path}': {exc}") from exc

    machine_elem: Optional[ET.Element] = None
    for elem in tree.getroot().iter():
        if elem.tag == "Machine" or elem.tag.endswith("}Machine"):
            machine_elem = elem
            break

    if machine_elem is None:
        raise ValueError(f"No <Machine> element found in .vbox file '{vbox_path}'.")

    name = machine_elem.attrib.get("name", "").strip()
    uuid = machine_elem.attrib.get("uuid", "").strip().strip("{}")
    os_type = machine_elem.attrib.get("OSType", "unknown").strip() or "unknown"
    return (name, uuid, os_type)


def _get_default_machine_folder() -> Optional[str]:
    """Query VirtualBox's configured Default machine folder, if available."""
    res = run_vbox_cmd(["list", "systemproperties"])
    if not res.ok:
        return None
    for raw_line in res.stdout.splitlines():
        line = raw_line.strip()
        if line.lower().startswith("default machine folder:"):
            folder = line.split(":", 1)[1].strip()
            return folder or None
    return None


def _get_registered_vms() -> tuple[dict[str, str], dict[str, str]]:
    """Return `(by_name, by_uuid)` maps for all currently registered VirtualBox VMs."""
    res = run_vbox_cmd(["list", "vms"])
    if not res.ok:
        raise RuntimeError(res.error or "Failed to list registered VMs.")
    by_name: dict[str, str] = {}
    by_uuid: dict[str, str] = {}
    for name, uuid in _parse_vm_entries(res.stdout):
        by_name[name] = uuid
        if uuid:
            by_uuid[uuid.lower()] = name
    return (by_name, by_uuid)


def _build_modifyvm_args(
    target_vm: str,
    new_name: Optional[str] = None,
    cpus: Optional[int] = None,
    memory_mb: Optional[int] = None,
    vram_mb: Optional[int] = None,
    nic_mode: Optional[str] = None,
    clipboard_mode: Optional[str] = None,
) -> tuple[list[str], list[str]]:
    """Build a `VBoxManage modifyvm` command and human-readable change list."""
    cmd = ["modifyvm", target_vm]
    changes: list[str] = []
    if new_name:
        cmd.extend(["--name", new_name])
        changes.append(f"name={new_name}")
    if cpus is not None:
        cmd.extend(["--cpus", str(cpus)])
        changes.append(f"cpus={cpus}")
    if memory_mb is not None:
        cmd.extend(["--memory", str(memory_mb)])
        changes.append(f"memory_mb={memory_mb}")
    if vram_mb is not None:
        cmd.extend(["--vram", str(vram_mb)])
        changes.append(f"vram_mb={vram_mb}")
    if nic_mode is not None:
        cmd.extend(["--nic1", nic_mode])
        changes.append(f"nic1={nic_mode}")
    if clipboard_mode is not None:
        cmd.extend(["--clipboard-mode", clipboard_mode])
        changes.append(f"clipboard_mode={clipboard_mode}")
    return cmd, changes


def _resolve_vbox_from_source(
    abs_source: str, target_dir_for_7z: str, timeout: int
) -> tuple[str, Optional[str]]:
    """Resolve a `.vbox` file from a directory, `.vbox` file, or `.7z` archive."""
    if os.path.isdir(abs_source):
        return _find_vbox_file(abs_source), None
    if os.path.isfile(abs_source):
        lower = abs_source.lower()
        if lower.endswith(".vbox"):
            return abs_source, None
        if lower.endswith(".7z"):
            if os.path.isdir(target_dir_for_7z) and os.listdir(target_dir_for_7z):
                raise ValueError(
                    f"Target extraction directory '{target_dir_for_7z}' already exists and is not empty. "
                    "Specify a fresh extract_dir or pass the existing .vbox file path directly."
                )
            extracted = _extract_7z_archive(abs_source, target_dir_for_7z, timeout=timeout)
            return _find_vbox_file(extracted), extracted
    raise ValueError(
        f"Source path '{abs_source}' must be an existing .vbox file, .7z archive, "
        "or directory containing a .vbox file."
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
def register_vm(
    source_path: str,
    vm_name: str = "",
    extract_dir: str = "",
    cpus: Optional[int] = None,
    memory_mb: Optional[int] = None,
    vram_mb: Optional[int] = None,
    nic_mode: Optional[Literal["nat", "bridged", "hostonly", "intnet", "none"]] = None,
    clipboard_mode: Optional[
        Literal["disabled", "hosttoguest", "guesttohost", "bidirectional"]
    ] = None,
    timeout: int = 600,
) -> str:
    """
    Register a pre-built VM from a `.vbox` file, directory, or `.7z` archive (such as official Kali images).

    Args:
        source_path (str): Host path to a `.vbox` file, `.7z` archive, or directory containing a `.vbox` file.
        vm_name (str): Optional new display name to apply via `modifyvm --name` after registering.
        extract_dir (str): Optional extraction directory when `source_path` is a `.7z` archive.
        cpus (int, optional): Override vCPU count (1-128).
        memory_mb (int, optional): Override RAM in MB (128-262144).
        vram_mb (int, optional): Override video memory in MB (1-256).
        nic_mode (str, optional): Override NIC 1 mode ("nat", "bridged", "hostonly", "intnet", or "none").
        clipboard_mode (str, optional): Override clipboard sharing mode.
        timeout (int): Extraction/registration timeout in seconds (1-3600).

    Returns:
        str: Markdown summary of the registered VM or error details.
    """
    try:
        src = _validate_path_arg(source_path, "source_path")
        valid_name = _validate_identifier(vm_name, "vm_name") if vm_name.strip() else ""
        dest_dir = _validate_path_arg(extract_dir, "extract_dir") if extract_dir.strip() else ""
        valid_cpus = _validate_int_range(cpus, "cpus", 1, 128) if cpus is not None else None
        valid_mem = (
            _validate_int_range(memory_mb, "memory_mb", 128, 262144)
            if memory_mb is not None
            else None
        )
        valid_vram = _validate_int_range(vram_mb, "vram_mb", 1, 256) if vram_mb is not None else None
        valid_timeout = _validate_int_range(timeout, "timeout", 1, 3600)
    except ValueError as exc:
        return f"Error: {exc}"

    if nic_mode is not None and nic_mode not in VALID_NIC_MODES:
        return f"Error: Invalid nic_mode '{nic_mode}'. Must be one of {list(VALID_NIC_MODES)}."
    if clipboard_mode is not None and clipboard_mode not in VALID_CLIPBOARD_MODES:
        return (
            f"Error: Invalid clipboard_mode '{clipboard_mode}'. "
            f"Must be one of {list(VALID_CLIPBOARD_MODES)}."
        )

    abs_source = os.path.abspath(src)
    default_7z_dir = os.path.join(
        os.path.dirname(abs_source),
        os.path.splitext(os.path.basename(abs_source))[0],
    )
    target_7z_dir = os.path.abspath(dest_dir) if dest_dir else default_7z_dir

    try:
        vbox_file, extracted_dir = _resolve_vbox_from_source(
            abs_source, target_7z_dir, timeout=valid_timeout
        )
        orig_name, machine_uuid, os_type = _parse_vbox_metadata(vbox_file)
        target_ref = _validate_identifier(machine_uuid or orig_name, "machine identifier")
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        return f"Error: {exc}"

    reg_res = run_vbox_cmd(["registervm", vbox_file], timeout=min(valid_timeout, 120))
    if not reg_res.ok:
        err_text = reg_res.error or "Unknown registration error."
        hint = ""
        if "already exists" in err_text.lower():
            hint = (
                " Hint: A VM or disk with the same UUID/name is already registered; "
                "use `clone_vm` or `provision_kali_vm(base_vm=...)` to create a separate copy."
            )
        return f"Error: Failed to register VM from '{vbox_file}': {err_text}{hint}"

    modify_cmd, changes = _build_modifyvm_args(
        target_ref,
        new_name=valid_name if (valid_name and valid_name != orig_name) else None,
        cpus=valid_cpus,
        memory_mb=valid_mem,
        vram_mb=valid_vram,
        nic_mode=nic_mode,
        clipboard_mode=clipboard_mode,
    )
    if changes:
        mod_res = run_vbox_cmd(modify_cmd)
        if not mod_res.ok:
            return (
                f"Error: VM '{orig_name or target_ref}' was registered from '{vbox_file}', "
                f"but applying customizations failed: {mod_res.error}"
            )

    final_name = valid_name or orig_name or os.path.splitext(os.path.basename(vbox_file))[0]
    lines = [
        f"### Registered VM: {final_name}",
        f"- **UUID:** `{machine_uuid or 'unknown'}`",
        f"- **OS Type:** `{os_type}`",
        f"- **Definition File:** `{vbox_file}`",
    ]
    if extracted_dir:
        lines.append(f"- **Extracted Directory:** `{extracted_dir}`")
    if changes:
        lines.append(f"- **Customizations Applied:** {', '.join(changes)}")
    return "\n".join(lines)


@mcp.tool(
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    }
)
@tool_guard
def provision_kali_vm(
    vm_name: str = KALI_DEFAULT_VM_NAME,
    image_path: str = "",
    download: bool = False,
    base_vm: str = "",
    base_snapshot: str = "",
    linked_clone: bool = True,
    extract_dir: str = "",
    cpus: int = 2,
    memory_mb: int = 4096,
    vram_mb: int = 128,
    nic_mode: Literal["nat", "bridged", "hostonly", "intnet", "none"] = "nat",
    clipboard_mode: Literal[
        "disabled", "hosttoguest", "guesttohost", "bidirectional"
    ] = "bidirectional",
    take_clean_snapshot: bool = True,
    snapshot_name: str = KALI_DEFAULT_SNAPSHOT_NAME,
    start_vm: bool = False,
    start_mode: Literal["headless", "gui", "separate"] = "headless",
    verify_checksum: bool = True,
    timeout: int = 1800,
) -> str:
    """
    Provision a ready-to-use Kali Linux VM for the agent from a pre-built image or Kali base VM.

    Supports official Kali VirtualBox `.7z` archives (including optional verified HTTPS download from
    `cdimage.kali.org/current/`), extracted `.vbox` directories/files, `.ova`/`.ovf` appliances,
    and fast linked/full clones from an existing Kali base VM.

    Args:
        vm_name (str): Name for the new Kali VM (default "Kali-Agent").
        image_path (str): Optional local `.7z`, `.vbox`, extracted VM dir, or `.ova`/`.ovf`.
        download (bool): Download & SHA-256-verify the official pre-built Kali VirtualBox `.7z`.
        base_vm (str): Existing registered Kali template VM to clone from.
        base_snapshot (str): Snapshot on `base_vm` (defaults to "clean-base" when `linked_clone=True`).
        linked_clone (bool): Use a fast linked clone when cloning from `base_vm`.
        extract_dir (str): Optional target directory when extracting a `.7z` image.
        cpus (int): Virtual CPU count (1-128, default 2).
        memory_mb (int): Base RAM in MB (128-262144, default 4096).
        vram_mb (int): Video memory in MB (1-256, default 128).
        nic_mode (str): NIC 1 mode ("nat", "bridged", "hostonly", "intnet", or "none").
        clipboard_mode (str): Guest clipboard sharing mode (default "bidirectional").
        take_clean_snapshot (bool): Create an initial baseline snapshot after provisioning.
        snapshot_name (str): Name of the baseline snapshot (default "clean-base").
        start_vm (bool): Boot the provisioned Kali VM immediately after setup.
        start_mode (str): Boot mode when `start_vm=True` ("headless", "gui", or "separate").
        verify_checksum (bool): Verify official `SHA256SUMS` digest when downloading.
        timeout (int): Maximum operation timeout in seconds (1-3600).

    Returns:
        str: Markdown summary with Kali VM details, snapshot state, and credential guidance.
    """
    try:
        vm = _validate_identifier(vm_name, "vm_name")
        valid_cpus = _validate_int_range(cpus, "cpus", 1, 128)
        valid_mem = _validate_int_range(memory_mb, "memory_mb", 128, 262144)
        valid_vram = _validate_int_range(vram_mb, "vram_mb", 1, 256)
        valid_timeout = _validate_int_range(timeout, "timeout", 1, 3600)
        valid_snap = (
            _validate_identifier(snapshot_name, "snapshot_name") if take_clean_snapshot else ""
        )
        valid_image = _validate_path_arg(image_path, "image_path") if image_path.strip() else ""
        valid_base_vm = _validate_identifier(base_vm, "base_vm") if base_vm.strip() else ""
        valid_base_snap = (
            _validate_identifier(base_snapshot, "base_snapshot") if base_snapshot.strip() else ""
        )
        valid_extract_dir = (
            _validate_path_arg(extract_dir, "extract_dir") if extract_dir.strip() else ""
        )
    except ValueError as exc:
        return f"Error: {exc}"

    if nic_mode not in VALID_NIC_MODES:
        return f"Error: Invalid nic_mode '{nic_mode}'. Must be one of {list(VALID_NIC_MODES)}."
    if clipboard_mode not in VALID_CLIPBOARD_MODES:
        return (
            f"Error: Invalid clipboard_mode '{clipboard_mode}'. "
            f"Must be one of {list(VALID_CLIPBOARD_MODES)}."
        )
    if start_mode not in VALID_START_MODES:
        return f"Error: Invalid start_mode '{start_mode}'. Must be one of {list(VALID_START_MODES)}."

    try:
        by_name, by_uuid = _get_registered_vms()
    except RuntimeError as exc:
        return f"Error: {exc}"

    if vm in by_name:
        existing_uuid = by_name[vm] or "unknown"
        return (
            f"Error: VM '{vm}' is already registered (UUID: {existing_uuid}). "
            "Choose a different vm_name or manage the existing VM."
        )

    flow_mode = ""
    resolved_image = ""
    resolved_base = ""
    source_desc = ""
    machine_uuid = ""
    os_type = "Debian_64"

    if valid_image:
        flow_mode = "image"
        resolved_image = valid_image
        source_desc = f"Local image (`{os.path.abspath(valid_image)}`)"
    elif valid_base_vm:
        flow_mode = "clone"
        resolved_base = valid_base_vm
    elif download:
        try:
            cache_dir = _default_kali_cache_dir()
            downloaded_path, actual_sha, from_cache = _download_kali_image(
                cache_dir, verify_checksum=verify_checksum, timeout=valid_timeout
            )
        except (ValueError, TimeoutError, urllib.error.URLError, OSError) as exc:
            return f"Error: Failed to download Kali Linux image: {exc}"

        flow_mode = "image"
        resolved_image = downloaded_path
        cache_note = "reused verified cached archive" if from_cache else "downloaded"
        sha_note = (
            f"SHA-256 verified (`{actual_sha}`)"
            if verify_checksum
            else f"SHA-256 `{actual_sha}` (checksum verification disabled)"
        )
        source_desc = (
            f"Official Kali Linux VirtualBox archive (`{os.path.basename(downloaded_path)}`, "
            f"{cache_note}; {sha_note})"
        )
    else:
        env_base = os.environ.get("VBOX_KALI_BASE_VM", "").strip()
        env_img = os.environ.get("VBOX_KALI_IMAGE_PATH", "").strip()
        if env_base:
            try:
                resolved_base = _validate_identifier(env_base, "VBOX_KALI_BASE_VM")
            except ValueError as exc:
                return f"Error: {exc}"
            flow_mode = "clone"
        elif env_img:
            try:
                resolved_image = _validate_path_arg(env_img, "VBOX_KALI_IMAGE_PATH")
            except ValueError as exc:
                return f"Error: {exc}"
            flow_mode = "image"
            source_desc = f"Configured VBOX_KALI_IMAGE_PATH (`{os.path.abspath(resolved_image)}`)"
        else:
            try:
                cache_dir = _default_kali_cache_dir()
            except ValueError as exc:
                return f"Error: {exc}"
            cached_archive = _find_cached_kali_archive(cache_dir)
            if cached_archive:
                flow_mode = "image"
                resolved_image = cached_archive
                source_desc = f"Cached Kali Linux VirtualBox archive (`{cached_archive}`)"

    if not flow_mode:
        return (
            "Error: No Kali Linux provisioning source found. Supply one of:\n"
            "1. `download=True` to download & SHA-256-verify the official pre-built Kali VirtualBox `.7z` image;\n"
            "2. `image_path='/path/to/kali-linux-*-virtualbox-amd64.7z'` (or `.vbox` / extracted dir / `.ova`), "
            "or set `VBOX_KALI_IMAGE_PATH`;\n"
            "3. `base_vm='<existing-kali-vm>'` (or set `VBOX_KALI_BASE_VM`) to clone an existing Kali template VM."
        )

    if flow_mode == "clone":
        clone_cmd = ["clonevm", resolved_base, "--name", vm, "--mode", "machine", "--register"]
        if linked_clone:
            eff_snap = valid_base_snap or KALI_DEFAULT_SNAPSHOT_NAME
            clone_cmd.extend(["--snapshot", eff_snap, "--options", "link"])
            source_desc = f"Linked clone from `{resolved_base}` (snapshot `{eff_snap}`)"
        elif valid_base_snap:
            clone_cmd.extend(["--snapshot", valid_base_snap])
            source_desc = f"Full clone from `{resolved_base}` (snapshot `{valid_base_snap}`)"
        else:
            source_desc = f"Full clone from `{resolved_base}`"

        clone_res = run_vbox_cmd(clone_cmd, timeout=min(valid_timeout, 600))
        if not clone_res.ok:
            return f"Error: Failed to clone Kali base VM '{resolved_base}' to '{vm}': {clone_res.error}"

        mod_cmd, _ = _build_modifyvm_args(
            vm,
            cpus=valid_cpus,
            memory_mb=valid_mem,
            vram_mb=valid_vram,
            nic_mode=nic_mode,
            clipboard_mode=clipboard_mode,
        )
        mod_res = run_vbox_cmd(mod_cmd)
        if not mod_res.ok:
            return (
                f"Error: Cloned Kali VM '{vm}', but applying resource settings failed: "
                f"{mod_res.error}"
            )
    else:
        abs_image = os.path.abspath(resolved_image)
        lower_image = abs_image.lower()

        if lower_image.endswith(".iso"):
            return (
                f"Error: '{abs_image}' is an installer ISO, whereas `provision_kali_vm` uses "
                "pre-built Kali VirtualBox images (`.7z`, `.vbox`, extracted VM directory, or `.ova`/`.ovf`) "
                "with Guest Additions pre-installed. For a manual ISO install, call "
                f"`create_vm(vm_name='{vm}', os_type='Debian_64', disk_size_mb=40960, iso_path='{abs_image}')`."
            )

        if lower_image.endswith((".ova", ".ovf")):
            if not os.path.isfile(abs_image):
                return f"Error: Appliance file '{abs_image}' does not exist."
            import_cmd = [
                "import",
                abs_image,
                "--vsys",
                "0",
                "--vmname",
                vm,
                "--vsys",
                "0",
                "--cpus",
                str(valid_cpus),
                "--vsys",
                "0",
                "--memory",
                str(valid_mem),
            ]
            imp_res = run_vbox_cmd(import_cmd, timeout=min(valid_timeout, 600))
            if not imp_res.ok:
                return f"Error: Failed to import Kali appliance '{abs_image}': {imp_res.error}"

            mod_cmd, _ = _build_modifyvm_args(
                vm,
                vram_mb=valid_vram,
                nic_mode=nic_mode,
                clipboard_mode=clipboard_mode,
            )
            mod_res = run_vbox_cmd(mod_cmd)
            if not mod_res.ok:
                return (
                    f"Error: Imported Kali VM '{vm}', but network/display configuration failed: "
                    f"{mod_res.error}"
                )
        else:
            target_7z_dir = ""
            if os.path.isfile(abs_image) and lower_image.endswith(".7z"):
                if valid_extract_dir:
                    target_7z_dir = os.path.abspath(valid_extract_dir)
                else:
                    default_folder = _get_default_machine_folder()
                    if default_folder:
                        target_7z_dir = os.path.join(default_folder, vm)
                    else:
                        target_7z_dir = os.path.join(os.path.dirname(abs_image), vm)

            try:
                vbox_file, _ = _resolve_vbox_from_source(
                    abs_image, target_7z_dir, timeout=valid_timeout
                )
                orig_name, machine_uuid, os_type = _parse_vbox_metadata(vbox_file)
                target_ref = _validate_identifier(machine_uuid or orig_name, "machine identifier")
            except (FileNotFoundError, ValueError, RuntimeError) as exc:
                return f"Error: {exc}"

            if machine_uuid and machine_uuid.lower() in by_uuid:
                existing_vm = by_uuid[machine_uuid.lower()]
                return (
                    f"Error: The .vbox machine UUID '{machine_uuid}' is already registered under "
                    f"VM '{existing_vm}'. VirtualBox cannot register the same VM/VDI UUIDs twice. "
                    f"Use `provision_kali_vm(vm_name='{vm}', base_vm='{existing_vm}', linked_clone=True)` "
                    "or `clone_vm` to create an independent Kali VM with fresh UUIDs."
                )

            reg_res = run_vbox_cmd(["registervm", vbox_file], timeout=min(valid_timeout, 120))
            if not reg_res.ok:
                return f"Error: Failed to register Kali VM from '{vbox_file}': {reg_res.error}"

            mod_cmd, _ = _build_modifyvm_args(
                target_ref,
                new_name=vm if vm != orig_name else None,
                cpus=valid_cpus,
                memory_mb=valid_mem,
                vram_mb=valid_vram,
                nic_mode=nic_mode,
                clipboard_mode=clipboard_mode,
            )
            mod_res = run_vbox_cmd(mod_cmd)
            if not mod_res.ok:
                return (
                    f"Error: Registered Kali VM '{orig_name or target_ref}' from '{vbox_file}', "
                    f"but configuration failed: {mod_res.error}"
                )

    snapshot_status = "Skipped"
    if take_clean_snapshot:
        snap_res = run_vbox_cmd(
            ["snapshot", vm, "take", valid_snap, "--description", "Clean Kali Linux agent baseline"],
            timeout=120,
        )
        if not snap_res.ok:
            return (
                f"Error: Provisioned Kali VM '{vm}', but creating baseline snapshot "
                f"'{valid_snap}' failed: {snap_res.error}"
            )
        snapshot_status = f"`{valid_snap}` (created)"

    power_status = "STOPPED"
    if start_vm:
        start_res = run_vbox_cmd(["startvm", vm, "--type", start_mode])
        if not start_res.ok:
            return f"Error: Provisioned Kali VM '{vm}', but starting it failed: {start_res.error}"
        power_status = f"RUNNING (`{start_mode}`)"

    lines = [
        f"### Provisioned Kali Linux VM: {vm}",
        f"- **Source:** {source_desc}",
    ]
    if machine_uuid:
        lines.append(f"- **UUID:** `{machine_uuid}`")
    lines.extend(
        [
            f"- **OS Type:** `{os_type}`",
            f"- **Resources:** {valid_cpus} vCPU(s), {valid_mem} MB RAM, {valid_vram} MB VRAM",
            f"- **NIC 1:** `{nic_mode}` | **Clipboard:** `{clipboard_mode}`",
            f"- **Baseline Snapshot:** {snapshot_status}",
            f"- **Power State:** {power_status}",
            (
                "- **Default Credentials Note:** Fresh official Kali pre-built VirtualBox images "
                "use username `kali` / password `kali` with Guest Additions pre-installed. "
                "Rotate the default password on first boot (or create a dedicated low-privilege user) "
                "and configure `VBOX_GUEST_USER` / `VBOX_GUEST_PASSWORD`."
            ),
            (
                f"- **Fast Reuse Tip:** Spin up additional disposable Kali VMs quickly via "
                f"`provision_kali_vm(vm_name='<new-name>', base_vm='{vm}', linked_clone=True)`."
            ),
        ]
    )
    return "\n".join(lines)


@mcp.resource("vbox://vms")
def resource_vms() -> str:
    """Expose registered VirtualBox VMs as an MCP resource."""
    return list_vms()


def main() -> None:
    """Run the VirtualBox MCP server over stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
