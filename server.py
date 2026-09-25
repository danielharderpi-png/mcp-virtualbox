import os
import shutil
import subprocess
import sys
from typing import List

from fastmcp import FastMCP

# Instantiate FastMCP server
mcp = FastMCP("VirtualBox Manager")

def get_vboxmanage_path() -> str:
    """
    Detects and returns the absolute path to the VBoxManage executable.
    Checks the system PATH first, then falls back to default OS-specific locations.
    """
    # 1. Check system PATH
    path = shutil.which("VBoxManage")
    if path:
        return path
    
    # 2. Check Windows fallback
    if sys.platform == "win32":
        windows_fallback = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
        if os.path.exists(windows_fallback):
            return windows_fallback
            
    # 3. Check macOS/Linux fallbacks (just in case they aren't in PATH)
    nix_fallbacks = [
        "/usr/bin/VBoxManage",
        "/usr/local/bin/VBoxManage",
        "/opt/VirtualBox/VBoxManage"
    ]
    for nix_path in nix_fallbacks:
        if os.path.exists(nix_path):
            return nix_path

    raise FileNotFoundError("VBoxManage executable not found in PATH or standard locations.")

def run_vbox_cmd(args: List[str], timeout: int = 60) -> str:
    """
    Safely executes a VBoxManage command.
    Captures stdout, stderr, and handles timeouts and non-zero exit codes.
    
    Args:
        args: List of command arguments to pass to VBoxManage.
        timeout: Maximum execution time in seconds.
        
    Returns:
        The standard output of the command if successful, or an error string.
    """
    try:
        vbox_path = get_vboxmanage_path()
    except FileNotFoundError as e:
        return f"Error: {str(e)}"

    cmd = [vbox_path] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            return f"Error executing command: '{' '.join(cmd)}'\nExit code: {result.returncode}\nDetails: {error_msg}"
            
        return result.stdout.strip()
        
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout} seconds."
    except Exception as e:
        return f"Error: An unexpected exception occurred: {str(e)}"

@mcp.tool()
def list_vms() -> str:
    """
    Returns a list of all registered VirtualBox VMs and their current running state.
    
    Returns:
        A string formatted list of VMs indicating whether they are STOPPED or RUNNING.
    """
    all_vms_out = run_vbox_cmd(["list", "vms"])
    if all_vms_out.startswith("Error"):
        return all_vms_out
        
    running_vms_out = run_vbox_cmd(["list", "runningvms"])
    
    # Extract UUIDs of running VMs for comparison
    running_uuids = set()
    for line in running_vms_out.splitlines():
        if "{" in line:
            uuid = line.split("{")[-1].strip("}")
            running_uuids.add(uuid)
            
    result = []
    for line in all_vms_out.splitlines():
        if not line.strip():
            continue
        is_running = False
        if "{" in line:
            uuid = line.split("{")[-1].strip("}")
            if uuid in running_uuids:
                is_running = True
                
        state_str = "RUNNING" if is_running else "STOPPED"
        result.append(f"{line} - State: {state_str}")
        
    if not result:
        return "No VirtualBox VMs found on this system."
        
    return "Registered VirtualBox VMs:\n" + "\n".join(result)

@mcp.tool()
def get_vm_info(vm_name: str) -> str:
    """
    Returns detailed configuration and state information for a specific virtual machine.
    
    Args:
        vm_name: The name or UUID of the virtual machine.
        
    Returns:
        A string containing the detailed properties of the VM.
    """
    result = run_vbox_cmd(["showvminfo", vm_name])
    if result.startswith("Error"):
        return f"Failed to get info for VM '{vm_name}':\n{result}"
    return result

@mcp.tool()
def manage_power(vm_name: str, action: str) -> str:
    """
    Controls the power state of a virtual machine.
    
    Args:
        vm_name: The name or UUID of the virtual machine.
        action: The power action to execute. Must be one of:
                - "start": Boots the VM in headless mode.
                - "stop": Sends ACPI power button signal (graceful shutdown).
                - "force-stop": Immediately powers off the VM (hard stop).
                - "pause": Suspends VM execution.
                - "resume": Resumes a paused VM.
                
    Returns:
        A string message indicating success or failure.
    """
    valid_actions = ["start", "stop", "force-stop", "pause", "resume"]
    if action not in valid_actions:
        return f"Error: Invalid action '{action}'. Must be one of {valid_actions}."
        
    if action == "start":
        cmd = ["startvm", vm_name, "--type", "headless"]
    elif action == "stop":
        cmd = ["controlvm", vm_name, "acpipowerbutton"]
    elif action == "force-stop":
        cmd = ["controlvm", vm_name, "poweroff"]
    elif action == "pause":
        cmd = ["controlvm", vm_name, "pause"]
    elif action == "resume":
        cmd = ["controlvm", vm_name, "resume"]
        
    result = run_vbox_cmd(cmd)
    if result.startswith("Error"):
        return f"Failed to '{action}' VM '{vm_name}':\n{result}"
        
    return f"Successfully executed power action '{action}' on VM '{vm_name}'. Output:\n{result}"

@mcp.tool()
def manage_snapshot(vm_name: str, action: str, snapshot_name: str = "") -> str:
    """
    Manages snapshots for a specific virtual machine.
    
    Args:
        vm_name: The name or UUID of the virtual machine.
        action: The snapshot action to execute. Must be one of: "take", "restore", "delete", "list".
        snapshot_name: The name of the snapshot. Required for "take", "restore", and "delete" actions.
        
    Returns:
        A string containing the result of the snapshot operation.
    """
    valid_actions = ["take", "restore", "delete", "list"]
    if action not in valid_actions:
        return f"Error: Invalid action '{action}'. Must be one of {valid_actions}."
        
    if action in ["take", "restore", "delete"] and not snapshot_name:
        return f"Error: The 'snapshot_name' parameter is strictly required for the '{action}' action."
        
    if action == "list":
        cmd = ["snapshot", vm_name, "list"]
    else:
        cmd = ["snapshot", vm_name, action, snapshot_name]
        
    result = run_vbox_cmd(cmd)
    if result.startswith("Error"):
        return f"Failed to '{action}' snapshot on VM '{vm_name}':\n{result}"
        
    return f"Successfully executed snapshot action '{action}' on VM '{vm_name}'. Output:\n{result}"

@mcp.tool()
def execute_guest_command(
    vm_name: str, 
    username: str, 
    password: str, 
    command: str, 
    args: list[str] = []
) -> str:
    """
    Executes a shell command inside the guest VM using VBoxManage guestcontrol.
    Requires VirtualBox Guest Additions to be installed and running inside the guest OS.
    
    Args:
        vm_name: The name or UUID of the virtual machine.
        username: The guest OS username to authenticate as.
        password: The guest OS password.
        command: The absolute path to the executable inside the guest (e.g., "/bin/ls" or "C:\\Windows\\System32\\ipconfig.exe").
        args: Optional list of string arguments to pass to the command.
        
    Returns:
        The standard output of the executed command inside the guest, or an error.
    """
    cmd = [
        "guestcontrol", vm_name, 
        "run", 
        "--username", username, 
        "--password", password, 
        "--exe", command,
        "--"
    ] + args
    
    # We increase the timeout to 120s for guest commands as they can be slower
    result = run_vbox_cmd(cmd, timeout=120)
    
    if result.startswith("Error"):
        return f"Failed to execute guest command on VM '{vm_name}':\n{result}"
        
    return f"Guest command executed successfully. Output:\n{result}"

if __name__ == "__main__":
    # Start the FastMCP server utilizing stdio transport
    mcp.run(transport="stdio")