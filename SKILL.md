---
name: virtualbox-mcp
description: Safely manage local Oracle VirtualBox VMs, snapshots, guest execution, file transfers, port forwarding, and debugging workflows through the VirtualBox MCP server.
---

# VirtualBox MCP Skill

Use this skill when interacting with local VirtualBox virtual machines through the `virtualbox-manager` MCP tools.

## Core Safety & Efficiency Workflow

1. **Inspect before mutating**
   - Start by calling `list_vms` (or reading resource `vbox://vms`) to confirm the exact VM name/UUID and power state.
   - Use `get_vm_info` to check allocated CPUs, memory, NICs, NAT port forwards, shared folders, and the active snapshot before changing settings.

2. **Snapshot before risky work**
   - Always create a restore point before running untrusted code, upgrades, or destructive commands:
     - `manage_snapshot(vm_name=..., action="take", snapshot_name="pre-test", description="Clean checkpoint")`
   - Pass `live=True` when snapshotting a running VM without pausing execution.
   - If a test fails or breaks the environment, revert cleanly with `manage_snapshot(..., action="restore")`.

3. **Prefer headless starts & linked clones**
   - Use `manage_power(vm_name=..., action="start", mode="headless")` by default unless GUI output is explicitly needed.
   - For disposable test sandboxes, take a clean base snapshot and spin up fast copies with `clone_vm(source_vm=..., new_name=..., linked=True, snapshot_name="...")`.

4. **Transfer scripts instead of stuffing complex one-liners**
   - When running multi-line scripts or test suites inside a VM, upload files with `copy_to_guest` and then invoke them cleanly with `execute_guest_command` (setting `cwd` and `env` explicitly).
   - Pull logs or build artifacts back to the host with `copy_from_guest`.
   - Leave `username` and `password` omitted when `VBOX_GUEST_USER` / `VBOX_GUEST_PASSWORD` are configured in the MCP environment so credentials never enter the prompt context.

5. **Networking & headless debugging**
   - Discover a running VM's guest IP addresses and Guest Additions status with `get_vm_ip`.
   - Expose guest services to localhost with `manage_port_forwarding(..., action="add", is_running=True)`.
   - If a VM fails to boot, hangs at a login/BIOS prompt, or exhibits GUI errors, capture its framebuffer with `take_vm_screenshot` and inspect the PNG.
