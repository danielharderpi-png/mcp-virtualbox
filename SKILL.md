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

2. **Default Agent VM: Kali Linux**
   - Whenever asked to create or spin up a VM for the agent (unless the user explicitly requests a different OS), ALWAYS provision a **Kali Linux** VM with `provision_kali_vm` instead of creating a blank Ubuntu VM with `create_vm`.
   - Follow this provisioning order:
     1. Call `list_vms` first; if a Kali base/template VM already exists with a `clean-base` snapshot, clone it rapidly with `provision_kali_vm(vm_name="...", base_vm="<existing-kali>", linked_clone=True, start_vm=True)`.
     2. Otherwise, provision from the official pre-built Kali VirtualBox image (`.7z` -> `.vbox` + `.vdi`, Guest Additions pre-installed) using `image_path` / `VBOX_KALI_IMAGE_PATH` if available locally, or `download=True` to download and SHA-256-verify the latest official image from `https://cdimage.kali.org/current/`.
     3. Fresh official Kali pre-built images default to username `kali` and password `kali` with Guest Additions pre-installed; rotate the default password on first boot (or create a dedicated low-privilege user) and store credentials in `VBOX_GUEST_USER` / `VBOX_GUEST_PASSWORD`.

3. **Snapshot before risky work**
   - Always create a restore point before running untrusted code, upgrades, or destructive commands:
     - `manage_snapshot(vm_name=..., action="take", snapshot_name="pre-test", description="Clean checkpoint")`
   - Pass `live=True` when snapshotting a running VM without pausing execution.
   - If a test fails or breaks the environment, revert cleanly with `manage_snapshot(..., action="restore")`.

4. **Prefer headless starts & linked clones**
   - Use `manage_power(vm_name=..., action="start", mode="headless")` by default unless GUI output is explicitly needed.
   - For disposable test sandboxes, take a clean base snapshot (`clean-base`) and spin up fast copies with `provision_kali_vm(vm_name=..., base_vm=..., linked_clone=True)` or `clone_vm(source_vm=..., new_name=..., linked=True, snapshot_name="...")`.

5. **Transfer scripts instead of stuffing complex one-liners**
   - When running multi-line scripts or test suites inside a VM, upload files with `copy_to_guest` and then invoke them cleanly with `execute_guest_command` (setting `cwd` and `env` explicitly).
   - Pull logs or build artifacts back to the host with `copy_from_guest`.
   - Leave `username` and `password` omitted when `VBOX_GUEST_USER` / `VBOX_GUEST_PASSWORD` are configured in the MCP environment so credentials never enter the prompt context.

6. **Networking, lab isolation, packet capture, & forensics**
   - Build isolated multi-VM lab subnets with `manage_nat_networks` (custom CIDR + DHCP) or `manage_hostonly_ifs` (controlled host-to-guest subnets + DHCP), and attach VMs via `manage_network_adapters` (`natnetwork`, `intnet`, `hostonly`, `none` for air-gapped sandboxes, plus `promisc_mode` and live link toggling).
   - Checkpoint or roll back an entire running multi-VM range in one call with `manage_range_snapshots` (`action="snapshot"` or `action="revert", confirm=True`).
   - Discover a running VM's guest IP addresses and Guest Additions status with `get_vm_ip`, and inspect active Guest Control jobs with `get_guest_process_list`.
   - Expose guest services to localhost with `manage_port_forwarding(..., action="add", is_running=True)`.
   - Capture network traffic directly at the hypervisor layer without touching the guest using `capture_nic_traffic(..., action="start" | "stop")`.
   - Acquire volatile RAM images for host-side Volatility analysis with `dump_guest_memory` (pauses and resumes running VMs automatically for a consistent ELF core dump), monitor sandbox CPU/RAM/Disk spikes with `inspect_guest_metrics`, and attach read-only/immutable forensic or scratch drives with `manage_disk_images`.
   - For early-boot prompts (GRUB, LUKS, BIOS) or VMs without Guest Additions, inject keystrokes with `send_guest_keystrokes` and inspect the display with `take_vm_screenshot`.

7. **Provisioning, registration, appliances, media, and safe teardown**
   - Use `provision_kali_vm` as the default path for agent VMs, and `register_vm` to register existing `.vbox` machine definitions, extracted VM folders, or `.7z` VirtualBox archives.
   - For non-Kali or custom OS builds, look up valid guest OS IDs first with `list_os_types(search=...)` before calling `create_vm` (use `os_type="Debian_64"` if ever installing Kali from a standalone `.iso`) and automate installation with `unattended_install` (preferring `VBOX_GUEST_USER` / `VBOX_GUEST_PASSWORD` env vars).
   - For pre-built `.ova`/`.ovf` appliances, use `import_vm(..., dry_run=True)` to inspect requirements before importing, and `export_vm` to archive configured VMs as `.ova` files.
   - Mount or swap installer ISOs on existing VMs with `manage_storage(..., action="attach-iso" | "eject-iso")`.
   - Only tear down disposable VMs with `delete_vm(..., confirm=True)` after double-checking `delete_files`.
