# VirtualBox MCP Server

A production-ready [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server built with FastMCP that gives your AI assistant safe, structured control over your local Oracle VirtualBox environment via `VBoxManage`.

Spin up headless sandboxes, snapshot state before risky changes, discover guest IP addresses, copy scripts in and out of VMs, configure NAT port forwarding or shared folders, capture screenshots, and run guest commands directly from your AI client.

## Features

- **32 Specialized Tools + 1 MCP Resource (`vbox://vms`):** Full VM lifecycle (Kali Linux agent VM provisioning, `.vbox`/`.7z` registration, VM creation, unattended OS install, cloning, `.ova`/`.ovf` import/export, guarded deletion), isolated lab networking (`manage_network_adapters`, `manage_nat_networks`, `manage_hostonly_ifs`), hypervisor-level PCAP capture (`capture_nic_traffic`), memory & disk forensics (`dump_guest_memory`, `inspect_guest_metrics`, `manage_disk_images`), multi-VM range checkpointing (`manage_range_snapshots`), virtual keyboard injection (`send_guest_keystrokes`), Guest Control process listing (`get_guest_process_list`), snapshots, storage/ISO control, guest execution, bidirectional file copy, NAT port forwarding, shared folders, resource sizing, IP discovery, and screenshots.
- **Native MCP Tool Annotations:** Accurate `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` hints so MCP clients know which operations mutate state.
- **Credential Redaction & Env Fallbacks:** Passwords (`--password` / `--password-file`) are automatically scrubbed from error messages and logs, and can be supplied via `VBOX_GUEST_USER` / `VBOX_GUEST_PASSWORD` so credentials never appear in chat history.
- **CLI Flag-Injection & Bounds Validation:** Rejects invalid/flag-prefixed identifiers (`--...`), validates port/resource ranges, and runs `VBoxManage` without `shell=True`.
- **Thread-Safe Sliding-Window Rate Limiting:** Applied cleanly at the MCP tool boundary (configurable via `VBOX_MAX_CALLS_PER_MINUTE`) so multi-command tools like `list_vms` never self-throttle.

## Prerequisites

- **Python 3.10+**
- **Oracle VirtualBox** installed locally (`VBoxManage` in `PATH`, standard install directory, or via `VBOXMANAGE_PATH`).
- **VirtualBox Guest Additions** installed in target VMs for `get_vm_ip`, `execute_guest_command`, `copy_to_guest`, `copy_from_guest`, and shared folders.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/danielharderpi-png/mcp-virtualbox.git
   cd mcp-virtualbox
   ```

2. Create and activate a virtual environment:

   **Windows:**
   ```cmd
   python -m venv venv
   venv\Scripts\activate
   ```

   **Linux / macOS:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies (or install editable with the `mcp-virtualbox` console script):
   ```bash
   pip install -r requirements.txt
   # Or:
   pip install -e .
   ```

## Configuration

Add the server to your MCP client configuration (Claude Desktop, Cline, Cursor, etc.):

```json
{
  "mcpServers": {
    "virtualbox-manager": {
      "command": "/absolute/path/to/mcp-virtualbox/venv/bin/python",
      "args": ["/absolute/path/to/mcp-virtualbox/server.py"],
      "env": {
        "VBOX_GUEST_USER": "sandbox",
        "VBOX_GUEST_PASSWORD": "your-low-priv-guest-password"
      }
    }
  }
}
```

*(Windows example command: `C:\\path\\to\\mcp-virtualbox\\venv\\Scripts\\python.exe`)*

### Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `VBOXMANAGE_PATH` | Auto-detected | Explicit path to the `VBoxManage` executable. |
| `VBOX_GUEST_USER` | *(none)* | Default guest OS username for `guestcontrol` tools. |
| `VBOX_GUEST_PASSWORD` | *(none)* | Default guest OS password so secrets stay out of prompts. |
| `VBOX_MAX_CALLS_PER_MINUTE` | `60` | Sliding-window tool rate limit (`0` disables limiting). |
| `VBOX_REQUIRE_STRICT_AUTH` | `false` | Set to `true` to require `VBOX_API_TOKEN`. |
| `VBOX_API_TOKEN` | *(none)* | Token checked when `VBOX_REQUIRE_STRICT_AUTH=true`. |
| `VBOX_LOG_LEVEL` | `WARNING` | `stderr` log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `VBOX_KALI_IMAGE_PATH` | *(none)* | Default local `.7z`, `.vbox`, extracted directory, or `.ova`/`.ovf` used by `provision_kali_vm`. |
| `VBOX_KALI_BASE_VM` | *(none)* | Existing Kali template VM name/UUID used for cloning when `provision_kali_vm` runs without explicit source. |
| `VBOX_KALI_CACHE_DIR` | `~/.mcp-virtualbox/kali` | Directory where downloaded official Kali VirtualBox `.7z` archives are cached. |
| `VBOX_KALI_IMAGE_BASE_URL` | `https://cdimage.kali.org/current/` | HTTPS base URL hosting `SHA256SUMS` and official Kali VirtualBox `.7z` images. |

## Tool Reference

| Tool | Description | Hints |
| --- | --- | --- |
| `list_vms` | List all registered VMs (or `running_only=True`) with UUIDs and states. | Read-only, Idempotent |
| `get_vm_info` | Structured summary of CPU/RAM/NICs/forwards/folders/snapshots (`verbose=True` for raw). | Read-only, Idempotent |
| `get_vm_ip` | Discover guest IPv4/IPv6 addresses and Guest Additions version. | Read-only, Idempotent |
| `manage_power` | Power actions: `start` (`headless`/`gui`/`separate`), `stop`, `force-stop`, `reset`, `savestate`, `pause`, `resume`. | Destructive |
| `manage_snapshot` | `list`, `take` (with `--description` and `--live`), `restore`, or `delete` snapshots. | Destructive |
| `execute_guest_command` | Run an executable inside a guest with optional `args`, `cwd`, `env`, and `timeout`. | Destructive, Open-world |
| `copy_to_guest` | Copy a file or directory from the host into the guest VM (`recursive` supported). | Idempotent |
| `copy_from_guest` | Copy a file or directory from the guest VM back to the host. | Idempotent |
| `manage_port_forwarding` | `list`, `add`, or `delete` NAT port-forwarding rules (offline or live on running VMs). | Mutating |
| `manage_network_adapters` | `list` or `configure` NICs 1–8 (`nat`, `natnetwork`, `intnet`, `hostonly`, `bridged`, `none`), link state, promiscuous mode, and MAC (offline or live). | Idempotent |
| `manage_nat_networks` | `list`, `add`, `modify`, `remove`, `start`, or `stop` VirtualBox NAT Networks with custom IPv4 CIDR blocks and DHCP. | Mutating |
| `manage_hostonly_ifs` | `list`, `create`, `configure`, `remove`, `dhcp-configure`, or `dhcp-remove` Host-Only interfaces and DHCP servers. | Mutating |
| `capture_nic_traffic` | `status`, `start`, or `stop` hypervisor-level PCAP packet capture on a VM NIC (offline or live). | Idempotent |
| `dump_guest_memory` | Capture a raw ELF core dump (`debugvm dumpvmcore`) of a running/paused VM's RAM for host-side Volatility analysis. | Mutating |
| `inspect_guest_metrics` | `setup`, `query`, or `disable` hypervisor-level CPU, RAM, Disk, and Network metrics for a VM or host. | Idempotent |
| `manage_disk_images` | `list`, `create`, `clone`, `set-type` (`normal`/`immutable`/`readonly`), `attach`, or `detach` virtual hard disks. | Mutating |
| `manage_range_snapshots` | Batch `snapshot` or guarded `revert` (`confirm=True`) across all running lab VMs (or an explicit VM list). | Destructive |
| `send_guest_keystrokes` | Send text, named special keys (`ENTER`, `ESC`, `F1`–`F12`, `CTRL_ALT_DEL`), or PS/2 scancodes without Guest Additions. | Mutating |
| `get_guest_process_list` | List active VirtualBox Guest Control processes on a running VM. | Read-only, Idempotent |
| `manage_shared_folders` | `list`, `add`, or `remove` permanent or transient shared folders. | Mutating |
| `configure_vm_resources` | Update `cpus`, `memory_mb`, `vram_mb`, and `clipboard_mode` on a stopped VM. | Idempotent |
| `clone_vm` | Create full or linked clones (from a snapshot) and register them. | Mutating |
| `take_vm_screenshot` | Capture a PNG screenshot of a running VM display for debugging. | Idempotent |
| `list_os_types` | List supported VirtualBox guest OS type IDs (with optional `search` filter). | Read-only, Idempotent |
| `create_vm` | Create and register a new VM with CPUs, RAM, VRAM, NIC mode, VDI disk, and optional ISO. | Mutating |
| `unattended_install` | Configure hands-free OS installation from an ISO with Guest Additions support. | Destructive |
| `import_vm` | Import a pre-built `.ova` or `.ovf` appliance (supports `dry_run` and overrides). | Mutating |
| `register_vm` | Register an existing `.vbox` file, VM directory, or `.7z` VirtualBox archive with optional overrides. | Mutating |
| `provision_kali_vm` | Provision a Kali Linux agent VM from an official `.7z`/`.vbox`/`.ova` image (with optional verified HTTPS download) or clone an existing Kali VM. | Mutating, Open-world |
| `export_vm` | Export a stopped VM into an `.ova` or `.ovf` appliance archive. | Read-only, Idempotent |
| `manage_storage` | `list` controllers/attached media, `attach-iso`, or `eject-iso` on virtual DVD drives. | Idempotent |
| `delete_vm` | Guarded VM teardown (`confirm=True` required; optionally removes disk files). | Destructive |

**Resource:** `vbox://vms` exposes the registered VM inventory directly as an MCP resource.

### Kali Linux Agent VM Setup

Official pre-built Kali Linux VirtualBox images come with Guest Additions pre-installed and default credentials `kali` / `kali`.

1. **First-time provisioning** (downloads & SHA-256-verifies the official `.7z` archive, extracts it, registers the `.vbox`, sets 2 vCPUs / 4096 MB RAM / 128 MB VRAM, and takes a `clean-base` snapshot):
   ```text
   provision_kali_vm(vm_name="Kali-Agent", download=True, start_vm=True)
   ```
   *(Or pass a local archive/folder directly with `image_path="/path/to/kali-linux-*-virtualbox-amd64.7z"`, or set `VBOX_KALI_IMAGE_PATH`.)*
2. **Fast linked-clone reuse** for additional disposable agent VMs:
   ```text
   provision_kali_vm(vm_name="Kali-Sandbox-1", base_vm="Kali-Agent", linked_clone=True, start_vm=True)
   ```
3. **Credential hygiene:** On first boot, rotate the default `kali` password (or create a dedicated low-privilege guest user) and store those credentials in `VBOX_GUEST_USER` / `VBOX_GUEST_PASSWORD`.

## Security Best Practices

1. Create a dedicated, **low-privilege account** inside your guest VMs for automation rather than using `root` or `Administrator`.
2. Pass guest credentials via `VBOX_GUEST_USER` / `VBOX_GUEST_PASSWORD` in your MCP client's `env` configuration instead of typing passwords in conversation prompts.
3. Always take a snapshot (`manage_snapshot(..., action="take")`) before testing destructive commands or untrusted software in a VM.

## Running Tests

```bash
python -m unittest test_server.py -v
```

## License

MIT — see [LICENSE](LICENSE). For more terminal tools, visit [helloterminalio.com](https://helloterminalio.com).
