# VirtualBox MCP Server

A production-ready [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server built with FastMCP that gives your AI assistant safe, structured control over your local Oracle VirtualBox environment via `VBoxManage`.

Spin up headless sandboxes, snapshot state before risky changes, discover guest IP addresses, copy scripts in and out of VMs, configure NAT port forwarding or shared folders, capture screenshots, and run guest commands directly from your AI client.

## Features

- **20 Specialized Tools + 1 MCP Resource (`vbox://vms`):** Full VM lifecycle (creation, unattended OS install, cloning, `.ova`/`.ovf` import/export, guarded deletion), snapshots, storage/ISO control, guest execution, bidirectional file copy, NAT port forwarding, shared folders, resource sizing, IP discovery, and screenshots.
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
| `manage_shared_folders` | `list`, `add`, or `remove` permanent or transient shared folders. | Mutating |
| `configure_vm_resources` | Update `cpus`, `memory_mb`, `vram_mb`, and `clipboard_mode` on a stopped VM. | Idempotent |
| `clone_vm` | Create full or linked clones (from a snapshot) and register them. | Mutating |
| `take_vm_screenshot` | Capture a PNG screenshot of a running VM display for debugging. | Idempotent |
| `list_os_types` | List supported VirtualBox guest OS type IDs (with optional `search` filter). | Read-only, Idempotent |
| `create_vm` | Create and register a new VM with CPUs, RAM, VRAM, NIC mode, VDI disk, and optional ISO. | Mutating |
| `unattended_install` | Configure hands-free OS installation from an ISO with Guest Additions support. | Destructive |
| `import_vm` | Import a pre-built `.ova` or `.ovf` appliance (supports `dry_run` and overrides). | Mutating |
| `export_vm` | Export a stopped VM into an `.ova` or `.ovf` appliance archive. | Read-only, Idempotent |
| `manage_storage` | `list` controllers/attached media, `attach-iso`, or `eject-iso` on virtual DVD drives. | Idempotent |
| `delete_vm` | Guarded VM teardown (`confirm=True` required; optionally removes disk files). | Destructive |

**Resource:** `vbox://vms` exposes the registered VM inventory directly as an MCP resource.

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
