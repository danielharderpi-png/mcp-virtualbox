# Privacy Policy

**Last Updated:** November 2026

## Overview
The `mcp-virtualbox` server is a local software component designed to run exclusively on your local hardware. It acts as an interface between an MCP-compatible AI client and your local Oracle VirtualBox (`VBoxManage`) installation.

## Data Collection
This software collects **no data whatsoever**:
- No telemetry, analytics, or usage data is gathered.
- No information is transmitted over the internet by this server.
- All command executions, VM states, file transfers, and screenshots remain strictly on your local machine.

## Credential Handling & Security
- Guest credentials passed to `execute_guest_command`, `copy_to_guest`, and `copy_from_guest` are forwarded locally to `VBoxManage` only.
- All `--password` and `--password-file` values are redacted (`***`) from diagnostic logs and error messages.
- To avoid passing guest passwords inside AI chat prompts, configure `VBOX_GUEST_USER` and `VBOX_GUEST_PASSWORD` in your MCP client's environment block and use a dedicated, low-privilege guest account inside your VMs.

## Third-Party Access
Because this server operates locally over `stdio`, no data is sent to third parties by `mcp-virtualbox`. Prompts and tool outputs shared with an LLM provider are governed by that provider's privacy policy.
