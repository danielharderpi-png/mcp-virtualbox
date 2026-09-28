[![M8ven Score](https://m8ven.ai/badge/mcp/danielharderpi-png-mcp-virtualbox-d44dck)](https://m8ven.ai/mcp/danielharderpi-png-mcp-virtualbox-d44dck)
# VirtualBox MCP Server

A lightweight Model Context Protocol (MCP) server that gives your AI assistant direct control over your local VirtualBox environment. 

AI models are great at writing code, but they usually lack a safe, isolated environment to actually test it. This bridge allows any MCP-compatible AI (like Claude Desktop, Cline, or local agents) to interact with `VBoxManage`. Your AI can now spin up your virtual machines, take safety snapshots, and execute scripts directly inside the guest OS.

## Features
* **VM Discovery:** List all registered virtual machines and check if they are running or stopped.
* **Power Management:** Start (headless by default), stop, force-stop, pause, and resume VMs.
* **Snapshot Control:** Take, restore, delete, and list snapshots so the AI can create safe restore points before running risky code.
* **Guest Execution:** Run shell commands and scripts directly inside the guest OS using `VBoxManage guestcontrol`.

## Prerequisites
* Python 3.10+
* Oracle VirtualBox installed. (The server automatically checks your system PATH, with built-in fallback paths for standard Windows and Linux installations).
* VirtualBox Guest Additions installed on the target VMs (strictly required if you want the AI to use the guest execution tool).

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
   **Linux/macOS:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

To use this server, you need to add it to your MCP client's configuration file. Point the `command` to the Python executable inside your virtual environment, and the `args` to the `server.py` file.

### Example: Claude Desktop or Cline (VS Code)
Add this snippet to your MCP configuration JSON, replacing the paths with your actual absolute paths:

```json
{
  "mcpServers": {
    "virtualbox-manager": {
      "command": "/absolute/path/to/mcp-virtualbox/venv/bin/python",
      "args": [
        "/absolute/path/to/mcp-virtualbox/server.py"
      ]
    }
  }
}
```
*(Windows users: Remember to use double backslashes in your JSON paths, e.g., `C:\\path\\to\\venv\\Scripts\\python.exe`)*

## Contributing
This tool was built to solve a specific infrastructure gap for local AI development. If you find a bug, a pathing issue on a specific OS, or want to add tools for network interface management, pull requests are highly encouraged and welcome.

For more information on this project and other terminal tools, visit helloterminalio.com.
