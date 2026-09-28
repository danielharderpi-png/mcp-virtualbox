# Privacy Policy

**Last Updated:** September 2026

## Overview
The `mcp-virtualbox` server is a local software component designed to run exclusively on your local hardware. It acts as an interface between an AI agent and your local Oracle VirtualBox installation.

## Data Collection
This software collects **no data whatsoever**. 
- No telemetry, analytics, or usage data is gathered.
- No information is transmitted across the internet by this server.
- All command executions, credentials, and virtual machine metadata remain strictly on your local machine.

## Third-Party Access
Because this software operates entirely locally, no data is shared with third parties. Any prompts, inputs, or system states evaluated by the AI models you use are governed by the privacy policies of those respective model providers (e.g., Anthropic, OpenAI). 

## Security
Guest execution tools require passing credentials locally via command-line arguments to `VBoxManage`. We strongly recommend creating dedicated, low-privilege guest accounts within your VMs for AI automation purposes.