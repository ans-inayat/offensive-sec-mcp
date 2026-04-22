# offensive-sec-mcp
**Daemons Zyrax — Ans Inayat**

An offensive-security **MCP tool router** with a slick local dashboard — built to make your operator workflow feel like a cat: quiet, fast, and always landing on its feet.

- **MCP server (stdio)**: exposes your tool registry as MCP tools
- **Local dashboard**: FastAPI + WebSocket terminal streaming
- **Scope guardrails**: blocks out-of-scope targets and keeps outputs organized
- **Installer**: `install_tools.sh` preflights/installs common Kali dependencies

---

## Quick Start

```bash
# 0) (Kali) install tool deps
sudo ./install_tools.sh

# 1) Python deps (recommended: venv)
python3 -m venv mcp
source mcp/bin/activate
pip install -r requirements.txt

# 2. Set Anthropic API key (for AI agent)
export ANTHROPIC_API_KEY="sk-ant-..."

# 3. Launch
chmod +x start.sh && ./start.sh

# Dashboard opens at: http://localhost:8000
# API docs at:        http://localhost:8000/docs
```

---

## Project Structure

```
offensive-sec-mcp/
├── api_server.py              # FastAPI backend (main)
├── start.sh                   # Launcher script
├── install_tools.sh           # Kali preflight/installer
├── requirements.txt
├── mcp_server/
│   ├── mcp_server.py          # MCP stdio server
│   └── tools_registry.py      # All tool definitions
├── static/
│   └── index.html             # Frontend dashboard
├── logs/                      # Audit logs (auto-created)
├── reports/                   # Tool output files (auto-created)
└── payloads/                  # Generated payloads (auto-created)
```

---

## MCP Integration (Claude Desktop / Claude Code)

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "offensive-kali": {
      "command": "python3",
      "args": ["/path/to/offensive-mcp-agent/mcp_server/mcp_server.py"]
    }
  }
}
```

Claude can then call any tool directly:
- `set_scope` — define authorized targets
- `nmap_basic` — run nmap scan
- `gobuster_dir` — directory brute-force
- `sqlmap_basic` — SQLi scan
- `msfvenom_exe` — generate payload
- `bloodhound_collect` — AD data collection
- `eaphammer` — WPA2-Enterprise attack
- ... and 80+ more

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/tools` | List all tools (filter by category/platform/search) |
| GET | `/api/tools/{name}` | Tool details |
| POST | `/api/tools/build-command` | Preview command without executing |
| POST | `/api/scope` | Set engagement scope |
| GET | `/api/scope` | Get current scope |
| POST | `/api/payload/generate` | Generate payload via msfvenom |
| GET | `/api/reports` | List output files |
| GET | `/api/audit` | Audit log entries |
| POST | `/api/ai/chat` | Claude AI assistant (REST) |
| POST | `/api/mcp/config` | Generate MCP JSON config |
| WS | `/ws/terminal` | Real-time command execution |
| WS | `/ws/ai` | Streaming AI chat |

---

## Tool Categories (90 tools)

| Category | Tools |
|----------|-------|
| Recon & OSINT | nmap, masscan, theHarvester, amass, subfinder, shodan, whois, dnsx |
| Scanning | nikto, gobuster, feroxbuster, ffuf, nuclei, enum4linux, ldap_enum, snmpwalk |
| Web Attacks | sqlmap, xsstrike, commix, wfuzz, jwt_tool, cors_scan |
| Exploitation | metasploit, searchsploit, msfvenom (5 formats), netcat |
| Post-Exploitation | linpeas, winpeas, evil-winrm, chisel, ligolo-ng, mimikatz, bloodhound |
| Password Attacks | hydra, hashcat (3 modes), john, crackmapexec, responder, impacket, kerbrute |
| Wireless | airmon, airodump, aireplay, aircrack, eaphammer, hcxdumptool, wifite |
| Windows-Specific | rubeus, powerview, seatbelt, sharpup, psexec, wmiexec |
| C2 Frameworks | sliver, havoc, mythic, empire, poshc2 |

---

## Security Notes

- All tool executions validated against defined scope
- Scope violations are blocked and logged
- Audit log written to `logs/audit_YYYYMMDD.jsonl`
- Use only on authorized systems — you are responsible
- Risk levels: low → medium → high → critical

---

## License

Licensed under the **GNU General Public License v3.0**. See `LICENSE`.
