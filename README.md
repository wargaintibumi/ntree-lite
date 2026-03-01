# NTREE - Neural Tactical Red-Team Exploitation Engine

**Open Source Edition**

An autonomous penetration testing platform powered by Claude Code, integrating AI with security tools via the Model Context Protocol (MCP). Runs on Raspberry Pi 5 or Kali Linux ARM64.

## Features

- **Autonomous pentesting** - Fully automated from scope to report
- **5 MCP servers** - Scope validation, scanning, enumeration, vulnerability testing, reporting
- **Professional HTML reports** - Auto-generated with findings, evidence, and remediation
- **Prescan pipeline** - Fast host discovery with masscan + detailed nmap fingerprinting
- **Evidence validation** - Distinguishes exploitation proof from scan-only output
- **Scope enforcement** - Every action verified against authorized targets
- **Session resume** - Pick up interrupted assessments where you left off
- **Audit logging** - Complete action history for compliance

## Quick Start

### 1. Install

```bash
git clone https://github.com/YOUR_USERNAME/ntree.git
cd ntree
bash setup.sh --yes
```

### 2. Create a scope file

```
# targets.txt
192.168.1.0/24
EXCLUDE 192.168.1.1
```

### 3. Run a pentest

```bash
./start_pentest.sh --scope targets.txt
```

Or use interactively with Claude Code:

```bash
claude
# Then: "Start NTREE with scope: ~/ntree/templates/scope_ctf_lab.txt"
```

## MCP Servers

| Server | Purpose | Key Tools |
|--------|---------|-----------|
| **ntree-scope** | Assessment lifecycle | `init_assessment`, `verify_scope`, `save_finding`, `update_state`, `complete_assessment` |
| **ntree-scan** | Network discovery | `scan_network`, `quick_scan`, `passive_recon` |
| **ntree-enum** | Service enumeration | `enumerate_services`, `search_wordlists`, `web_crawl` |
| **ntree-vuln** | Vulnerability testing | `test_vulnerability`, `check_credentials`, `research_exploits` |
| **ntree-report** | Report generation | `score_risk`, `generate_report` |

## Prescan

Discover live hosts before the full assessment:

```bash
python ntree-autonomous/prescan.py --scope targets.txt              # Standard
python ntree-autonomous/prescan.py --scope targets.txt --ports quick # Fast
python ntree-autonomous/prescan.py --scope targets.txt --ports full  # Thorough
```

## Monitoring

Watch a pentest in real-time from another terminal:

```bash
./ntree_monitor.py                    # Auto-detect active assessment
./ntree_monitor.py --findings-only    # Only show new findings
```

## Session Resume

```bash
./start_pentest.sh --list-sessions    # See resumable sessions
./start_pentest.sh --resume           # Interactive selection
./start_pentest.sh --resume name      # Resume specific assessment
```

## Safety

- Scope validation on every action
- Rate limiting (3 credential attempts per account per 5 minutes)
- Interactive tool detection prevents hanging
- All commands run with stdin=DEVNULL
- Comprehensive audit logging

## Scope File Syntax

```
192.168.1.100        # Single IP
192.168.1.0/24       # CIDR range
example.com          # Domain
*.example.com        # Wildcard subdomains
EXCLUDE 192.168.1.1  # Exclusion
```

## Requirements

- Python 3.10+
- Kali Linux or Raspberry Pi OS (ARM64)
- Claude Code CLI (`claude`)
- Security tools: nmap, masscan, nuclei, nikto, gobuster, hydra, etc.

## Development

```bash
cd ntree-mcp-servers
source venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
black ntree_mcp/
ruff check ntree_mcp/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [SecLists](https://github.com/danielmiessler/SecLists) by Daniel Miessler
- [MCP Protocol](https://modelcontextprotocol.io/) by Anthropic
- [Claude Code](https://claude.ai/code) by Anthropic
