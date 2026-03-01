# NTREE MCP Servers

Python Model Context Protocol servers for NTREE penetration testing on Raspberry Pi 5 / Kali Linux ARM64.

## Overview

This package provides 8 specialized MCP servers that integrate security tools with Claude Code for automated penetration testing:

- **ntree-scope**: Scope validation, assessment initialization, finding storage, report generation
- **ntree-scan**: Network discovery and port scanning (nmap, masscan)
- **ntree-enum**: Service enumeration (SMB, web, LDAP, DNS, etc.)
- **ntree-vuln**: Vulnerability testing and CVE validation
- **ntree-post**: Post-exploitation and lateral movement analysis
- **ntree-report**: Risk scoring
- **ntree-wifi**: Wi-Fi and router security assessment
- **ntree-troubleshoot**: Self-error troubleshooting with Claude SDK integration

## Installation

### Prerequisites

- Python 3.11 or later
- Raspberry Pi OS (64-bit) or Kali Linux ARM64
- Security tools installed (nmap, enum4linux, nikto, etc.)

### Install from Source

```bash
cd ntree-mcp-servers

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install package
pip install -e .

# Install dev dependencies
pip install -e ".[dev]"
```

## Configuration

### Claude Code Integration

Add to `~/.config/claude-code/mcp-servers.json`:

```json
{
  "mcpServers": {
    "ntree-scope": {
      "command": "/home/kali/ntree/ntree-mcp-servers/venv/bin/python",
      "args": ["-m", "ntree_mcp.scope"],
      "env": { "NTREE_HOME": "/home/kali/ntree" }
    },
    "ntree-scan": {
      "command": "/home/kali/ntree/ntree-mcp-servers/venv/bin/python",
      "args": ["-m", "ntree_mcp.scan"],
      "env": { "NTREE_HOME": "/home/kali/ntree" }
    }
  }
}
```

Add entries for all 8 servers (scope, scan, enum, vuln, post, report, wifi, troubleshoot).

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `NTREE_HOME` | Base directory for assessments and logs | `~/ntree` |
| `ANTHROPIC_API_KEY` | API key for autonomous/troubleshoot SDK mode | Required for API mode |
| `SECLISTS_PATH` | Path to SecLists wordlists | `~/wordlists/SecLists` |
| `NTREE_WORDLISTS_PATH` | Base wordlist directory | `~/wordlists` |
| `NTREE_INCLUDE_CREDENTIALS` | Include full passwords in findings (`true`/`false`) | `false` |
| `NTREE_AUDIT_SESSION_ID` | Cross-process audit session sharing | Auto-set |
| `NTREE_AUDIT_ASSESSMENT_ID` | Cross-process audit assessment sharing | Auto-set |

## Usage

### 1. Initialize Assessment

```python
# Via MCP (from Claude Code)
ntree-scope.init_assessment(
    scope_file="/home/kali/ntree/templates/scope_example.txt",
    title="Internal Network Pentest"
)
```

### 2. Scan Network

```python
ntree-scan.scan_network(
    targets="192.168.1.0/24",
    scan_type="tcp_syn",
    intensity="normal"
)
```

### 3. Save Finding

```python
ntree-scope.save_finding(
    title="SMB Signing Disabled",
    severity="high",
    description="...",
    affected_hosts=["192.168.1.10"],
    evidence="nmap output...",
    cvss_score=5.3,
    remediation="Enable SMB signing"
)
```

### 4. Generate Report

```python
ntree-scope.complete_assessment()
# Generates JSON + HTML reports in assessments/{id}/reports/
```

## Development

### Project Structure

```
ntree-mcp-servers/
├── ntree_mcp/
│   ├── __init__.py
│   ├── scope.py           # Scope validation, assessment init, save_finding, complete_assessment
│   ├── scan.py            # Network scanning (nmap, masscan)
│   ├── enum.py            # Service enumeration (web, SMB, LDAP, etc.)
│   ├── vuln.py            # Vulnerability testing, CVE correlation
│   ├── post.py            # Post-exploitation, lateral movement
│   ├── report.py          # Risk scoring
│   ├── wifi.py            # Wi-Fi/Router security (supports NTREE_INCLUDE_CREDENTIALS)
│   ├── troubleshoot.py    # Self-error troubleshooting with Claude SDK
│   └── utils/
│       ├── __init__.py
│       ├── command_runner.py      # Safe subprocess execution
│       ├── scope_parser.py        # Scope file parsing (CIDR, domains, wildcards)
│       ├── nmap_parser.py         # nmap XML output parsing
│       ├── interactive_tools.py   # Interactive tool detection & alternatives
│       ├── wifi_utils.py          # Wi-Fi utilities (interface, channel)
│       ├── logger.py              # Colored logging setup
│       ├── audit_logger.py        # Comprehensive audit logging (JSON Lines, singleton)
│       ├── state_manager.py       # State management with file locking & checkpoints
│       ├── retry.py               # Smart retry with exponential backoff
│       ├── evidence_validator.py  # Evidence quality validation (type-specific guidance)
│       ├── scope_expansion.py     # Out-of-scope link detection
│       ├── report_generator.py    # JSON-to-HTML report generation with session interaction log
│       └── performance_metrics.py # Cross-process performance metrics
├── tests/
│   └── test_performance_metrics.py  # Unit tests for performance metrics
├── test_servers.py        # Integration test suite (7 suites, all MCP servers)
├── setup.py
├── requirements.txt
└── README.md
```

### Running Tests

```bash
source venv/bin/activate

# Unit tests
pytest tests/ -v

# Integration tests (all 7 MCP server suites)
python test_servers.py

# With coverage
pytest tests/ --cov=ntree_mcp --cov-report=html
```

### Code Quality

```bash
source venv/bin/activate

# Format code
black ntree_mcp/

# Lint
ruff check ntree_mcp/

# Type checking
mypy ntree_mcp/

# Syntax check individual file
python3 -c "import ast; ast.parse(open('ntree_mcp/utils/report_generator.py').read()); print('OK')"
```

## MCP Server API Reference

### ntree-scope

**init_assessment**(scope_file, title, roe_file)
- Initialize assessment with scope validation
- Creates `~/ntree/assessments/{id}/` directory structure
- Returns assessment_id and validated scope

**verify_scope**(target)
- Check if target is in authorized scope
- Returns boolean with explanation

**save_finding**(title, severity, description, affected_hosts, evidence, cvss_score, remediation, ...)
- Save a vulnerability finding to `findings/*.json`
- Automatically enriches with evidence quality validation
- **Required** for findings to appear in reports

**update_state**(phase, hosts, services, ...)
- Update `state.json` with current assessment state
- Used as ground truth for SDK completion validation

**complete_assessment**()
- Generates JSON + HTML reports from all saved findings
- Populates host table with OS/hostname/ports from scan XML
- Includes Session Interaction Log in HTML from audit log

### ntree-scan

**scan_network**(targets, scan_type, intensity, ports)
- Perform nmap network scan
- Returns discovered hosts and services

**passive_recon**(domain)
- DNS enumeration, subdomain discovery, WHOIS
- No direct contact with target

### ntree-enum

**enumerate_services**(host, ports)
- Detailed service version detection
- Returns service list with versions

**enumerate_web**(url, depth)
- Web application enumeration, technology detection

**enumerate_smb**(host)
- SMB/Windows enumeration (shares, users, domain)

### ntree-vuln

**test_vuln**(host, service, vuln_id, safe_mode)
- Test for specific vulnerability
- Returns exploitability status

**check_creds**(host, service, username, password, hash)
- Validate credentials, returns access level

**search_exploits**(service, version)
- Search exploit databases

### ntree-post

**analyze_trust**(host, session_info)
- Map lateral movement paths

**extract_secrets**(host, session_info, types)
- Extract credentials/hashes — **requires explicit approval**

**map_privileges**(host, session_info)
- Privilege escalation opportunities

### ntree-wifi

**scan_wireless_networks**(interface, duration, passive_only)
- Discover nearby Wi-Fi networks

**assess_router_security**(target, interface)
- Comprehensive router security assessment

**test_wps**(target, bssid, interface)
- Test WPS vulnerabilities

> Set `NTREE_INCLUDE_CREDENTIALS=true` to include full passwords in findings.

### ntree-report

**score_risk**(assessment_id)
- Calculate CVSS-based risk scores
- Returns business impact assessment

### ntree-troubleshoot

**log_error**(error_message, error_type, source, context)
- Log errors for pattern analysis

**analyze_error**(error_message, context, use_claude_sdk)
- Diagnose errors with pattern matching + Claude SDK

**apply_fix**(fix_type, fix_command, target, dry_run)
- Apply suggested fixes (supports dry_run)

**self_diagnose**(check_mcp_servers, check_tools, check_permissions, check_network)
- Comprehensive infrastructure diagnostics

## Report Generation

HTML reports are generated by `complete_assessment()` and include:

- **Executive Summary** - Risk overview, findings count by severity
- **Host Table** - IP, hostname, OS, open ports (enriched from nmap XML)
- **Findings** - Full vulnerability details with evidence quality ratings
- **Methodology** - Tools used, phases, duration
- **Performance Metrics** - Timing per tool/phase
- **Session Interaction Log** - Full terminal + MCP + Claude interaction history

### Re-generating a Report

```bash
source venv/bin/activate
python3 -c "
from ntree_mcp.utils.report_generator import ReportGenerator
import json
from pathlib import Path

aid = 'your_assessment_id'
gen = ReportGenerator(aid)
base = Path.home() / 'ntree/assessments' / aid
state = json.loads((base / 'state.json').read_text())
findings = [json.loads(f.read_text()) for f in sorted((base / 'findings').glob('*.json'))]
raw_hosts = state.get('discovered_assets', {}).get('hosts', [])
hosts = [{'ip': h} if isinstance(h, str) else h for h in raw_hosts]
services = state.get('discovered_assets', {}).get('services', [])
jp = gen.generate_json_report(findings, hosts, services, state)
hp = gen.generate_html_report(jp)
print(f'HTML: {hp}')
"
```

## Security Considerations

### Scope Validation

Every action is validated against scope:

```python
if not await verify_scope(target):
    return {"status": "error", "error": "Target out of scope"}
```

### Audit Logging

All actions logged to:
- `~/ntree/assessments/{id}/logs/` — Assessment audit log (JSON Lines)
- `~/ntree/logs/audit/` — Pre-assessment staging (auto-migrated on init)

### Rate Limiting

Built-in protections:
- Max 3 credential attempts per account per 5 minutes
- Adaptive scan timing
- Circuit breakers for unresponsive targets

## Troubleshooting

### MCP Server Not Picking Up Code Changes

MCP servers are started once per Claude Code session. After modifying source files, restart the Claude Code session or run:

```bash
# Restart specific MCP server (if using systemd)
systemctl --user restart ntree-scope
```

### Permission Errors (airodump-ng, nmap)

```bash
# Ensure sudo configured for security tools
sudo visudo /etc/sudoers.d/ntree
# Add: kali ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/sbin/airmon-ng, /usr/sbin/airodump-ng
```

### Tool Not Found

```bash
which nmap masscan nuclei nikto
sudo apt install nmap masscan nikto
```

---

**Version**: 2.2.0
**Status**: Beta
**Python**: 3.11+
**Platform**: Raspberry Pi 5 / Kali Linux ARM64
