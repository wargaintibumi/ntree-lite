# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NTREE (Neura Tactical Red-Team Exploitation Engine) is an open-source autonomous penetration testing platform that integrates Claude Code with security tools via MCP (Model Context Protocol) servers. It runs on Raspberry Pi 5 or Kali Linux ARM64.

### Key Features

1. **Autonomous Operation**: Fully automated pentests from start to finish
   - Auto-report generation at assessment completion
   - Error recovery (max 5 consecutive errors before stopping)
   - Extended timeouts (30-minute total, 10-minute idle)
   - Phase tracking (init->recon->enum->vuln->report)

2. **Interactive Tools Detection**: Automatic detection of tools requiring user input
   - Pre-execution detection prevents commands from hanging
   - Flags operations for manual review with recommendations

3. **Custom Assessment Titles**: Name assessments with user-friendly titles
   - Example: `init_assessment(scope_file, title="Internal Network Pentest")`

4. **Automatic HTML Report Generation**: Professional reports via `complete_assessment`

5. **Wordlist Integration**: Built-in SecLists search and management

## Build & Development Commands

### Setup
```bash
bash setup.sh
bash setup.sh --yes  # Non-interactive mode
```

### MCP Servers (ntree-mcp-servers/)
```bash
cd ntree-mcp-servers
source venv/bin/activate

pip install -e .
pip install -e ".[dev]"

pytest tests/ -v
black ntree_mcp/
ruff check ntree_mcp/
mypy ntree_mcp/

# Run individual MCP servers
ntree-scope    # Scope validation server
ntree-scan     # Network scanning server
ntree-enum     # Service enumeration server
ntree-vuln     # Vulnerability testing server
ntree-report   # Reporting server
```

### Autonomous Agent (ntree-autonomous/)
```bash
cd ntree-autonomous
source venv/bin/activate
pip install -r requirements.txt

# SDK mode (requires claude auth login)
python ntree_agent_sdk.py --scope ~/ntree/templates/scope_example.txt
```

### Running Pentests
```bash
./start_pentest.sh --help
./start_pentest.sh --scope templates/scope_ctf_lab.txt
./start_pentest.sh --scope targets.txt --no-prescan
./start_pentest.sh --resume
./start_pentest.sh --list-sessions
```

### Live Monitoring
```bash
./ntree_monitor.py
./ntree_monitor.py --assessment assess_20260125_123456
./ntree_monitor.py --findings-only
```

### Prescan (ntree-autonomous/prescan.py)
```bash
python ntree-autonomous/prescan.py --scope targets.txt
python ntree-autonomous/prescan.py --scope targets.txt --ports quick
python ntree-autonomous/prescan.py --scope targets.txt --ports full
```

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `NTREE_HOME` | Base directory for NTREE files | `~/ntree` |
| `ANTHROPIC_API_KEY` | API key for autonomous mode | Required for autonomous |
| `SECLISTS_PATH` | Path to SecLists wordlists | `~/wordlists/SecLists` |

## Architecture

### Two Operational Modes
1. **Interactive (MCP)**: Human-in-the-loop via Claude Code with MCP servers
2. **Autonomous SDK**: Claude Code SDK with MCP integration (`ntree_agent_sdk.py`)

### MCP Server Structure (ntree-mcp-servers/ntree_mcp/)

| Server | Purpose |
|--------|---------|
| `scope.py` | Scope validation, assessment init, **save_finding**, **update_state** |
| `scan.py` | Network discovery, nmap, passive recon |
| `enum.py` | Service enumeration (web, SMB, LDAP, etc.), **wordlist search** |
| `vuln.py` | CVE testing, credential checking, exploit research |
| `report.py` | Risk scoring, report generation |

### Utility Modules (ntree-mcp-servers/ntree_mcp/utils/)
- `command_runner.py`: Safe subprocess execution with timeout, interactive tool detection
- `scope_parser.py`: Parses scope files (CIDR, domains, wildcards, EXCLUDE statements)
- `nmap_parser.py`: Parses nmap XML output
- `interactive_tools.py`: Detects interactive tools and suggests non-interactive alternatives
- `logger.py`: Colored logging setup
- `audit_logger.py`: Comprehensive audit logging for full penetration test audit trail
- `state_manager.py`: Centralized state management with file locking and checkpoint/resume
- `evidence_validator.py`: Evidence quality validation (distinguishes scan output from exploitation proof)
- `report_generator.py`: JSON-to-HTML report generation with professional templates

### Data Flow
```
Scope file -> [Prescan: masscan -> nmap] -> live_targets.txt (with service annotations)
    |
ScopeValidator -> init_assessment() loads prescan services/OS
    | (agent skips scan_network when prescan has service data)
enumerate_services() -> test_vuln() -> save_finding() -> generate_report()
```

### Critical: Data Flow for Real Reports

For reports to contain real findings, Claude MUST follow this workflow:

```
1. init_assessment(scope_file)        -> Creates assessment directory
2. scan_network(targets)              -> Returns real nmap results
3. save_finding(                      -> SAVES finding to findings/*.json
     title="SMB Signing Disabled",
     severity="high",
     description="...",
     affected_hosts=["192.168.1.10"],
     evidence="nmap output...",
     cvss_score=5.3,
     remediation="Enable SMB signing"
   )
4. update_state(                      -> Updates state.json with discovered assets
     phase="ENUM",
     hosts=["192.168.1.10", "192.168.1.11"],
     services=["192.168.1.10:445/smb"]
   )
5. generate_report(assessment_id)     -> Reads findings/*.json, generates report
```

**Without calling `save_finding()` after discovering vulnerabilities, reports will be empty!**

## Key Patterns

### MCP Tool Pattern
```python
from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

app = Server("ntree-{module}")

class ToolArgs(BaseModel):
    param: str = Field(description="...")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(name="...", inputSchema=ToolArgs.model_json_schema())]

@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    args = ToolArgs(**arguments)
    result = await handler(...)
    return [TextContent(type="text", text=json.dumps(result, indent=2))]
```

### Input Validation (security critical)
```python
def validate_ip_or_cidr(target: str) -> bool:
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'

def validate_url(url: str) -> bool:
    url_pattern = r'^https?://[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(:[0-9]{1,5})?(/.*)?$'
    return bool(re.match(url_pattern, url))
```

**Always validate inputs before passing to shell commands!**

### Scope Validation (defense in depth)
```python
if not await verify_scope(target):
    return {"status": "error", "error": "Target out of scope"}
```

### Standard Response Pattern
```python
try:
    result = await operation()
    return {"status": "success", "data": result}
except Exception as e:
    logger.error(f"Operation failed: {e}", exc_info=True)
    return {"status": "error", "error": str(e)}
```

### Safe Command Execution
```python
import shlex
target = shlex.quote(validated_target)
cmd = f"nmap -sV {target}"
```

## Safety Architecture

- **Scope validation**: Every action checked against authorized targets via `verify_scope()`
- **Rate limiting**: Max 3 credential attempts per account per 5 minutes
- **Safe mode**: Validation without exploitation by default
- **Approval workflow**: High-risk operations require `approved=True`
- **Circuit breakers**: Unresponsive targets automatically skipped
- **Interactive tool detection**: Automatic detection and flagging of tools requiring user input
- **stdin blocking**: All commands executed with stdin=DEVNULL to prevent interactive prompts
- **Audit logging**: Complete action history with timestamps

## Evidence Quality Validation

### Quality Levels
| Level | Description |
|-------|-------------|
| `excellent` | Clear proof of exploitation with impact demonstrated |
| `good` | Demonstrates vulnerability exploitation |
| `acceptable` | Shows vulnerability exists with some validation |
| `weak` | Mostly scan output, limited validation |
| `insufficient` | Pure scan output, no exploitation proof |

## Session Resume Capability

```bash
./start_pentest.sh --list-sessions
./start_pentest.sh --resume
./start_pentest.sh --resume my_assessment_name
```

## 5-Phase Testing Workflow

0. **INIT** - Scope validation, assessment setup, load prescan results
1. **RECON** - Network discovery, OS fingerprinting
2. **ENUM** - Service detection, versioning, CVE correlation
3. **VULN** - Safe vulnerability testing, credential checks
4. **REPORT** - Risk scoring, documentation -> **COMPLETE**

## Scope File Syntax
```
192.168.1.100        # Single IP
192.168.1.0/24       # CIDR range
example.com          # Domain
*.example.com        # Wildcard subdomains
EXCLUDE 192.168.1.1  # Exclusion
```

## Project File Structure

```
ntree/
├── setup.sh                           # Main installation script
├── start_pentest.sh                   # Launcher script
├── ntree_monitor.py                   # Live monitoring tool
├── CLAUDE.md                          # This file
├── README.md                          # User-facing documentation
├── config.json                        # Configuration
├── LICENSE                            # MIT License
├── ntree-mcp-servers/                 # MCP server implementations
│   ├── setup.py                       # Python package configuration
│   ├── test_servers.py                # Integration test suite
│   └── ntree_mcp/                     # Main package
│       ├── scope.py                   # Scope validation & assessment init
│       ├── scan.py                    # Network scanning (nmap, masscan)
│       ├── enum.py                    # Service enumeration
│       ├── vuln.py                    # Vulnerability testing
│       ├── report.py                  # Report generation
│       └── utils/                     # Shared utilities
│           ├── command_runner.py      # Safe command execution
│           ├── scope_parser.py        # Scope file parsing
│           ├── nmap_parser.py         # nmap XML parsing
│           ├── interactive_tools.py   # Interactive tool detection
│           ├── audit_logger.py        # Comprehensive audit logging
│           ├── logger.py              # Logging configuration
│           ├── state_manager.py       # Centralized state with checkpoints
│           ├── evidence_validator.py  # Evidence quality validation
│           └── report_generator.py    # JSON-to-HTML reports
├── ntree-autonomous/                  # Autonomous mode
│   ├── ntree_agent_sdk.py             # SDK mode (MCP integration)
│   ├── prescan.py                     # Pre-scan host discovery
│   └── requirements.txt               # Python dependencies
├── templates/                         # Scope templates
│   ├── scope_example.txt
│   ├── scope_single_target.txt
│   ├── scope_internal_network.txt
│   ├── scope_ctf_lab.txt
│   ├── scope_external.txt
│   ├── scope_active_directory.txt
│   └── scope_webapp.txt
└── ~/ntree/                           # Runtime directory
    ├── assessments/                   # Assessment workspaces
    ├── prescans/                      # Prescan output directories
    └── logs/                          # Pre-assessment staging logs
```

## Tech Stack

- Python 3.10+ with asyncio
- MCP Protocol for AI tool integration
- Pydantic v2.0+ for data validation
- Security tools: nmap, masscan, nuclei, nikto, gobuster, hydra, crackmapexec, etc.
