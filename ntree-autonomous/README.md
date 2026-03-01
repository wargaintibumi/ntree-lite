# NTREE Autonomous Agent

**Fully Automated Penetration Testing Using Claude SDK**

## Two Modes Available

### API Mode (ntree_agent.py)
- Direct Anthropic API with function calling
- 18 security tool definitions
- Lighter weight, simpler architecture
- Best for: Standard autonomous testing

### SDK Mode (ntree_agent_sdk.py)
- Claude Code SDK (claude-code-sdk library)
- Full MCP server integration
- Session-based working directories
- More Claude Code-like behavior
- Best for: Advanced workflows, better MCP integration

## Quick Start

```bash
# 1. Deploy autonomous mode
bash deploy_autonomous.sh

# 2. Configure API key
nano ~/ntree/config.json
# Set: anthropic.api_key = "sk-ant-..."

# 3. Run a pentest
# API Mode:
python ntree_agent.py --scope ~/ntree/templates/scope_example.txt

# SDK Mode:
python ntree_agent_sdk.py --scope ~/ntree/templates/scope_example.txt
```

## Files

```
ntree-autonomous/
├── ntree_agent.py              # API Mode - Direct Anthropic API
├── ntree_agent_sdk.py          # SDK Mode - Claude Code SDK
├── ntree_scheduler.py          # Automated scheduling
├── config.example.json         # Configuration template
├── requirements.txt            # Python dependencies
├── deploy_autonomous.sh        # Deployment script
└── README.md                   # This file
```

## How It Works

1. **Claude SDK Integration**: Uses Anthropic API for autonomous decision-making
2. **Tool Execution**: Calls security tool functions from ntree-mcp-servers
3. **Intelligent Workflow**: Claude decides:
   - Which hosts to scan
   - What services to enumerate
   - Which vulnerabilities to test
   - When to move between phases
   - What findings to prioritize

4. **Autonomous Operation**: No human interaction required
5. **Safety Controls**: All NTREE safety features remain active

## Features

### ✅ Fully Autonomous
- No human in the loop required
- Claude makes all tactical decisions
- Adapts strategy based on findings
- Completes entire pentest workflow independently

### ✅ Scheduled Automation
- Cron-based scheduling
- Daily/weekly/monthly recurring tests
- Systemd service integration
- Automatic report generation

### ✅ Complete Pentest Methodology
```
Phase 1: Reconnaissance
  └─ Network discovery, passive recon

Phase 2: Enumeration
  └─ Service enumeration, web profiling, SMB/AD enum

Phase 3: Vulnerability Assessment
  └─ CVE validation, config analysis, credential testing

Phase 4: Safe Exploitation
  └─ Lateral movement mapping, privilege escalation paths

Phase 5: Reporting
  └─ Risk scoring, multi-format reports, recommendations
```

### ✅ Safety Features
- Scope validation before every action
- Rate limiting (3 credential attempts per 5 min)
- Safe mode by default (validation without exploitation)
- Approval required for high-risk actions
- Complete audit logging
- Maximum iteration limits

## Configuration

### API Key

Get your API key from: https://console.anthropic.com/

```json
{
  "anthropic": {
    "api_key": "sk-ant-api03-...",
    "model": "claude-sonnet-4-5-20250929"
  }
}
```

### Pentest Settings

```json
{
  "pentest": {
    "max_iterations": 50,
    "default_scan_intensity": "normal",
    "credential_attempt_limit": 3,
    "enable_safe_mode": true
  }
}
```

### Automation

```json
{
  "automation": {
    "enabled": true,
    "schedule": "0 2 * * 0",  // Every Sunday at 2 AM
    "scope_file": "~/ntree/templates/scope_weekly.txt",
    "notification_webhook": "https://hooks.slack.com/..."
  }
}
```

## Usage

### Manual Execution

```bash
# Basic
python ntree_agent.py --scope scope.txt

# With ROE file
python ntree_agent.py --scope scope.txt --roe roe.txt

# Custom iteration limit
python ntree_agent.py --scope scope.txt --max-iterations 100

# Using helper script
~/ntree/run_pentest.sh ~/ntree/templates/my_scope.txt
```

### Automated Scheduling

```bash
# Enable scheduler service
sudo systemctl enable ntree-scheduler
sudo systemctl start ntree-scheduler

# Check status
sudo systemctl status ntree-scheduler

# View logs
tail -f ~/ntree/logs/scheduler.log

# Stop scheduler
sudo systemctl stop ntree-scheduler
```

## Tool Definitions

The agent has access to 18 security functions:

**Scope & Initialization:**
- `init_assessment()` - Initialize pentest assessment
- `verify_scope()` - Validate target in scope

**Reconnaissance:**
- `scan_network()` - Network scanning (nmap)
- `passive_recon()` - DNS/WHOIS research

**Enumeration:**
- `enumerate_services()` - Deep service enumeration
- `enumerate_web()` - Web application profiling
- `enumerate_smb()` - SMB/Windows enumeration
- `enumerate_domain()` - Active Directory enumeration

**Vulnerability Assessment:**
- `test_vuln()` - CVE validation
- `check_creds()` - Credential testing (rate-limited)
- `search_exploits()` - Exploit database search
- `analyze_config()` - Configuration analysis

**Post-Exploitation:**
- `analyze_trust()` - Lateral movement mapping
- `extract_secrets()` - Credential extraction (requires approval)
- `map_privileges()` - Privilege escalation opportunities

**Reporting:**
- `score_risk()` - Risk scoring and aggregation
- `generate_report()` - Multi-format report generation

## Decision-Making Example

```
User provides scope → Agent starts

Claude: "I'll initialize the assessment and scan the network"
  → Calls: init_assessment(scope_file)
  → Calls: scan_network(targets="192.168.1.0/24")

Claude: "Found 5 hosts. Host 192.168.1.10 has ports 80, 443, 445 open"
  → Calls: enumerate_web(url="http://192.168.1.10")
  → Calls: enumerate_smb(host="192.168.1.10")

Claude: "Web server is Apache 2.4.41 with known CVEs. Testing..."
  → Calls: test_vuln(host="192.168.1.10", vuln_id="CVE-2021-41773")

Claude: "Vulnerability confirmed! Also found anonymous SMB share"
  → Documents findings
  → Continues testing other hosts

Claude: "All hosts tested. Generating reports..."
  → Calls: score_risk(assessment_id)
  → Calls: generate_report(format="comprehensive")

Claude: "Penetration test complete. Found 8 vulnerabilities across 5 hosts"
  → Test completes autonomously
```

## API Costs

**Claude Sonnet 4.5 Pricing** (as of Jan 2025):
- Input: $3 / million tokens
- Output: $15 / million tokens

**Estimated Costs:**
- Small pentest (5 hosts): $1-2
- Medium pentest (20 hosts): $5-10
- Large pentest (100 hosts): $20-40
- Weekly automation: $10-50/month

## Monitoring

### Logs

```bash
# Agent activity
tail -f ~/ntree/logs/ntree_agent.log

# Scheduler activity
tail -f ~/ntree/logs/scheduler.log

# Security audit trail
tail -f ~/ntree/logs/audit.log
```

### Engagement Data

```bash
# List assessments
ls -lat ~/ntree/assessments/

# View assessment
cd ~/ntree/assessments/eng_20260109_120000/
ls findings/
ls reports/
cat state.json
```

## Notifications

### Slack

```json
{
  "automation": {
    "notification_webhook": "https://hooks.slack.com/services/T00/B00/XXX"
  }
}
```

Receives:
- ✅ Pentest completed
- 📊 Finding count
- 🔗 Report links
- ❌ Error alerts

## Troubleshooting

### Agent Won't Start

```bash
# Check API key
grep api_key ~/ntree/config.json

# Test API key
python -c "from anthropic import Anthropic; \
  Anthropic(api_key='YOUR_KEY').messages.create( \
  model='claude-sonnet-4-5-20250929', \
  max_tokens=10, \
  messages=[{'role':'user','content':'Hi'}])"

# Check dependencies
source venv/bin/activate
pip list | grep anthropic
```

### No Progress After Init

```bash
# Check scope file
cat ~/ntree/templates/scope_example.txt

# Verify security tools
nmap --version
nikto -Version

# Check logs
tail -50 ~/ntree/logs/ntree_agent.log
```

### High API Costs

```bash
# Reduce max iterations
nano ~/ntree/config.json
# Set: pentest.max_iterations = 30

# Use smaller scope
# Edit scope file to fewer targets

# Check usage
# Visit: https://console.anthropic.com/settings/usage
```

## Safety & Legal

⚠️ **CRITICAL WARNINGS**:

- **Authorization Required**: ALWAYS get written permission before testing
- **Scope Compliance**: NEVER test targets outside authorized scope
- **API Key Security**: NEVER commit API keys to version control
- **Autonomous ≠ Unsupervised**: Review findings and reports
- **Legal Liability**: You are responsible for all testing activities

## Architecture

```
┌─────────────────────────────────────────┐
│         ntree_agent.py                  │
│  ┌─────────────────────────────────┐   │
│  │  Claude SDK (Anthropic API)     │   │
│  │  - Autonomous decision-making   │   │
│  │  - Tool/function calling        │   │
│  └──────────┬──────────────────────┘   │
│             │                           │
│  ┌──────────▼──────────────────────┐   │
│  │  Security Tool Functions        │   │
│  │  (from ntree-mcp-servers)       │   │
│  │  - Network scanning             │   │
│  │  - Service enumeration          │   │
│  │  - Vulnerability testing        │   │
│  │  - Post-exploitation            │   │
│  │  - Report generation            │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

## Next Steps

1. ✅ Deploy: `bash deploy_autonomous.sh`
2. ✅ Configure: `nano ~/ntree/config.json`
3. ✅ Test: `python ntree_agent.py --scope scope.txt`
4. ✅ Review: `cat ~/ntree/assessments/eng_*/reports/*.html`
5. ✅ Automate: Enable scheduling in config

## Documentation

- **Full Guide**: See `AUTONOMOUS_MODE.md`
- **Mode Comparison**: See `MODE_COMPARISON.md` (API vs SDK modes explained)
- **Configuration**: See `config.example.json`
- **Installation**: See `deploy_autonomous.sh`

## Support

- **Issues**: Report at GitHub repository
- **Logs**: Check `~/ntree/logs/` for debugging
- **API Docs**: https://docs.anthropic.com/

---

**Version:** 1.0
**Compatible With:** NTREE v2.0+
**License:** MIT
