# Example Pentest Results — RoE Comparison

These are real pentest results from NTREE running against a **Metasploitable 2** VM (`192.168.0.140`).
Both assessments used the same target, same prescan, same MCP tools — the **only difference is the Rules of Engagement (RoE)** template.

## Assessments

| | test4 (CTF Lab RoE) | test5 (Internal Network RoE) |
|---|---|---|
| RoE Template | `roe_ctf_lab.txt` | `roe_internal_network.txt` |
| Findings | **8** | **14** |
| Turns | 50 | 66 |
| API Cost | $0.99 | $1.32 |
| Scan Intensity | aggressive | normal |
| Rate Limiting | disabled | 3 attempts / 300s |
| Requires Approval | none | exploitation, credential extraction, lateral movement |
| Prohibited | none | data exfiltration, malware deployment, permanent changes |

## How RoE Changed the Agent's Behavior

### CTF Lab RoE (`test4_ctf_roe/`)

With all restrictions removed (`ALLOW_BRUTE_FORCE: true`, `RATE_LIMITING: disabled`, `SCAN_INTENSITY: aggressive`), the agent adopted a **capture-the-flag mindset**:

- Focused on high-impact exploitation wins (root shells, backdoors)
- Moved quickly through services — found it, exploited it, moved on
- Grouped related issues together (e.g., all web info disclosures as one finding)
- **8 findings in 50 turns** — fast and focused

### Internal Network RoE (`test5_internal_roe/`)

With corporate constraints (`MAX_LOGIN_ATTEMPTS: 3`, `REQUIRES_APPROVAL: exploitation`, `PROHIBITED: data exfiltration`), the agent adopted an **audit mindset**:

- Spent more turns on enumeration before attempting exploitation
- Documented configuration weaknesses that a CTF player would skip:
  - Telnet cleartext protocol exposure
  - R-Services (rexec/rlogin/rsh) on ports 512-514
  - SSH weak ciphers and key exchange algorithms
- Reported findings individually rather than grouping them
- **14 findings in 66 turns** — thorough and methodical

### Findings Only in test5 (Internal Network)

| Finding | Why It Matters for Corporate Networks |
|---------|--------------------------------------|
| Telnet Service Exposed | Cleartext credentials on the wire — compliance violation |
| R-Services Exposed (512-514) | Legacy trust-based auth — lateral movement risk |
| SSH Weak Ciphers | Fails security baseline audits (PCI-DSS, CIS) |
| SMB Null Session Access | Unauthenticated enumeration of shares and users |

These are legitimate risks in a corporate environment that don't matter in a CTF.

## Directory Structure

```
examples/
├── README.md                          # This file
├── test4_ctf_roe/                     # CTF Lab RoE assessment
│   ├── scope.txt                      # Target scope
│   ├── roe.txt                        # Rules of Engagement (CTF Lab)
│   ├── state.json                     # Assessment state + token usage
│   ├── findings/                      # 8 vulnerability findings (JSON)
│   │   ├── finding_001.json
│   │   └── ...
│   └── reports/                       # Generated reports
│       ├── report_test4.html          # HTML report with RoE section
│       └── report_test4.json          # Machine-readable JSON report
└── test5_internal_roe/                # Internal Network RoE assessment
    ├── scope.txt                      # Target scope (same target)
    ├── roe.txt                        # Rules of Engagement (Internal Network)
    ├── state.json                     # Assessment state + token usage
    ├── findings/                      # 14 vulnerability findings (JSON)
    │   ├── finding_001.json
    │   └── ...
    └── reports/                       # Generated reports
        ├── report_test5.html          # HTML report with RoE section
        └── report_test5.json          # Machine-readable JSON report
```

## Key Takeaway

**RoE doesn't just restrict — it shapes strategy.** The same AI agent, given the same target, produces fundamentally different assessments based on the rules it's given. This is exactly how a human pentester operates: a CTF player hunts flags, while a corporate auditor documents every risk.
