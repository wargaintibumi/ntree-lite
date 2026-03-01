"""
NTREE Scope Validation MCP Server
Manages assessment initialization and scope validation
"""

import asyncio
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from .utils.scope_parser import ScopeValidator
from .utils.logger import get_logger
from .utils.audit_logger import get_audit_logger, AuditEventType
from .utils.state_manager import get_state_manager, StateManager
from .utils.evidence_validator import validate_evidence, enrich_finding_with_validation, EvidenceQuality
from .utils.report_generator import ReportGenerator, generate_report

logger = get_logger(__name__)

# Initialize audit logger
def _get_audit():
    """Get audit logger with lazy initialization and env var sync"""
    try:
        audit = get_audit_logger()

        # Sync with environment variables (set by SDK agent)
        env_session_id = os.environ.get("NTREE_AUDIT_SESSION_ID")
        env_assessment_id = os.environ.get("NTREE_AUDIT_ASSESSMENT_ID")

        if env_session_id and audit.session_id != env_session_id:
            audit.session_id = env_session_id
        if env_assessment_id and audit.assessment_id != env_assessment_id:
            audit.set_assessment_id(env_assessment_id)

        return audit
    except Exception:
        return None

# Initialize MCP server
app = Server("ntree-scope")

# Global scope validator (set during init_assessment)
_scope_validator: Optional[ScopeValidator] = None
_current_assessment_id: Optional[str] = None
_state_lock = asyncio.Lock()  # Lock for thread-safe access to global state


class InitAssessmentArgs(BaseModel):
    """Arguments for init_assessment tool."""
    scope_file: str = Field(description="Path to scope file containing authorized targets")
    title: str = Field(default="", description="Assessment title (e.g., 'Internal Network Pentest'). If empty, uses timestamp.")
    roe_file: str = Field(default="", description="Path to rules of assessment file (optional)")


class VerifyScopeArgs(BaseModel):
    """Arguments for verify_scope tool."""
    target: str = Field(description="IP address or domain to verify against scope")


class SaveFindingArgs(BaseModel):
    """Arguments for save_finding tool."""
    title: str = Field(description="Finding title (e.g., 'SMB Signing Disabled')")
    severity: str = Field(description="Severity: critical, high, medium, low, or informational")
    description: str = Field(description="Detailed description of the finding")
    affected_hosts: list = Field(description="List of affected IP addresses or hostnames")
    evidence: str = Field(default="", description="REQUIRED: Proof of exploitation - command output showing successful exploitation, not just scan results. Include actual exploitation attempts, extracted data, or successful command execution.")
    cvss_score: float = Field(default=0.0, description="CVSS score (0.0-10.0)")
    remediation: str = Field(default="", description="Recommended remediation steps")
    references: list = Field(default=[], description="CVE IDs, URLs, or other references")
    exploitable: bool = Field(default=False, description="Whether vulnerability was confirmed exploitable through actual exploitation attempt")
    replay_commands: list = Field(default=[], description="Exact shell commands to replay in a live xterm for authentic evidence screenshots (e.g. ['nc -w5 192.168.0.140 1524', 'id', 'whoami']). When provided, the commands are re-executed in a real terminal and screenshotted.")


class UpdateStateArgs(BaseModel):
    """Arguments for update_state tool."""
    phase: str = Field(default="", description="Current phase (RECON, ENUM, VULN, EXPLOIT, POST, REPORT)")
    hosts: list = Field(default=[], description="Discovered hosts to add")
    services: list = Field(default=[], description="Discovered services to add")
    credentials: list = Field(default=[], description="Discovered credentials to add (username:service:access_level)")


class CompleteAssessmentArgs(BaseModel):
    """Arguments for complete_assessment tool."""
    pass  # Uses current assessment ID


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="init_assessment",
            description="Initialize penetration test assessment with scope and ROE validation. Must be called before any other actions.",
            inputSchema=InitAssessmentArgs.model_json_schema()
        ),
        Tool(
            name="verify_scope",
            description="Verify if a target (IP or domain) is within the authorized scope. Returns true/false with reason.",
            inputSchema=VerifyScopeArgs.model_json_schema()
        ),
        Tool(
            name="save_finding",
            description="Save a security finding with PROOF OF EXPLOITATION. Evidence must show actual exploitation success (e.g., command output, extracted data, shell access), NOT just scan results. Findings are used to generate reports.",
            inputSchema=SaveFindingArgs.model_json_schema()
        ),
        Tool(
            name="update_state",
            description="Update assessment state with discovered assets (hosts, services, credentials) and current phase.",
            inputSchema=UpdateStateArgs.model_json_schema()
        ),
        Tool(
            name="complete_assessment",
            description="Mark assessment as complete and automatically generate comprehensive HTML report with all findings.",
            inputSchema=CompleteAssessmentArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    # Audit log the tool call
    audit = _get_audit()
    call_id = None
    if audit:
        call_id = audit.log_tool_call(
            tool_name=f"ntree-scope.{name}",
            arguments=arguments
        )

    try:
        if name == "init_assessment":
            args = InitAssessmentArgs(**arguments)
            result = await init_assessment(args.scope_file, args.title, args.roe_file)
            # Audit log assessment init
            if audit and result.get("status") == "success":
                audit.log_assessment_init(
                    assessment_id=result.get("assessment_id", ""),
                    scope_file=args.scope_file,
                    roe_file=args.roe_file if args.roe_file else None
                )
            if audit and call_id:
                audit.log_tool_output(f"ntree-scope.{name}", call_id, result, result.get("status", "success"))
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "verify_scope":
            args = VerifyScopeArgs(**arguments)
            result = await verify_scope(args.target)
            # Audit log scope validation
            if audit:
                audit.log_scope_validation(
                    target=args.target,
                    in_scope=result.get("in_scope", False),
                    reason=result.get("reason")
                )
            if audit and call_id:
                audit.log_tool_output(f"ntree-scope.{name}", call_id, result, "success")
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "save_finding":
            args = SaveFindingArgs(**arguments)
            result = await save_finding(
                args.title,
                args.severity,
                args.description,
                args.affected_hosts,
                args.evidence,
                args.cvss_score,
                args.remediation,
                args.references,
                args.exploitable,
                args.replay_commands
            )
            # Audit log finding saved
            if audit and result.get("status") == "success":
                audit.log_finding(
                    title=args.title,
                    severity=args.severity,
                    target=", ".join(args.affected_hosts[:3]) if args.affected_hosts else "",
                    finding_id=result.get("finding_id")
                )
            if audit and call_id:
                audit.log_tool_output(f"ntree-scope.{name}", call_id, result, result.get("status", "success"))
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "update_state":
            args = UpdateStateArgs(**arguments)
            result = await update_state(
                args.phase,
                args.hosts,
                args.services,
                args.credentials
            )
            # Audit log phase change if applicable
            if audit and args.phase:
                audit.log_phase_change("", args.phase)
            if audit and call_id:
                audit.log_tool_output(f"ntree-scope.{name}", call_id, result, result.get("status", "success"))
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "complete_assessment":
            result = await complete_assessment()
            # Audit log assessment complete
            if audit and result.get("status") == "success":
                audit.log_assessment_complete(
                    assessment_id=result.get("assessment_id", ""),
                    findings_count=result.get("findings_count", 0),
                    reports_generated=result.get("reports", [])
                )
            if audit and call_id:
                audit.log_tool_output(f"ntree-scope.{name}", call_id, result, result.get("status", "success"))
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            if audit and call_id:
                audit.log_tool_output(f"ntree-scope.{name}", call_id, error_result, "error")
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        # Audit log error
        if audit and call_id:
            audit.log_tool_error(f"ntree-scope.{name}", call_id, e)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


def _parse_roe_flags(roe_text: str) -> Dict[str, str]:
    """
    Parse KEY: value flags from Rules of Engagement text.

    Extracts lines matching "KEY: value" (ignoring comments and blank lines).
    Returns a dict of flag names to their values.
    """
    flags = {}
    for line in roe_text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Match KEY: value (key is uppercase/underscores, value is the rest)
        match = re.match(r'^([A-Z][A-Z0-9_]+)\s*:\s*(.+)$', line)
        if match:
            flags[match.group(1)] = match.group(2).strip()
    return flags


async def init_assessment(scope_file: str, title: str = "", roe_file: str = "") -> dict:
    """
    Initialize assessment with scope and ROE validation.

    Args:
        scope_file: Path to scope file
        title: Assessment title (if empty, uses timestamp)
        roe_file: Path to rules of assessment file (optional)

    Returns:
        {
            "status": "success",
            "assessment_id": "internal_network_pentest" or "assess_20250108_103045",
            "title": "Internal Network Pentest",
            "validated_scope": {
                "included_ranges": ["192.168.1.0/24"],
                "included_ips": ["10.0.0.50"],
                "included_domains": ["example.com"],
                "excluded_ips": ["192.168.1.1"],
                "excluded_ranges": []
            },
            "restrictions": {...},
            "assessment_dir": "/home/pi/ntree/assessments/internal_network_pentest"
        }
    """
    global _scope_validator, _current_assessment_id

    try:
        logger.info(f"Initializing assessment with scope file: {scope_file}")

        # Expand path
        scope_path = Path(scope_file).expanduser().resolve()

        if not scope_path.exists():
            return {
                "status": "error",
                "error": f"Scope file not found: {scope_file}"
            }

        # Initialize scope validator and assessment ID with lock protection
        async with _state_lock:
            _scope_validator = ScopeValidator(scope_path)

            # Generate assessment ID from title or timestamp
            if title:
                # Convert title to safe directory name
                safe_title = title.lower().replace(" ", "_").replace("-", "_")
                # Remove unsafe characters
                import re
                safe_title = re.sub(r'[^a-z0-9_]', '', safe_title)
                _current_assessment_id = safe_title
            else:
                # Use timestamp if no title provided
                _current_assessment_id = f"assess_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                title = _current_assessment_id

            # Store local copies for use outside the lock
            current_id = _current_assessment_id
            validator = _scope_validator

        # Create assessment directory structure
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / current_id

        assessment_dir.mkdir(parents=True, exist_ok=True)
        (assessment_dir / "scans").mkdir(exist_ok=True)
        (assessment_dir / "findings").mkdir(exist_ok=True)
        (assessment_dir / "evidence").mkdir(exist_ok=True)
        (assessment_dir / "reports").mkdir(exist_ok=True)
        (assessment_dir / "logs").mkdir(exist_ok=True)

        logger.info(f"Created assessment directory: {assessment_dir}")

        # Copy prescan files if scope came from a prescan directory
        try:
            prescan_summary = scope_path.parent / "prescan_summary.json"
            if prescan_summary.exists():
                import shutil
                scans_dir = assessment_dir / "scans"
                # Copy summary
                shutil.copy2(str(prescan_summary), str(scans_dir / "prescan_summary.json"))
                # Copy full prescan results
                prescan_results = scope_path.parent / "prescan_results.json"
                if prescan_results.exists():
                    shutil.copy2(str(prescan_results), str(scans_dir / "prescan_results.json"))
                # Copy masscan result files
                for mf in scope_path.parent.glob("masscan_*.json"):
                    shutil.copy2(str(mf), str(scans_dir / mf.name))
                # Copy nmap results if present
                for nf in scope_path.parent.glob("nmap_*.xml"):
                    shutil.copy2(str(nf), str(scans_dir / nf.name))
                logger.info(f"Copied prescan files to {scans_dir}")
        except Exception as e:
            logger.debug(f"Could not copy prescan files: {e}")

        # Parse ROE if provided
        restrictions = {}
        if roe_file:
            roe_path = Path(roe_file).expanduser().resolve()
            if roe_path.exists():
                # Simple ROE parsing - just store the path for now
                # Can be enhanced to parse specific restrictions
                restrictions["roe_file"] = str(roe_path)
                logger.info(f"Loaded ROE file: {roe_path}")

        # Save scope to assessment directory
        scope_copy = assessment_dir / "scope.txt"
        scope_copy.write_text(scope_path.read_text())

        # Parse prescan port/service hints from scope file comments (live_targets.txt format)
        # New format: "192.168.1.5  # ports: 22,80,443 | ssh(OpenSSH 8.9),http(nginx 1.18),https"
        # Old format: "192.168.1.5  # ports: 22,80,443"
        prescan_hosts: dict = {}
        try:
            for line in scope_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '# ports:' in line:
                    ip_part, comment_part = line.split('# ports:', 1)
                    ip = ip_part.strip()
                    comment_part = comment_part.strip()
                    if not ip or not comment_part:
                        continue

                    # Split on | to separate ports from service hints
                    if '|' in comment_part:
                        ports_str, svc_str = comment_part.split('|', 1)
                        ports_str = ports_str.strip()
                        svc_str = svc_str.strip()
                    else:
                        ports_str = comment_part
                        svc_str = ""

                    try:
                        ports = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]
                    except ValueError:
                        ports = []

                    if not ports:
                        continue

                    # Parse service hints if present
                    services: dict = {}
                    if svc_str:
                        svc_items = svc_str.split(',')
                        for i, svc_item in enumerate(svc_items):
                            svc_item = svc_item.strip()
                            if not svc_item:
                                continue
                            # Map service to corresponding port by position
                            if i < len(ports):
                                services[str(ports[i])] = svc_item

                    if services:
                        prescan_hosts[ip] = {"ports": ports, "services": services}
                    else:
                        prescan_hosts[ip] = ports
        except Exception as e:
            logger.warning(f"Error parsing prescan data: {e}")

        # Copy ROE file to assessment directory if provided and parse flags
        roe_summary = ""
        roe_flags = {}
        roe_file_path = restrictions.get("roe_file", "")
        if roe_file_path:
            roe_src = Path(roe_file_path)
            if roe_src.exists():
                roe_copy = assessment_dir / "roe.txt"
                roe_content = roe_src.read_text()
                roe_copy.write_text(roe_content)
                roe_summary = roe_content.strip()
                roe_flags = _parse_roe_flags(roe_content)

        # Build original scope targets and exclusions for report
        scope_targets = (
            [str(r) for r in validator.included_ranges]
            + [str(ip) for ip in validator.included_ips]
            + list(validator.included_domains)
        )
        scope_exclusions = (
            [str(r) for r in validator.excluded_ranges]
            + [str(ip) for ip in validator.excluded_ips]
        )

        # Create initial state file
        state = {
            "assessment_id": current_id,
            "title": title,
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "phase": "INITIALIZATION",
            "scope_file": str(scope_path),
            "scope_targets": scope_targets,
            "scope_exclusions": scope_exclusions,
            "roe_file": roe_file_path,
            "roe_summary": roe_summary,
            "roe_flags": roe_flags,
            "prescan_hosts": prescan_hosts,
            "assessment_dir": str(assessment_dir),
            "discovered_assets": {
                "hosts": [],
                "services": [],
                "credentials": []
            },
            "findings": [],
            "action_history": []
        }

        state_file = assessment_dir / "state.json"
        state_file.write_text(json.dumps(state, indent=2))

        # Write marker file so other MCP server processes can discover the assessment ID
        try:
            marker = ntree_home / "current_assessment.txt"
            marker.write_text(current_id)
        except Exception:
            pass

        logger.info(f"Assessment {current_id} initialized successfully")

        # Build RoE permissions summary for the agent
        roe_permissions = {}
        if roe_flags:
            roe_permissions["assessment_type"] = roe_flags.get("ASSESSMENT_TYPE", "unknown")
            # Collect all ALLOW_* flags
            for key, value in roe_flags.items():
                if key.startswith("ALLOW_"):
                    roe_permissions[key] = value
            # Include scan intensity and rate limiting
            if "SCAN_INTENSITY" in roe_flags:
                roe_permissions["SCAN_INTENSITY"] = roe_flags["SCAN_INTENSITY"]
            if "RATE_LIMITING" in roe_flags:
                roe_permissions["RATE_LIMITING"] = roe_flags["RATE_LIMITING"]

        return {
            "status": "success",
            "assessment_id": current_id,
            "title": title,
            "validated_scope": {
                "included_ranges": [str(r) for r in validator.included_ranges],
                "included_ips": [str(ip) for ip in validator.included_ips],
                "included_domains": list(validator.included_domains),
                "excluded_ips": [str(ip) for ip in validator.excluded_ips],
                "excluded_ranges": [str(r) for r in validator.excluded_ranges],
            },
            "scope_summary": validator.get_scope_summary(),
            "restrictions": restrictions,
            "roe_permissions": roe_permissions,
            "assessment_dir": str(assessment_dir),
            "prescan_hosts": prescan_hosts,
        }

    except Exception as e:
        logger.error(f"Error initializing assessment: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def verify_scope(target: str) -> dict:
    """
    Verify if target is in scope.

    Args:
        target: IP address or domain to check

    Returns:
        {
            "in_scope": true/false,
            "reason": "explanation",
            "target": "192.168.1.10"
        }
    """
    global _scope_validator, _current_assessment_id

    async with _state_lock:
        if not _scope_validator:
            return {
                "in_scope": False,
                "reason": "Assessment not initialized. Call init_assessment first.",
                "target": target
            }

        # Get local copies of globals
        validator = _scope_validator
        current_id = _current_assessment_id

    try:
        in_scope, reason = validator.is_in_scope(target)

        logger.info(f"Scope check: {target} -> {'IN SCOPE' if in_scope else 'OUT OF SCOPE'}")

        if not in_scope:
            logger.warning(f"SCOPE VIOLATION BLOCKED: {target} - {reason}")

        return {
            "in_scope": in_scope,
            "reason": reason,
            "target": target,
            "assessment_id": current_id
        }

    except Exception as e:
        logger.error(f"Error verifying scope for {target}: {e}")
        return {
            "in_scope": False,
            "reason": f"Error during scope validation: {str(e)}",
            "target": target
        }


async def save_finding(
    title: str,
    severity: str,
    description: str,
    affected_hosts: list,
    evidence: str = "",
    cvss_score: float = 0.0,
    remediation: str = "",
    references: list = None,
    exploitable: bool = False,
    replay_commands: list = None
) -> dict:
    """
    Save a security finding to the assessment directory.

    IMPORTANT: Evidence must be proof of exploitation, not just scan results.
    - Good evidence: Command output showing successful exploitation, extracted data, shell access
    - Bad evidence: Just nmap or nuclei scan output showing a vulnerability exists
    - Best practice: Include the actual exploitation command and its successful output

    Args:
        title: Finding title
        severity: Severity level (critical, high, medium, low, informational)
        description: Detailed description of the vulnerability and exploitation
        affected_hosts: List of affected hosts
        evidence: REQUIRED - Proof of successful exploitation (not just scan results)
        cvss_score: CVSS score (0.0-10.0)
        remediation: Recommended remediation steps
        references: CVE IDs, URLs, or other references
        exploitable: True if vulnerability was confirmed through exploitation attempt

    Returns:
        {
            "status": "success",
            "finding_id": "finding_001",
            "finding_path": "/path/to/finding.json"
        }
    """
    global _current_assessment_id

    async with _state_lock:
        if not _current_assessment_id:
            return {
                "status": "error",
                "error": "Assessment not initialized. Call init_assessment first."
            }
        current_id = _current_assessment_id

    try:
        # Get assessment directory (needed before validation to load RoE flags)
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / current_id
        findings_dir = assessment_dir / "findings"

        # Load RoE flags from state.json for context-aware evidence validation
        roe_flags = {}
        state_file = assessment_dir / "state.json"
        if state_file.exists():
            try:
                state_data = json.loads(state_file.read_text())
                roe_flags = state_data.get("roe_flags", {})
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Error saving finding: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }

    # Validate evidence quality using the evidence validator (RoE-aware)
    evidence_validation = validate_evidence(
        evidence=evidence,
        finding_type=title,
        severity=severity,
        require_exploitation=(severity.lower() in ("critical", "high")),
        roe_flags=roe_flags
    )

    # Log validation results
    if evidence_validation.quality in (EvidenceQuality.WEAK, EvidenceQuality.INSUFFICIENT):
        logger.warning(
            f"Finding '{title}' has {evidence_validation.quality.value} evidence quality. "
            f"Issues: {', '.join(evidence_validation.issues[:2])}"
        )
        if evidence_validation.suggestions:
            logger.info(f"Suggestions: {evidence_validation.suggestions[0]}")

    try:

        # Generate finding ID
        existing_findings = list(findings_dir.glob("finding_*.json"))
        finding_num = len(existing_findings) + 1
        finding_id = f"finding_{finding_num:03d}"

        # Determine exploitation status
        if exploitable and evidence and len(evidence.strip()) >= 50:
            # Has exploit proof
            exploitation_status = "CONFIRMED"
        elif evidence and len(evidence.strip()) >= 20:
            # Has some evidence but not confirmed exploited
            exploitation_status = "NEEDS_VERIFICATION"
        else:
            # No evidence or insufficient evidence
            exploitation_status = "REQUIRES_MANUAL_CHECK"

        # Create finding object with evidence validation
        finding = {
            "finding_id": finding_id,
            "title": title,
            "severity": severity.lower(),
            "description": description,
            "affected_hosts": affected_hosts,
            "evidence": evidence,
            "cvss_score": cvss_score,
            "remediation": remediation,
            "references": references or [],
            "exploitable": exploitable,
            "exploitation_status": exploitation_status,
            "discovered_at": datetime.now().isoformat(),
            "assessment_id": current_id,
            "evidence_validation": {
                "quality": evidence_validation.quality.value,
                "score": evidence_validation.score,
                "issues": evidence_validation.issues,
                "suggestions": evidence_validation.suggestions,
                "has_exploitation_proof": len(evidence_validation.exploitation_indicators) > 0
            }
        }

        # Save finding to file
        finding_path = findings_dir / f"{finding_id}.json"
        finding_path.write_text(json.dumps(finding, indent=2))

        # Update state file with finding reference
        state_file = assessment_dir / "state.json"
        if state_file.exists():
            state = json.loads(state_file.read_text())
            if "findings" not in state:
                state["findings"] = []
            state["findings"].append({
                "id": finding_id,
                "title": title,
                "severity": severity
            })
            state["updated"] = datetime.now().isoformat()
            state_file.write_text(json.dumps(state, indent=2))

        logger.info(f"Saved finding: {finding_id} - {title} ({severity})")

        result = {
            "status": "success",
            "finding_id": finding_id,
            "finding_path": str(finding_path),
            "severity": severity,
            "title": title
        }

        # Add prominent warning for weak/insufficient evidence on HIGH/CRITICAL findings
        # Determine if exploitation is authorized from RoE flags
        exploitation_authorized = True
        if roe_flags:
            allow_exploit = roe_flags.get("ALLOW_EXPLOITATION", "").lower()
            allow_full = roe_flags.get("ALLOW_FULL_EXPLOITATION", "").lower()
            if allow_exploit == "false" and allow_full != "true":
                exploitation_authorized = False

        if (severity.lower() in ("critical", "high") and
                evidence_validation.quality in (EvidenceQuality.WEAK, EvidenceQuality.INSUFFICIENT)):
            if exploitation_authorized:
                result["evidence_warning"] = (
                    f"⚠️  WEAK EVIDENCE on {severity.upper()} finding! "
                    f"Quality: {evidence_validation.quality.value} (score: {evidence_validation.score}/100). "
                    f"This finding has scan-only evidence — you MUST go back and EXPLOIT this vulnerability "
                    f"to collect proof (e.g., run the exploit, capture 'id', 'whoami', 'cat /etc/passwd' output). "
                    f"Then call save_finding again with the exploitation output as evidence."
                )
            else:
                result["evidence_warning"] = (
                    f"⚠️  WEAK EVIDENCE on {severity.upper()} finding! "
                    f"Quality: {evidence_validation.quality.value} (score: {evidence_validation.score}/100). "
                    f"Exploitation is not authorized by RoE — ensure evidence documents the vulnerability "
                    f"with configuration output, version strings, service banners, and detailed tool output."
                )
            if evidence_validation.suggestions:
                result["evidence_suggestions"] = evidence_validation.suggestions[:3]

        return result

    except Exception as e:
        logger.error(f"Error saving finding: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def update_state(
    phase: str = "",
    hosts: list = None,
    services: list = None,
    credentials: list = None
) -> dict:
    """
    Update assessment state with discovered assets.

    Args:
        phase: Current phase
        hosts: Discovered hosts to add
        services: Discovered services to add
        credentials: Discovered credentials to add

    Returns:
        {
            "status": "success",
            "phase": "ENUM",
            "total_hosts": 12,
            "total_services": 45,
            "total_credentials": 3
        }
    """
    global _current_assessment_id

    async with _state_lock:
        if not _current_assessment_id:
            return {
                "status": "error",
                "error": "Assessment not initialized. Call init_assessment first."
            }
        current_id = _current_assessment_id

    try:
        # Get assessment directory
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / current_id
        state_file = assessment_dir / "state.json"

        if not state_file.exists():
            return {
                "status": "error",
                "error": f"State file not found for assessment {current_id}"
            }

        # Load current state
        state = json.loads(state_file.read_text())

        # Update phase if provided
        if phase:
            state["phase"] = phase.upper()

        # Initialize discovered_assets if not present
        if "discovered_assets" not in state:
            state["discovered_assets"] = {
                "hosts": [],
                "services": [],
                "credentials": []
            }

        # Add hosts (avoid duplicates)
        if hosts:
            existing_hosts = set(state["discovered_assets"]["hosts"])
            for host in hosts:
                if host not in existing_hosts:
                    state["discovered_assets"]["hosts"].append(host)
                    existing_hosts.add(host)

        # Add services (avoid duplicates)
        if services:
            existing_services = set(state["discovered_assets"]["services"])
            for service in services:
                if service not in existing_services:
                    state["discovered_assets"]["services"].append(service)
                    existing_services.add(service)

        # Add credentials (avoid duplicates)
        if credentials:
            existing_creds = set(state["discovered_assets"]["credentials"])
            for cred in credentials:
                if cred not in existing_creds:
                    state["discovered_assets"]["credentials"].append(cred)
                    existing_creds.add(cred)

        # Update timestamp
        state["updated"] = datetime.now().isoformat()

        # Save state
        state_file.write_text(json.dumps(state, indent=2))

        logger.info(f"Updated state: phase={state.get('phase')}, "
                   f"hosts={len(state['discovered_assets']['hosts'])}, "
                   f"services={len(state['discovered_assets']['services'])}")

        return {
            "status": "success",
            "assessment_id": current_id,
            "phase": state.get("phase", "UNKNOWN"),
            "total_hosts": len(state["discovered_assets"]["hosts"]),
            "total_services": len(state["discovered_assets"]["services"]),
            "total_credentials": len(state["discovered_assets"]["credentials"]),
            "total_findings": len(state.get("findings", []))
        }

    except Exception as e:
        logger.error(f"Error updating state: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }



async def complete_assessment() -> dict:
    """
    Mark assessment as complete and generate HTML reports.

    Returns:
        {
            "status": "success",
            "assessment_id": "...",
            "phase": "COMPLETE",
            "reports": {
                "comprehensive_html": "/path/to/comprehensive_report.html",
                "executive_html": "/path/to/executive_report.html"
            },
            "risk_assessment": {...},
            "total_findings": 15
        }
    """
    global _current_assessment_id

    try:
        async with _state_lock:
            if not _current_assessment_id:
                return {
                    "status": "error",
                    "error": "No active assessment. Call init_assessment first."
                }
            current_id = _current_assessment_id

        logger.info(f"Completing assessment {current_id}")

        # Get assessment directory
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / current_id

        if not assessment_dir.exists():
            return {
                "status": "error",
                "error": f"Assessment directory not found: {assessment_dir}"
            }

        # Load state
        state_file = assessment_dir / "state.json"
        if not state_file.exists():
            return {
                "status": "error",
                "error": "State file not found"
            }

        state = json.loads(state_file.read_text())

        # Update state to COMPLETE
        state["phase"] = "COMPLETE"
        state["updated"] = datetime.now().isoformat()
        state["completed"] = datetime.now().isoformat()
        state_file.write_text(json.dumps(state, indent=2))

        logger.info("Assessment marked as COMPLETE, generating reports...")

        # Bug fix: Small delay to ensure any pending file writes complete
        # This prevents race conditions where findings are saved just before report generation
        await asyncio.sleep(0.5)

        # Re-read state to get the latest data (in case it was updated during the delay)
        state = json.loads(state_file.read_text())

        # Load findings
        findings_dir = assessment_dir / "findings"
        findings = []
        if findings_dir.exists():
            for f in sorted(findings_dir.glob("finding_*.json")):
                try:
                    findings.append(json.loads(f.read_text()))
                except Exception as e:
                    logger.warning(f"Error loading finding {f}: {e}")

        # Extract hosts and services from state
        # Bug fix: Read from discovered_assets which is the actual location
        discovered_assets = state.get("discovered_assets", {})

        # Helper function to enrich host objects with scan data
        def enrich_host_data(ip: str, services_list: List[str]) -> Dict:
            """Enrich host object with OS, hostname, and ports from scan data and services."""
            host_obj = {"ip": ip}

            # Extract ports from services list (format: "ip:port/service")
            ports = []
            for svc in services_list:
                if ip in svc:
                    try:
                        # Parse "192.168.0.1:22/ssh" -> port 22
                        port_part = svc.split(":")[1].split("/")[0]
                        ports.append(int(port_part))
                    except (IndexError, ValueError):
                        pass

            if ports:
                host_obj["ports"] = sorted(ports)

            # Try to load scan data from scans directory for OS/hostname info
            scans_dir = assessment_dir / "scans"
            if scans_dir.exists():
                # Look for nmap XML files
                for scan_file in scans_dir.glob("*.xml"):
                    try:
                        import xml.etree.ElementTree as ET
                        tree = ET.parse(scan_file)
                        root = tree.getroot()

                        # Find host element matching this IP
                        for host_elem in root.findall(".//host"):
                            addr_elem = host_elem.find(".//address[@addrtype='ipv4']")
                            if addr_elem is not None and addr_elem.get("addr") == ip:
                                # Extract hostname
                                hostname_elem = host_elem.find(".//hostname")
                                if hostname_elem is not None:
                                    host_obj["hostname"] = hostname_elem.get("name")

                                # Extract OS info
                                osmatch_elem = host_elem.find(".//osmatch")
                                if osmatch_elem is not None:
                                    host_obj["os"] = osmatch_elem.get("name")

                                break
                    except Exception as e:
                        logger.debug(f"Could not parse scan file {scan_file}: {e}")

            return host_obj

        hosts = []
        # Try discovered_assets.hosts first, fall back to state.hosts for backwards compatibility
        host_list = discovered_assets.get("hosts", []) or state.get("hosts", [])
        service_list = discovered_assets.get("services", []) or state.get("services", [])

        for host_str in host_list:
            if isinstance(host_str, dict):
                hosts.append(host_str)
            else:
                # Enrich host object with OS, hostname, and ports from scan data
                enriched_host = enrich_host_data(str(host_str), service_list)
                hosts.append(enriched_host)

        services = []
        # Try discovered_assets.services first, fall back to state.services for backwards compatibility
        service_list = discovered_assets.get("services", []) or state.get("services", [])
        for svc_str in service_list:
            if isinstance(svc_str, dict):
                services.append(svc_str)
            else:
                # Parse "host:port/service" format
                services.append({"service": str(svc_str)})

        # Use the new JSON-based report generator
        try:
            report_gen = ReportGenerator(current_id)

            # Generate JSON report (contains all data)
            json_path = report_gen.generate_json_report(
                findings=findings,
                hosts=hosts,
                services=services,
                state=state,
                metadata={
                    "generator": "NTREE Complete Assessment",
                    "generated_at": datetime.now().isoformat()
                }
            )
            logger.info(f"JSON report saved: {json_path}")

            # Generate HTML report from JSON template
            html_path = report_gen.generate_html_report(json_path)
            logger.info(f"HTML report saved: {html_path}")

            reports = {
                "json": str(json_path),
                "html": str(html_path)
            }

            # Load risk assessment from JSON
            with open(json_path) as f:
                report_data = json.load(f)
            risk_result = report_data.get("risk_score", {})

        except Exception as e:
            logger.error(f"Error generating reports with new generator: {e}")
            # Fallback to old report generation
            from .report import score_risk, generate_report as old_generate_report

            risk_result = await score_risk(current_id)
            reports = {}

            comp_result = await old_generate_report(current_id, format="comprehensive", output_format="html")
            if comp_result.get("status") == "success":
                reports["comprehensive_html"] = comp_result["report_path"]

        logger.info(f"Assessment {current_id} completed successfully")

        return {
            "status": "success",
            "assessment_id": current_id,
            "title": state.get("title", current_id),
            "phase": "COMPLETE",
            "reports": reports,
            "risk_assessment": risk_result if risk_result.get("status") == "success" else {},
            "total_findings": len(findings),  # Bug fix: Use actual findings count from disk
            "summary": f"Assessment completed with {len(findings)} findings. Reports generated in {assessment_dir / 'reports'}"
        }

    except Exception as e:
        logger.error(f"Error completing assessment: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


def main():
    """Main entry point for scope server."""
    import sys

    # Handle command-line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("ntree-scope v2.0.0")
            return
        elif sys.argv[1] == "--test":
            print("NTREE Scope Server - Test Mode")
            print("This would run tests...")
            return

    # Run MCP server
    async def run_server():
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
