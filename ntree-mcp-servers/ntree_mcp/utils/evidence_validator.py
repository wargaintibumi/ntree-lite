"""
NTREE Evidence Quality Validator
Validates that finding evidence demonstrates actual exploitation, not just scan results.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .logger import get_logger

logger = get_logger(__name__)


class EvidenceQuality(Enum):
    """Evidence quality levels."""
    EXCELLENT = "excellent"      # Clear proof of exploitation with impact
    GOOD = "good"               # Demonstrates vulnerability exploitation
    ACCEPTABLE = "acceptable"   # Shows vulnerability exists with some validation
    WEAK = "weak"               # Mostly scan output, limited validation
    INSUFFICIENT = "insufficient"  # Pure scan output, no exploitation proof


@dataclass
class ValidationResult:
    """Result of evidence validation."""
    quality: EvidenceQuality
    score: int  # 0-100
    issues: List[str]
    suggestions: List[str]
    exploitation_indicators: List[str]
    scan_indicators: List[str]


# Patterns indicating actual exploitation
EXPLOITATION_PATTERNS = [
    # Authentication/Access
    (r"successfully\s+(authenticated|logged\s+in|connected|exploited)", "Successful authentication/exploitation"),
    (r"access\s+granted", "Access granted"),
    (r"login\s+successful", "Login successful"),
    (r"session\s+(established|opened|created)", "Session established"),

    # Shell/Command execution
    (r"shell\s+(obtained|spawned|opened)", "Shell obtained"),
    (r"command\s+executed", "Command executed"),
    (r"\$\s+whoami.*\n.*\w+", "Command output captured"),
    (r"uid=\d+", "User ID information extracted"),
    (r"root@|admin@|administrator@", "Privileged access obtained"),
    (r"/etc/passwd|/etc/shadow", "Linux sensitive file access"),

    # Data extraction
    (r"extracted?\s+(data|credentials|secrets|hashes)", "Data extracted"),
    (r"dumped?\s+(hashes|passwords|database)", "Credentials dumped"),
    (r"password[:\s]+[^\s]{4,}", "Password retrieved"),
    (r"hash[:\s]+[a-fA-F0-9]{16,}", "Hash retrieved"),

    # File operations
    (r"file\s+(read|written|created|uploaded|downloaded)", "File operation successful"),
    (r"contents?\s+of\s+", "File contents retrieved"),
    (r"directory\s+listing", "Directory listing obtained"),

    # Specific vulnerability exploitation
    (r"SQL\s+injection\s+successful", "SQL injection exploited"),
    (r"XSS\s+(payload\s+)?executed", "XSS exploited"),
    (r"(RCE|rce)\s+(achieved|successful|obtained|confirmed)|obtained\s+RCE", "RCE achieved"),
    (r"privilege\s+escalat(ed|ion)", "Privilege escalation"),

    # Service connection proof
    (r"(anonymous|null)\s+(login|session|access)\s+successful", "Anonymous access confirmed"),
    (r"230[\s-]+Login\s+successful", "FTP login success"),

    # Credential confirmation
    (r"(default|factory)\s+(credentials?|password)\s*(work|confirmed|valid)", "Default credentials confirmed"),
    (r"admin(istrator)?\s+(panel|interface|console)\s*(access|accessible)", "Admin panel access"),
]

# Patterns indicating scan-only output (not exploitation)
SCAN_ONLY_PATTERNS = [
    (r"^Nmap\s+scan\s+report", "Nmap scan header"),
    (r"^Starting\s+Nmap", "Nmap start message"),
    (r"^\d+/tcp\s+(open|closed|filtered)", "Port scan result"),
    (r"^PORT\s+STATE\s+SERVICE", "Nmap port header"),
    (r"^Host\s+is\s+up", "Host discovery result"),
    (r"^MAC\s+Address:", "MAC address from scan"),
    (r"^Service\s+Info:", "Service info from scan"),
    (r"^OS\s+details:", "OS detection from scan"),
    (r"nuclei\s+-", "Nuclei command"),
    (r"\[INF\].*nuclei", "Nuclei output"),
    (r"nikto.*scan", "Nikto scan"),
    (r"gobuster.*dir", "Gobuster scan"),
    (r"dirb\s+http", "Dirb scan"),
    (r"wpscan\s+", "WPScan command"),
    (r"^\[\+\]\s+Scanning", "Generic scan progress"),
    (r"^\[\*\]\s+Checking", "Generic check message"),
    (r"^Discovered\s+open\s+port", "Port discovery"),
    (r"^Scanning\s+\d+\.\d+\.\d+\.\d+", "IP scanning"),
    (r"^version:\s*[\d.]+$", "Version detection only (standalone line)"),
    (r"banner:\s*", "Banner grab only"),
]

# Patterns that suggest but don't prove exploitation
SUGGESTIVE_PATTERNS = [
    (r"vulnerable\s+to", "Vulnerability identified"),
    (r"CVE-\d{4}-\d+", "CVE reference"),
    (r"exploit\s+available", "Exploit availability noted"),
    (r"default\s+(credentials?|password)", "Default credentials noted"),
    (r"misconfigur(ed|ation)", "Misconfiguration identified"),
    (r"weak\s+(password|cipher|encryption)", "Weakness identified"),
    (r"missing\s+(patch|update)", "Missing patch noted"),
    (r"outdated\s+version", "Outdated version noted"),
]


def validate_evidence(
    evidence: str,
    finding_type: str = "",
    severity: str = "",
    require_exploitation: bool = False,
    roe_flags: Optional[Dict[str, str]] = None
) -> ValidationResult:
    """
    Validate evidence quality for a security finding.

    Args:
        evidence: The evidence text to validate
        finding_type: Type of finding (e.g., "rce", "sqli", "info_disclosure")
        severity: Severity level (critical, high, medium, low, info)
        require_exploitation: If True, require proof of exploitation for high/critical
        roe_flags: Optional RoE flags dict; keys like ALLOW_EXPLOITATION, ALLOW_FULL_EXPLOITATION

    Returns:
        ValidationResult with quality assessment and suggestions
    """
    if not evidence or not evidence.strip():
        return ValidationResult(
            quality=EvidenceQuality.INSUFFICIENT,
            score=0,
            issues=["Evidence is empty"],
            suggestions=["Provide evidence of the vulnerability or exploitation"],
            exploitation_indicators=[],
            scan_indicators=[]
        )

    evidence_lower = evidence.lower()
    issues = []
    suggestions = []
    exploitation_found = []
    scan_found = []
    suggestive_found = []

    # Check for exploitation indicators
    for pattern, description in EXPLOITATION_PATTERNS:
        if re.search(pattern, evidence, re.IGNORECASE | re.MULTILINE):
            exploitation_found.append(description)

    # Check for scan-only indicators
    for pattern, description in SCAN_ONLY_PATTERNS:
        if re.search(pattern, evidence, re.IGNORECASE | re.MULTILINE):
            scan_found.append(description)

    # Check for suggestive patterns
    for pattern, description in SUGGESTIVE_PATTERNS:
        if re.search(pattern, evidence, re.IGNORECASE | re.MULTILINE):
            suggestive_found.append(description)

    # Determine if exploitation is authorized based on RoE flags
    exploitation_authorized = True  # default: assume exploitation is allowed
    if roe_flags:
        allow_exploit = roe_flags.get("ALLOW_EXPLOITATION", "").lower()
        allow_full = roe_flags.get("ALLOW_FULL_EXPLOITATION", "").lower()
        if allow_exploit == "false" and allow_full != "true":
            exploitation_authorized = False

    # Calculate score
    score = 0

    # Base score from exploitation indicators (improved: 25 pts each, max 75)
    if exploitation_found:
        score += min(len(exploitation_found) * 25, 75)

    # Suggestive patterns add some value
    if suggestive_found:
        score += min(len(suggestive_found) * 10, 30)

    # Penalty for scan-only output without exploitation
    if scan_found and not exploitation_found:
        score -= min(len(scan_found) * 5, 30)

    # Bonus for detailed evidence (length)
    if len(evidence) > 500:
        score += 10
    if len(evidence) > 1000:
        score += 10

    # Ensure score is in valid range
    score = max(0, min(100, score))

    # Determine quality level — two branches based on RoE context
    if exploitation_authorized:
        # Standard thresholds (exploitation expected)
        if score >= 70 and exploitation_found:
            quality = EvidenceQuality.EXCELLENT
        elif score >= 45 and exploitation_found:
            quality = EvidenceQuality.GOOD
        elif score >= 25 or (suggestive_found and len(suggestive_found) >= 2):
            quality = EvidenceQuality.ACCEPTABLE
        elif score >= 10 or suggestive_found:
            quality = EvidenceQuality.WEAK
        else:
            quality = EvidenceQuality.INSUFFICIENT
    else:
        # Relaxed thresholds (exploitation forbidden — documentation-only)
        if score >= 60:
            quality = EvidenceQuality.EXCELLENT
        elif score >= 35:
            quality = EvidenceQuality.GOOD
        elif score >= 15 or (suggestive_found and len(suggestive_found) >= 2):
            quality = EvidenceQuality.ACCEPTABLE
        elif score >= 5 or suggestive_found:
            quality = EvidenceQuality.WEAK
        else:
            quality = EvidenceQuality.INSUFFICIENT

    # Generate issues and suggestions
    if not exploitation_found:
        if exploitation_authorized:
            issues.append("No proof of exploitation found")
            # Provide specific examples based on finding type
            if finding_type in ("rce", "command_injection"):
                suggestions.append("For RCE: Show actual command execution (e.g., 'id', 'whoami' output)")
            elif finding_type in ("sqli", "sql_injection"):
                suggestions.append("For SQLi: Include actual database query results or error messages")
            elif finding_type in ("auth_bypass", "default_credentials"):
                suggestions.append("For auth bypass: Show authenticated session or access to restricted resources")
            elif finding_type in ("file_inclusion", "path_traversal", "lfi", "rfi"):
                suggestions.append("For file inclusion: Include contents of successfully read files")
            elif finding_type in ("xss", "csrf"):
                suggestions.append("For XSS/CSRF: Include proof of script execution or forged request")
            else:
                suggestions.append("Include output showing successful exploitation")
                suggestions.append("Add command output demonstrating access or data extraction")
        else:
            # Exploitation NOT authorized — documentation guidance
            issues.append("No exploitation proof (exploitation not authorized by RoE)")
            suggestions.append("Document the vulnerability with full tool output, version strings, and configuration details")

    if scan_found and not exploitation_found:
        issues.append("Evidence appears to be scan results only")
        if exploitation_authorized:
            suggestions.append("Scan results show vulnerability exists, but add exploitation proof")
            suggestions.append("Note: Detection-only findings are valid for initial assessment, but should be validated")
        else:
            suggestions.append("Include service banners, version strings, and configuration output to strengthen evidence")

    if severity in ("critical", "high") and quality in (EvidenceQuality.WEAK, EvidenceQuality.INSUFFICIENT):
        issues.append(f"{severity.upper()} severity finding should have stronger evidence")
        if exploitation_authorized:
            suggestions.append(f"For {severity} findings, demonstrate actual impact")
        else:
            suggestions.append(f"For {severity} findings, include detailed configuration output and version information")

    if require_exploitation and severity in ("critical", "high") and not exploitation_found:
        if exploitation_authorized:
            issues.append("Exploitation proof required for high/critical findings")
            suggestions.append("Actually exploit the vulnerability and capture output")
        else:
            issues.append("Exploitation not authorized — ensure thorough documentation")
            suggestions.append("Include version strings, service banners, and configuration details as evidence")

    # Specific suggestions based on finding type
    type_suggestions = _get_type_specific_suggestions(finding_type, exploitation_found)
    suggestions.extend(type_suggestions)

    return ValidationResult(
        quality=quality,
        score=score,
        issues=issues,
        suggestions=suggestions[:5],  # Limit suggestions
        exploitation_indicators=exploitation_found,
        scan_indicators=scan_found
    )


def _get_type_specific_suggestions(finding_type: str, exploitation_found: List[str]) -> List[str]:
    """Get suggestions specific to the finding type."""
    suggestions = []
    finding_type = finding_type.lower()

    if "sql" in finding_type and "SQL injection" not in str(exploitation_found):
        suggestions.append("For SQLi: Show extracted data or UNION-based output")
        suggestions.append("Include sqlmap output showing database/table extraction")

    elif "xss" in finding_type and "XSS" not in str(exploitation_found):
        suggestions.append("For XSS: Show alert box screenshot or cookie theft")
        suggestions.append("Include DOM showing injected payload execution")

    elif "rce" in finding_type or "command" in finding_type:
        if "Command executed" not in str(exploitation_found):
            suggestions.append("For RCE: Show command output (whoami, id, hostname)")
            suggestions.append("Include reverse shell session or command injection output")

    elif "auth" in finding_type or "credential" in finding_type:
        if "authentication" not in str(exploitation_found).lower():
            suggestions.append("For auth bypass: Show authenticated session or access")
            suggestions.append("Include successful login response or session token")

    elif "ssh" in finding_type or "smb" in finding_type:
        suggestions.append("Show successful connection or authentication")
        suggestions.append("Include session output or file access proof")

    return suggestions


def enrich_finding_with_validation(finding: Dict, roe_flags: Optional[Dict[str, str]] = None) -> Dict:
    """
    Enrich a finding dictionary with evidence validation results.

    Args:
        finding: Finding dictionary with 'evidence' key
        roe_flags: Optional RoE flags dict for context-aware validation

    Returns:
        Finding with added 'evidence_validation' key
    """
    evidence = finding.get("evidence", "")
    severity = finding.get("severity", "medium")
    finding_type = finding.get("type", finding.get("title", ""))

    validation = validate_evidence(
        evidence=evidence,
        finding_type=finding_type,
        severity=severity,
        require_exploitation=severity in ("critical", "high"),
        roe_flags=roe_flags
    )

    finding["evidence_validation"] = {
        "quality": validation.quality.value,
        "score": validation.score,
        "issues": validation.issues,
        "suggestions": validation.suggestions,
        "has_exploitation_proof": len(validation.exploitation_indicators) > 0
    }

    # Add warning flag for weak evidence on high/critical findings
    if severity in ("critical", "high") and validation.quality in (
        EvidenceQuality.WEAK, EvidenceQuality.INSUFFICIENT
    ):
        finding["evidence_warning"] = True
        finding["evidence_warning_message"] = (
            f"Evidence quality is {validation.quality.value} for {severity} finding. "
            f"Consider adding exploitation proof."
        )

    return finding


def get_evidence_quality_summary(findings: List[Dict], roe_flags: Optional[Dict[str, str]] = None) -> Dict:
    """
    Get summary of evidence quality across all findings.

    Args:
        findings: List of finding dictionaries
        roe_flags: Optional RoE flags dict for context-aware validation

    Returns:
        Summary statistics
    """
    quality_counts = {q.value: 0 for q in EvidenceQuality}
    total_score = 0
    warnings = []

    for finding in findings:
        evidence = finding.get("evidence", "")
        severity = finding.get("severity", "medium")
        validation = validate_evidence(evidence, severity=severity, roe_flags=roe_flags)

        quality_counts[validation.quality.value] += 1
        total_score += validation.score

        if validation.quality in (EvidenceQuality.WEAK, EvidenceQuality.INSUFFICIENT):
            if severity in ("critical", "high"):
                warnings.append({
                    "title": finding.get("title", "Unknown"),
                    "severity": severity,
                    "quality": validation.quality.value,
                    "issues": validation.issues
                })

    return {
        "total_findings": len(findings),
        "quality_distribution": quality_counts,
        "average_score": total_score / len(findings) if findings else 0,
        "warnings": warnings,
        "excellent_count": quality_counts["excellent"],
        "needs_improvement": quality_counts["weak"] + quality_counts["insufficient"]
    }
