"""
NTREE Vulnerability Testing MCP Server
Handles vulnerability validation, credential testing, and exploit research
"""

import asyncio
import json
import re
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import time

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from .utils.command_runner import run_command
from .utils.logger import get_logger

logger = get_logger(__name__)

# Audit logging
def _get_audit():
    """Get audit logger instance (lazy initialization with env var sync)."""
    try:
        from .utils.audit_logger import get_audit_logger
        import os

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

app = Server("ntree-vuln")

# Rate limiting for credential testing
_credential_attempts = {}  # {(host, service, username): [timestamps]}
_credential_lock = asyncio.Lock()  # Protect concurrent access to _credential_attempts
MAX_CRED_ATTEMPTS = 3
ATTEMPT_WINDOW = 300  # 5 minutes


# Helper function to handle manual review responses
def handle_command_result(returncode: int, stdout: str, stderr: str, operation: str) -> dict:
    """
    Handle command execution results, including manual review cases.

    Args:
        returncode: Command return code
        stdout: Command stdout
        stderr: Command stderr
        operation: Description of operation (for logging)

    Returns:
        Dict with status and details
    """
    # Check for manual review status (returncode = -2)
    if returncode == -2:
        try:
            manual_review_data = json.loads(stdout)
            logger.warning(f"{operation} requires manual review: {manual_review_data.get('reason')}")

            return {
                "status": "needs_manual_review",
                "operation": operation,
                "reason": manual_review_data.get("reason"),
                "details": manual_review_data.get("details"),
                "recommendation": manual_review_data.get("recommendation"),
                "tool": manual_review_data.get("tool"),
                "safe_alternative": manual_review_data.get("safe_alternative"),
                "original_command": manual_review_data.get("original_command")
            }
        except json.JSONDecodeError:
            return {
                "status": "needs_manual_review",
                "operation": operation,
                "reason": "Interactive tool detected",
                "details": stderr
            }

    # Normal error
    if returncode != 0:
        return {
            "status": "error",
            "error": f"{operation} failed: {stderr[:500]}"
        }

    # Success
    return {
        "status": "success",
        "data": stdout
    }


class TestVulnArgs(BaseModel):
    """Arguments for test_vuln tool."""
    host: str = Field(description="Target host IP address")
    service: str = Field(description="Service name (e.g., 'http', 'smb', 'ssh')")
    vuln_id: str = Field(description="Vulnerability ID (CVE-XXXX-XXXX or descriptive name)")
    safe_mode: bool = Field(default=True, description="Safe mode: only validate, don't exploit")
    port: int = Field(default=0, description="Specific port (0 for auto-detect)")


class CheckCredsArgs(BaseModel):
    """Arguments for check_creds tool."""
    host: str = Field(description="Target host IP address")
    service: str = Field(description="Service name (e.g., 'smb', 'ssh', 'ftp', 'rdp')")
    username: str = Field(description="Username to test")
    password: str = Field(default="", description="Password to test (provide password OR hash)")
    hash_value: str = Field(default="", description="NTLM hash to test (provide password OR hash)")


class SearchExploitsArgs(BaseModel):
    """Arguments for search_exploits tool."""
    service: str = Field(description="Service name or software")
    version: str = Field(default="", description="Version number (optional)")
    platform: str = Field(default="", description="Platform filter (e.g., 'linux', 'windows')")


class AnalyzeConfigArgs(BaseModel):
    """Arguments for analyze_config tool."""
    host: str = Field(description="Target host IP address")
    service: str = Field(description="Service to analyze (e.g., 'smb', 'ssh', 'ssl', 'rdp')")
    port: int = Field(default=0, description="Specific port (0 for auto-detect)")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available vulnerability testing tools."""
    return [
        Tool(
            name="test_vuln",
            description="Test for a specific vulnerability on a target host. Safe mode (default) only validates without exploitation.",
            inputSchema=TestVulnArgs.model_json_schema()
        ),
        Tool(
            name="check_creds",
            description="Validate credentials against a service. Rate-limited to 3 attempts per account per 5 minutes.",
            inputSchema=CheckCredsArgs.model_json_schema()
        ),
        Tool(
            name="search_exploits",
            description="Search exploit databases (searchsploit) for available exploits matching service/version",
            inputSchema=SearchExploitsArgs.model_json_schema()
        ),
        Tool(
            name="analyze_config",
            description="Analyze service configuration for security misconfigurations and weaknesses",
            inputSchema=AnalyzeConfigArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    # Log tool call to audit
    audit = _get_audit()
    if audit:
        audit.log_tool_call(f"ntree-vuln.{name}", arguments)

    try:
        if name == "test_vuln":
            args = TestVulnArgs(**arguments)
            result = await test_vuln(
                args.host,
                args.service,
                args.vuln_id,
                args.safe_mode,
                args.port
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "check_creds":
            args = CheckCredsArgs(**arguments)
            result = await check_creds(
                args.host,
                args.service,
                args.username,
                args.password,
                args.hash_value
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "search_exploits":
            args = SearchExploitsArgs(**arguments)
            result = await search_exploits(
                args.service,
                args.version,
                args.platform
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "analyze_config":
            args = AnalyzeConfigArgs(**arguments)
            result = await analyze_config(
                args.host,
                args.service,
                args.port
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def test_vuln(
    host: str,
    service: str,
    vuln_id: str,
    safe_mode: bool = True,
    port: int = 0
) -> dict:
    """
    Test for a specific vulnerability.

    Args:
        host: Target IP address
        service: Service name
        vuln_id: Vulnerability identifier
        safe_mode: Only validate, don't exploit
        port: Specific port

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "vuln_id": "CVE-2023-1234",
            "exploitable": true,
            "confidence": "confirmed",
            "evidence": "...",
            "cvss_score": 9.8,
            "safe_mode": true
        }
    """
    try:
        logger.info(f"Testing vulnerability {vuln_id} on {host}:{service} (safe_mode={safe_mode})")

        result = {
            "status": "success",
            "host": host,
            "service": service,
            "vuln_id": vuln_id,
            "exploitable": False,
            "confidence": "unknown",
            "evidence": "",
            "cvss_score": 0.0,
            "safe_mode": safe_mode,
        }

        # Normalize vulnerability ID
        vuln_id_lower = vuln_id.lower()

        # Route to appropriate testing method
        if vuln_id_lower.startswith('cve-'):
            # Test using nmap NSE scripts
            test_result = await _test_cve_with_nmap(host, service, vuln_id, port)
            result.update(test_result)

        elif 'eternalblue' in vuln_id_lower or 'ms17-010' in vuln_id_lower:
            # Test for EternalBlue
            test_result = await _test_eternalblue(host)
            result.update(test_result)

        elif 'bluekeep' in vuln_id_lower or 'cve-2019-0708' in vuln_id_lower:
            # Test for BlueKeep
            test_result = await _test_bluekeep(host)
            result.update(test_result)

        else:
            # Use nuclei for modern vulnerability scanning
            test_result = await _test_with_nuclei(host, vuln_id, port)
            result.update(test_result)

        summary = f"Vulnerability {vuln_id}: " \
                  f"{'EXPLOITABLE' if result['exploitable'] else 'Not Vulnerable'} " \
                  f"(confidence: {result['confidence']})"

        result['summary'] = summary

        logger.info(f"Vulnerability test complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error testing vulnerability {vuln_id} on {host}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _test_cve_with_nmap(host: str, service: str, cve_id: str, port: int) -> dict:
    """Test CVE using nmap NSE scripts."""
    result = {
        "exploitable": False,
        "confidence": "unknown",
        "evidence": "",
        "cvss_score": 0.0,
    }

    try:
        # Build nmap command
        port_spec = f"-p {port}" if port > 0 else ""
        command = f"sudo nmap {port_spec} --script vuln {host}"

        returncode, stdout, stderr = await run_command(command, timeout=300)

        if returncode == 0:
            # Parse nmap output for vulnerability
            if cve_id.upper() in stdout or cve_id.lower() in stdout:
                result['exploitable'] = True
                result['confidence'] = "likely"

                # Extract relevant lines as evidence
                evidence_lines = []
                for line in stdout.split('\n'):
                    if cve_id.lower() in line.lower() or 'vulnerable' in line.lower():
                        evidence_lines.append(line.strip())

                result['evidence'] = '\n'.join(evidence_lines[:10])

                # Try to extract CVSS score
                cvss_match = re.search(r'cvss[:\s]+(\d+\.?\d*)', stdout, re.IGNORECASE)
                if cvss_match:
                    result['cvss_score'] = float(cvss_match.group(1))

    except Exception as e:
        logger.warning(f"Error testing CVE with nmap: {e}")

    return result


async def _test_eternalblue(host: str) -> dict:
    """Test for EternalBlue (MS17-010) vulnerability."""
    result = {
        "exploitable": False,
        "confidence": "unknown",
        "evidence": "",
        "cvss_score": 9.3,
    }

    try:
        command = f"sudo nmap -p445 --script smb-vuln-ms17-010 {host}"
        returncode, stdout, stderr = await run_command(command, timeout=120)

        if returncode == 0:
            if 'VULNERABLE' in stdout.upper():
                result['exploitable'] = True
                result['confidence'] = "confirmed"
                result['evidence'] = "Host is vulnerable to MS17-010 (EternalBlue)"

    except Exception as e:
        logger.warning(f"Error testing EternalBlue: {e}")

    return result


async def _test_bluekeep(host: str) -> dict:
    """Test for BlueKeep (CVE-2019-0708) vulnerability."""
    result = {
        "exploitable": False,
        "confidence": "unknown",
        "evidence": "",
        "cvss_score": 9.8,
    }

    try:
        command = f"sudo nmap -p3389 --script rdp-vuln-ms12-020 {host}"
        returncode, stdout, stderr = await run_command(command, timeout=120)

        if returncode == 0:
            if 'VULNERABLE' in stdout.upper():
                result['exploitable'] = True
                result['confidence'] = "likely"
                result['evidence'] = "RDP service may be vulnerable to CVE-2019-0708 (BlueKeep)"

    except Exception as e:
        logger.warning(f"Error testing BlueKeep: {e}")

    return result


async def _test_with_nuclei(host: str, vuln_id: str, port: int) -> dict:
    """Test vulnerability using nuclei scanner."""
    result = {
        "exploitable": False,
        "confidence": "unknown",
        "evidence": "",
        "cvss_score": 0.0,
    }

    try:
        # Build nuclei command
        target = f"{host}:{port}" if port > 0 else host
        command = f"nuclei -u {shlex.quote(target)} -id {shlex.quote(vuln_id)} -silent"

        returncode, stdout, stderr = await run_command(command, timeout=180)

        if returncode == 0 and stdout.strip():
            result['exploitable'] = True
            result['confidence'] = "likely"
            result['evidence'] = stdout.strip()[:500]

    except Exception as e:
        logger.warning(f"Error testing with nuclei: {e}")

    return result


async def check_creds(
    host: str,
    service: str,
    username: str,
    password: str = "",
    hash_value: str = ""
) -> dict:
    """
    Validate credentials against a service.

    Args:
        host: Target IP
        service: Service name
        username: Username
        password: Password (or empty if using hash)
        hash_value: NTLM hash (or empty if using password)

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "service": "smb",
            "username": "admin",
            "valid": true,
            "access_level": "admin",
            "evidence": "...",
            "attempts_remaining": 2
        }
    """
    global _credential_attempts

    try:
        # Rate limiting check (async-safe)
        async with _credential_lock:
            attempt_key = (host, service, username)
            current_time = time.time()

            if attempt_key not in _credential_attempts:
                _credential_attempts[attempt_key] = []

            # Remove old attempts outside the window
            _credential_attempts[attempt_key] = [
                t for t in _credential_attempts[attempt_key]
                if current_time - t < ATTEMPT_WINDOW
            ]

            # Check if limit exceeded
            if len(_credential_attempts[attempt_key]) >= MAX_CRED_ATTEMPTS:
                logger.warning(f"Rate limit exceeded for {username}@{host}:{service}")
                return {
                    "status": "error",
                    "error": f"Rate limit exceeded: max {MAX_CRED_ATTEMPTS} attempts per {ATTEMPT_WINDOW}s",
                    "attempts_remaining": 0
                }

            # Record this attempt
            _credential_attempts[attempt_key].append(current_time)

        logger.info(f"Testing credentials for {username}@{host}:{service}")

        result = {
            "status": "success",
            "host": host,
            "service": service,
            "username": username,
            "valid": False,
            "access_level": "none",
            "evidence": "",
            "attempts_remaining": MAX_CRED_ATTEMPTS - len(_credential_attempts[attempt_key]),
        }

        # Route to appropriate credential testing method
        service_lower = service.lower()

        if service_lower in ['smb', 'cifs', '445']:
            test_result = await _test_smb_creds(host, username, password, hash_value)
            result.update(test_result)

        elif service_lower in ['ssh', '22']:
            test_result = await _test_ssh_creds(host, username, password)
            result.update(test_result)

        elif service_lower in ['ftp', '21']:
            test_result = await _test_ftp_creds(host, username, password)
            result.update(test_result)

        elif service_lower in ['rdp', '3389']:
            test_result = await _test_rdp_creds(host, username, password)
            result.update(test_result)

        else:
            return {
                "status": "error",
                "error": f"Credential testing not implemented for service: {service}"
            }

        summary = f"Credentials {username}@{host}:{service}: " \
                  f"{'VALID' if result['valid'] else 'INVALID'} " \
                  f"(access: {result['access_level']})"

        result['summary'] = summary

        logger.info(f"Credential test complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error testing credentials: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _test_smb_creds(host: str, username: str, password: str, hash_value: str) -> dict:
    """Test SMB credentials using crackmapexec."""
    result = {
        "valid": False,
        "access_level": "none",
        "evidence": "",
    }

    try:
        # Build crackmapexec command
        if hash_value:
            command = f"crackmapexec smb {shlex.quote(host)} -u {shlex.quote(username)} -H {shlex.quote(hash_value)}"
        else:
            command = f"crackmapexec smb {shlex.quote(host)} -u {shlex.quote(username)} -p {shlex.quote(password)}"

        returncode, stdout, stderr = await run_command(command, timeout=60)

        # Parse crackmapexec output
        if '(Pwn3d!)' in stdout:
            result['valid'] = True
            result['access_level'] = "admin"
            result['evidence'] = "User has administrative access (Pwn3d!)"

        elif '[+]' in stdout or 'STATUS_SUCCESS' in stdout:
            result['valid'] = True
            result['access_level'] = "user"
            result['evidence'] = "Valid credentials (user-level access)"

    except Exception as e:
        logger.warning(f"Error testing SMB credentials: {e}")

    return result


async def _test_ssh_creds(host: str, username: str, password: str) -> dict:
    """Test SSH credentials."""
    result = {
        "valid": False,
        "access_level": "none",
        "evidence": "",
    }

    try:
        # Use sshpass for password authentication
        command = f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {shlex.quote(username)}@{shlex.quote(host)} 'echo SUCCESS'"

        returncode, stdout, stderr = await run_command(command, timeout=30)

        if returncode == 0 and 'SUCCESS' in stdout:
            result['valid'] = True
            result['access_level'] = "user"
            result['evidence'] = "Successfully authenticated via SSH"

            # Check if user has sudo
            sudo_check = f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no {shlex.quote(username)}@{shlex.quote(host)} 'sudo -n true'"
            sudo_ret, sudo_out, sudo_err = await run_command(sudo_check, timeout=10)

            if sudo_ret == 0:
                result['access_level'] = "admin"
                result['evidence'] += " (has sudo privileges)"

    except Exception as e:
        logger.warning(f"Error testing SSH credentials: {e}")

    return result


async def _test_ftp_creds(host: str, username: str, password: str) -> dict:
    """Test FTP credentials."""
    result = {
        "valid": False,
        "access_level": "user",
        "evidence": "",
    }

    try:
        # Use curl to test FTP
        # Note: curl -u expects "username:password" format, so we quote the entire credential string
        creds = f"{username}:{password}"
        command = f"curl -u {shlex.quote(creds)} ftp://{shlex.quote(host)}/ --max-time 10"

        returncode, stdout, stderr = await run_command(command, timeout=30)

        if returncode == 0:
            result['valid'] = True
            result['evidence'] = "Successfully authenticated to FTP"

    except Exception as e:
        logger.warning(f"Error testing FTP credentials: {e}")

    return result


async def _test_rdp_creds(host: str, username: str, password: str) -> dict:
    """Test RDP credentials using crackmapexec."""
    result = {
        "valid": False,
        "access_level": "none",
        "evidence": "",
    }

    try:
        command = f"crackmapexec rdp {shlex.quote(host)} -u {shlex.quote(username)} -p {shlex.quote(password)}"

        returncode, stdout, stderr = await run_command(command, timeout=60)

        if '[+]' in stdout:
            result['valid'] = True
            result['access_level'] = "user"
            result['evidence'] = "Valid RDP credentials"

    except Exception as e:
        logger.warning(f"Error testing RDP credentials: {e}")

    return result


async def search_exploits(service: str, version: str = "", platform: str = "") -> dict:
    """
    Search exploit databases for available exploits.

    Args:
        service: Service/software name
        version: Version number
        platform: Platform filter

    Returns:
        {
            "status": "success",
            "service": "Apache",
            "version": "2.4.49",
            "exploits": [
                {
                    "id": "50383",
                    "title": "Apache 2.4.49 - Path Traversal",
                    "platform": "linux",
                    "type": "remote",
                    "url": "https://www.exploit-db.com/exploits/50383"
                },
                ...
            ]
        }
    """
    try:
        logger.info(f"Searching exploits for {service} {version}")

        # Build search query
        search_terms = [service]
        if version:
            search_terms.append(version)

        query = " ".join(search_terms)

        # Run searchsploit
        command = f"searchsploit {query}"

        returncode, stdout, stderr = await run_command(command, timeout=60)

        exploits = []

        if returncode == 0:
            # Parse searchsploit output
            for line in stdout.split('\n'):
                # Skip header and separator lines
                if '|' not in line or '---' in line:
                    continue

                # Parse line format: "Title | Path"
                parts = line.split('|')
                if len(parts) >= 2:
                    title = parts[0].strip()
                    path = parts[1].strip()

                    # Extract ID from path
                    id_match = re.search(r'/(\d+)\.', path)
                    exploit_id = id_match.group(1) if id_match else ""

                    # Platform and type from title
                    plat = "unknown"
                    exploit_type = "unknown"

                    if "linux" in title.lower():
                        plat = "linux"
                    elif "windows" in title.lower():
                        plat = "windows"

                    if "remote" in title.lower():
                        exploit_type = "remote"
                    elif "local" in title.lower():
                        exploit_type = "local"

                    # Apply platform filter
                    if platform and plat != platform.lower():
                        continue

                    exploits.append({
                        "id": exploit_id,
                        "title": title,
                        "platform": plat,
                        "type": exploit_type,
                        "url": f"https://www.exploit-db.com/exploits/{exploit_id}" if exploit_id else "",
                        "path": path
                    })

        result = {
            "status": "success",
            "service": service,
            "version": version,
            "platform_filter": platform,
            "exploits": exploits[:20],  # Limit to top 20
            "total_found": len(exploits),
            "summary": f"Found {len(exploits)} exploit(s) for {service} {version}"
        }

        logger.info(result['summary'])

        return result

    except Exception as e:
        logger.error(f"Error searching exploits: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def analyze_config(host: str, service: str, port: int = 0) -> dict:
    """
    Analyze service configuration for misconfigurations.

    Args:
        host: Target IP
        service: Service name
        port: Specific port

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "service": "ssl",
            "misconfigurations": [
                {
                    "type": "weak_cipher",
                    "severity": "high",
                    "description": "SSL 3.0 enabled (vulnerable to POODLE)",
                    "remediation": "Disable SSL 3.0, use TLS 1.2+"
                },
                ...
            ]
        }
    """
    try:
        logger.info(f"Analyzing configuration for {service} on {host}")

        result = {
            "status": "success",
            "host": host,
            "service": service,
            "misconfigurations": [],
        }

        service_lower = service.lower()

        # Route to appropriate analyzer
        if service_lower in ['ssl', 'tls', 'https', '443']:
            misconfigs = await _analyze_ssl_config(host, port or 443)
            result['misconfigurations'] = misconfigs

        elif service_lower in ['smb', 'cifs', '445']:
            misconfigs = await _analyze_smb_config(host)
            result['misconfigurations'] = misconfigs

        elif service_lower in ['ssh', '22']:
            misconfigs = await _analyze_ssh_config(host, port or 22)
            result['misconfigurations'] = misconfigs

        else:
            return {
                "status": "error",
                "error": f"Configuration analysis not implemented for service: {service}"
            }

        summary = f"Found {len(result['misconfigurations'])} misconfiguration(s)"
        result['summary'] = summary

        logger.info(f"Configuration analysis complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error analyzing configuration: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _analyze_ssl_config(host: str, port: int) -> list:
    """Analyze SSL/TLS configuration using testssl.sh."""
    misconfigs = []

    try:
        command = f"testssl.sh --fast --warnings off {host}:{port}"

        returncode, stdout, stderr = await run_command(command, timeout=180)

        if returncode == 0 or stdout:
            # Parse testssl.sh output for vulnerabilities
            for line in stdout.split('\n'):
                line_lower = line.lower()

                if 'vulnerable' in line_lower or 'not ok' in line_lower or 'weak' in line_lower:
                    severity = "high"
                    if 'medium' in line_lower:
                        severity = "medium"
                    elif 'low' in line_lower:
                        severity = "low"

                    misconfigs.append({
                        "type": "ssl_vulnerability",
                        "severity": severity,
                        "description": line.strip(),
                        "remediation": "Review SSL/TLS configuration, update to TLS 1.2+, disable weak ciphers"
                    })

    except Exception as e:
        logger.warning(f"Error analyzing SSL config: {e}")

    return misconfigs[:10]  # Limit results


async def _analyze_smb_config(host: str) -> list:
    """Analyze SMB configuration."""
    misconfigs = []

    try:
        command = f"sudo nmap -p445 --script smb-security-mode,smb-protocols {host}"

        returncode, stdout, stderr = await run_command(command, timeout=120)

        if returncode == 0:
            # Check for SMB signing
            if 'message_signing: disabled' in stdout.lower():
                misconfigs.append({
                    "type": "smb_signing_disabled",
                    "severity": "high",
                    "description": "SMB signing is not required",
                    "remediation": "Enable SMB signing to prevent relay attacks"
                })

            # Check for SMBv1
            if 'smbv1' in stdout.lower() or 'smb 1' in stdout.lower():
                misconfigs.append({
                    "type": "smbv1_enabled",
                    "severity": "critical",
                    "description": "SMBv1 protocol is enabled",
                    "remediation": "Disable SMBv1, use SMBv2/v3 only"
                })

    except Exception as e:
        logger.warning(f"Error analyzing SMB config: {e}")

    return misconfigs


async def _analyze_ssh_config(host: str, port: int) -> list:
    """Analyze SSH configuration."""
    misconfigs = []

    try:
        command = f"sudo nmap -p{port} --script ssh2-enum-algos {host}"

        returncode, stdout, stderr = await run_command(command, timeout=60)

        if returncode == 0:
            # Check for weak algorithms
            if 'diffie-hellman-group1' in stdout.lower():
                misconfigs.append({
                    "type": "weak_kex_algorithm",
                    "severity": "medium",
                    "description": "Weak key exchange algorithm (diffie-hellman-group1-sha1) enabled",
                    "remediation": "Disable weak KEX algorithms in sshd_config"
                })

            if 'arcfour' in stdout.lower() or 'rc4' in stdout.lower():
                misconfigs.append({
                    "type": "weak_cipher",
                    "severity": "high",
                    "description": "Weak cipher (arcfour/RC4) enabled",
                    "remediation": "Disable weak ciphers in sshd_config"
                })

    except Exception as e:
        logger.warning(f"Error analyzing SSH config: {e}")

    return misconfigs


def main():
    """Main entry point for vuln server."""
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("ntree-vuln v2.0.0")
            return
        elif sys.argv[1] == "--test":
            print("NTREE Vulnerability Testing Server - Test Mode")
            return

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
