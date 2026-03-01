"""
NTREE Service Enumeration MCP Server
Handles detailed service enumeration for discovered hosts
"""

import asyncio
import json
import re
import shlex
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from .utils.command_runner import run_command
from .utils.nmap_parser import parse_nmap_xml
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

app = Server("ntree-enum")


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
            import json
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


# Input validation functions to prevent command injection
def validate_ip_or_cidr(target: str) -> bool:
    """Validate IP address or CIDR range."""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'

    if re.match(ip_pattern, target) or re.match(cidr_pattern, target):
        octets = target.split('/')[0].split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            if '/' in target:
                prefix = int(target.split('/')[1])
                return 0 <= prefix <= 32
            return True
    return False


def validate_url(url: str) -> bool:
    """Validate URL format for web scanning."""
    url_pattern = r'^https?://[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(:[0-9]{1,5})?(/.*)?$'
    return bool(re.match(url_pattern, url))


def validate_port_range(port_range: str) -> bool:
    """Validate port range specification."""
    if not re.match(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$', port_range):
        return False

    parts = port_range.replace('-', ',').split(',')
    try:
        ports = [int(p) for p in parts]
        return all(0 < p <= 65535 for p in ports)
    except ValueError:
        return False


def validate_username(username: str) -> bool:
    """Validate username - alphanumeric, underscore, hyphen, dot only."""
    return bool(re.match(r'^[a-zA-Z0-9_\-\.]+$', username))


def validate_file_path(file_path: str) -> bool:
    """Validate file path is within allowed directories."""
    allowed_dirs = [
        '/usr/share/wordlists',
        '/usr/share/dirb',        # dirb wordlists (symlink target)
        '/usr/share/dirbuster',   # dirbuster wordlists
        '/tmp',
        str(Path.home() / 'wordlists')
    ]
    try:
        real_path = Path(file_path).resolve()
        # Check if the resolved path is actually within one of the allowed directories
        for allowed_dir in allowed_dirs:
            try:
                real_path.relative_to(Path(allowed_dir).resolve())
                return True
            except ValueError:
                # Not within this allowed directory, try the next one
                continue
        return False
    except (OSError, RuntimeError):
        # Path resolution failed (e.g., broken symlink, too many symlinks)
        return False


class EnumerateServicesArgs(BaseModel):
    """Arguments for enumerate_services tool."""
    host: str = Field(description="Target host IP address")
    ports: str = Field(
        default="default",
        description="Ports to enumerate: 'default', 'all', or specific ports like '22,80,443'"
    )


class EnumerateWebArgs(BaseModel):
    """Arguments for enumerate_web tool."""
    url: str = Field(description="Target URL (e.g., http://example.com)")
    depth: int = Field(default=2, description="Depth of enumeration (1-3)")


class EnumerateSMBArgs(BaseModel):
    """Arguments for enumerate_smb tool."""
    host: str = Field(description="Target host IP address")


class EnumerateDomainArgs(BaseModel):
    """Arguments for enumerate_domain tool."""
    domain_controller: str = Field(description="Domain controller IP address")
    username: str = Field(default="", description="Optional username for authenticated enumeration")
    password: str = Field(default="", description="Optional password for authenticated enumeration")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available enumeration tools."""
    return [
        Tool(
            name="enumerate_services",
            description="Perform detailed service enumeration on a host using nmap version detection and NSE scripts",
            inputSchema=EnumerateServicesArgs.model_json_schema()
        ),
        Tool(
            name="enumerate_web",
            description="Enumerate web application using nikto, technology detection, and directory brute-forcing",
            inputSchema=EnumerateWebArgs.model_json_schema()
        ),
        Tool(
            name="enumerate_smb",
            description="Enumerate SMB/Windows services including shares, users, groups, and domain information",
            inputSchema=EnumerateSMBArgs.model_json_schema()
        ),
        Tool(
            name="enumerate_domain",
            description="Enumerate Active Directory domain controller for users, groups, computers, and policies",
            inputSchema=EnumerateDomainArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    # Log tool call to audit
    audit = _get_audit()
    if audit:
        audit.log_tool_call(f"ntree-enum.{name}", arguments)

    try:
        if name == "enumerate_services":
            args = EnumerateServicesArgs(**arguments)
            result = await enumerate_services(args.host, args.ports)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "enumerate_web":
            args = EnumerateWebArgs(**arguments)
            result = await enumerate_web(args.url, args.depth)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "enumerate_smb":
            args = EnumerateSMBArgs(**arguments)
            result = await enumerate_smb(args.host)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "enumerate_domain":
            args = EnumerateDomainArgs(**arguments)
            result = await enumerate_domain(
                args.domain_controller,
                args.username,
                args.password
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def enumerate_services(host: str, ports: str = "default") -> dict:
    """
    Perform detailed service enumeration using nmap.

    Args:
        host: Target IP address
        ports: Port specification

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "services": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "7.4",
                    "cpe": "cpe:/a:openbsd:openssh:7.4",
                    "scripts": [...]
                },
                ...
            ],
            "summary": "Found 5 open services"
        }
    """
    try:
        logger.info(f"Enumerating services on {host}")

        # Validate host to prevent command injection
        if not validate_ip_or_cidr(host):
            logger.error(f"Invalid host IP: {host}")
            return {"status": "error", "error": f"Invalid host IP address: {host}"}

        # Validate ports if not default/all
        if ports not in ["default", "all"]:
            if not validate_port_range(ports):
                logger.error(f"Invalid port specification: {ports}")
                return {"status": "error", "error": f"Invalid port specification: {ports}"}

        # Build port specification
        if ports == "default":
            port_spec = ""  # nmap default ports
        elif ports == "all":
            port_spec = "-p-"  # all 65535 ports
        else:
            port_spec = f"-p {ports}"  # ports validated above

        # Create temporary file for XML output using UUID
        import uuid
        xml_output = Path(f"/tmp/enum_services_{uuid.uuid4()}.xml")

        try:
            # Build nmap command with aggressive service detection
            cmd_parts = [
                "sudo", "nmap",
                "-sV",  # Version detection
                "-sC",  # Default scripts
                "--version-intensity", "9",  # Maximum version detection
                "-T3",  # Normal timing
                "-v",   # Verbose
            ]

            if port_spec:
                cmd_parts.append(port_spec)  # port_spec is safe (validated above)

            cmd_parts.extend(["-oX", shlex.quote(str(xml_output))])
            cmd_parts.append(shlex.quote(host))

            command = " ".join(cmd_parts)

            logger.debug(f"Executing: {command}")

            # Run enumeration (timeout 15 minutes for detailed scans)
            returncode, stdout, stderr = await run_command(command, timeout=900)

            if returncode != 0:
                logger.error(f"Service enumeration failed: {stderr}")
                return {
                    "status": "error",
                    "error": f"nmap enumeration failed: {stderr[:500]}"
                }

            # Parse results
            scan_result = parse_nmap_xml(str(xml_output))

            if not scan_result['hosts']:
                return {
                    "status": "success",
                    "host": host,
                    "services": [],
                    "summary": "No services detected (host may be down or filtered)"
                }

            host_data = scan_result['hosts'][0]
            services = host_data.get('services', [])

            # Enrich services with additional information
            enriched_services = []
            for svc in services:
                enriched = await _enrich_service(host, svc)
                enriched_services.append(enriched)

            summary = f"Found {len([s for s in services if s['state'] == 'open'])} open services"

            logger.info(f"Service enumeration complete for {host}: {summary}")

            return {
                "status": "success",
                "host": host,
                "hostname": host_data.get('hostname', ''),
                "os": host_data.get('os', 'Unknown'),
                "services": enriched_services,
                "summary": summary,
                "command": command
            }

        finally:
            # Clean up temp file
            if xml_output.exists():
                try:
                    xml_output.unlink()
                except PermissionError:
                    # File was created by root (sudo nmap), try sudo rm
                    import subprocess
                    subprocess.run(['sudo', 'rm', '-f', str(xml_output)], check=False)

    except Exception as e:
        logger.error(f"Error enumerating services on {host}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _enrich_service(host: str, service: dict) -> dict:
    """Enrich service information with additional context."""
    enriched = service.copy()

    # Add vulnerability hints based on service/version
    vulnerabilities = []

    # Check for known vulnerable services
    service_name = service.get('service', '').lower()
    version = service.get('version', '').lower()

    # Common vulnerable services
    if 'smb' in service_name or service.get('port') == 445:
        vulnerabilities.append("SMB service detected - check for EternalBlue, SMB signing")

    if 'ftp' in service_name and service.get('port') == 21:
        vulnerabilities.append("FTP detected - check for anonymous login, weak credentials")

    if 'telnet' in service_name:
        vulnerabilities.append("Telnet detected - unencrypted, consider replacing with SSH")

    if 'mysql' in service_name and service.get('port') == 3306:
        vulnerabilities.append("MySQL exposed - check for weak credentials, public access")

    if 'rdp' in service_name or service.get('port') == 3389:
        vulnerabilities.append("RDP detected - check for BlueKeep, weak credentials")

    if 'ssh' in service_name:
        # Parse SSH version for vulnerabilities
        if 'openssh' in version:
            version_match = re.search(r'(\d+\.\d+)', version)
            if version_match:
                ver = float(version_match.group(1))
                if ver < 7.4:
                    vulnerabilities.append("Outdated OpenSSH version - multiple CVEs")

    enriched['vulnerability_hints'] = vulnerabilities

    return enriched


async def enumerate_web(url: str, depth: int = 2) -> dict:
    """
    Enumerate web application.

    Args:
        url: Target URL
        depth: Enumeration depth (1-3)

    Returns:
        {
            "status": "success",
            "url": "http://example.com",
            "technologies": ["Apache/2.4.41", "PHP/7.4"],
            "endpoints": ["/admin", "/api", ...],
            "vulnerabilities": [...],
            "security_headers": {...}
        }
    """
    try:
        logger.info(f"Enumerating web application: {url}")

        # Validate URL to prevent command injection
        if not validate_url(url):
            logger.error(f"Invalid URL: {url}")
            return {"status": "error", "error": f"Invalid URL format: {url}"}

        result = {
            "status": "success",
            "url": url,
            "technologies": [],
            "endpoints": [],
            "vulnerabilities": [],
            "security_headers": {},
            "forms": [],
        }

        # 1. Basic HTTP headers and technology detection
        tech_info = await _detect_web_technologies(url)
        result['technologies'] = tech_info['technologies']
        result['security_headers'] = tech_info['security_headers']

        # 2. Run nikto for vulnerability scanning
        if depth >= 2:
            nikto_results = await _run_nikto(url)
            result['vulnerabilities'] = nikto_results

        # 3. Directory/endpoint enumeration
        if depth >= 2:
            endpoints = await _enumerate_web_directories(url, depth)
            result['endpoints'] = endpoints

        # 4. Form detection
        forms = await _detect_forms(url)
        result['forms'] = forms

        summary = f"Found {len(result['technologies'])} technologies, " \
                  f"{len(result['endpoints'])} endpoints, " \
                  f"{len(result['vulnerabilities'])} potential issues"

        result['summary'] = summary

        logger.info(f"Web enumeration complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error enumerating web app {url}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _detect_web_technologies(url: str) -> dict:
    """Detect web technologies using HTTP headers."""
    technologies = []
    security_headers = {
        'present': [],
        'missing': []
    }

    try:
        # Validate URL to prevent command injection (should already be validated by caller)
        if not validate_url(url):
            logger.warning(f"Invalid URL in _detect_web_technologies: {url}")
            return {'technologies': [], 'security_headers': {'present': [], 'missing': []}}

        # Use curl to get headers with proper escaping
        command = f"curl -I -L -s {shlex.quote(url)}"
        returncode, stdout, stderr = await run_command(command, timeout=30)

        if returncode == 0:
            # Parse headers
            for line in stdout.split('\n'):
                line = line.strip()

                # Technology detection
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    technologies.append(server)

                if line.lower().startswith('x-powered-by:'):
                    powered = line.split(':', 1)[1].strip()
                    technologies.append(powered)

                # Security headers
                header_name = line.split(':', 1)[0].lower()
                if header_name in ['x-frame-options', 'x-xss-protection',
                                   'x-content-type-options', 'strict-transport-security',
                                   'content-security-policy']:
                    security_headers['present'].append(line.split(':', 1)[0])

        # Check for missing security headers
        important_headers = ['X-Frame-Options', 'X-XSS-Protection',
                            'X-Content-Type-Options', 'Strict-Transport-Security',
                            'Content-Security-Policy']

        for header in important_headers:
            if header not in security_headers['present']:
                security_headers['missing'].append(header)

    except Exception as e:
        logger.warning(f"Error detecting web technologies: {e}")

    return {
        'technologies': technologies,
        'security_headers': security_headers
    }


async def _run_nikto(url: str) -> list:
    """Run nikto vulnerability scanner."""
    vulnerabilities = []

    try:
        # Validate URL to prevent command injection (should already be validated by caller)
        if not validate_url(url):
            logger.warning(f"Invalid URL in _run_nikto: {url}")
            return []

        command = f"nikto -h {shlex.quote(url)} -Tuning 123bde -timeout 30"
        returncode, stdout, stderr = await run_command(command, timeout=300)

        if returncode == 0 or returncode == 1:  # nikto returns 1 on findings
            # Parse nikto output
            for line in stdout.split('\n'):
                if '+' in line and any(keyword in line.lower() for keyword in
                                      ['osvdb', 'cve', 'vulnerable', 'error', 'found']):
                    vulnerabilities.append(line.strip())

    except Exception as e:
        logger.warning(f"Error running nikto: {e}")

    return vulnerabilities[:20]  # Limit to top 20


async def _enumerate_web_directories(url: str, depth: int) -> list:
    """Enumerate web directories using gobuster."""
    endpoints = []

    try:
        # Validate URL to prevent command injection (should already be validated by caller)
        if not validate_url(url):
            logger.warning(f"Invalid URL in _enumerate_web_directories: {url}")
            return []

        # Use common wordlist
        wordlist = "/usr/share/wordlists/dirb/common.txt"

        if not Path(wordlist).exists():
            logger.warning(f"Wordlist not found: {wordlist}")
            return endpoints

        # Validate wordlist path to prevent path traversal
        if not validate_file_path(wordlist):
            logger.warning(f"Invalid wordlist path: {wordlist}")
            return endpoints

        command = f"gobuster dir -u {shlex.quote(url)} -w {shlex.quote(wordlist)} -t 10 -q --timeout 10s"

        returncode, stdout, stderr = await run_command(command, timeout=180)

        if returncode == 0:
            # Parse gobuster output
            for line in stdout.split('\n'):
                if line.strip() and not line.startswith('='):
                    # Extract endpoint from line like: "/admin (Status: 200)"
                    match = re.search(r'(/[^\s]+)', line)
                    if match:
                        endpoints.append(match.group(1))

    except Exception as e:
        logger.warning(f"Error enumerating directories: {e}")

    return endpoints[:50]  # Limit results


async def _detect_forms(url: str) -> list:
    """Detect HTML forms (basic detection with curl)."""
    forms = []

    try:
        # Validate URL to prevent command injection (should already be validated by caller)
        if not validate_url(url):
            logger.warning(f"Invalid URL in _detect_forms: {url}")
            return []

        command = f"curl -s -L {shlex.quote(url)}"
        returncode, stdout, stderr = await run_command(command, timeout=30)

        if returncode == 0:
            # Simple form detection
            form_count = stdout.lower().count('<form')
            if form_count > 0:
                forms.append(f"Detected {form_count} HTML form(s)")

    except Exception as e:
        logger.warning(f"Error detecting forms: {e}")

    return forms


async def enumerate_smb(host: str) -> dict:
    """
    Enumerate SMB/Windows services.

    Args:
        host: Target IP address

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "shares": [...],
            "users": [...],
            "groups": [...],
            "domain": "WORKGROUP",
            "os_info": "Windows Server 2019",
            "smb_version": "SMBv2/v3",
            "signing_required": false
        }
    """
    try:
        logger.info(f"Enumerating SMB on {host}")

        # Validate host to prevent command injection
        if not validate_ip_or_cidr(host):
            logger.error(f"Invalid host IP: {host}")
            return {"status": "error", "error": f"Invalid host IP address: {host}"}

        result = {
            "status": "success",
            "host": host,
            "shares": [],
            "users": [],
            "groups": [],
            "domain": "",
            "os_info": "",
            "smb_version": "",
            "signing_required": None,
        }

        # Use alternative tools instead of enum4linux
        # 1. Get domain/workgroup info using nmap
        domain_info = await _get_domain_info_nmap(host)
        result.update(domain_info)

        # 2. Enumerate shares using smbclient
        shares = await _enumerate_shares_smbclient(host)
        result['shares'] = shares

        # 3. Enumerate users using rpcclient
        users = await _enumerate_users_rpcclient(host)
        result['users'] = users

        # 4. Get OS info using crackmapexec if available
        os_info = await _get_os_info_cme(host)
        if os_info:
            result['os_info'] = os_info

        # Additionally check SMB signing with nmap
        signing_check = await _check_smb_signing(host)
        result['signing_required'] = signing_check

        summary = f"Domain: {result['domain']}, " \
                  f"Shares: {len(result['shares'])}, " \
                  f"Users: {len(result['users'])}, " \
                  f"Signing: {'Required' if signing_check else 'Not Required'}"

        result['summary'] = summary

        logger.info(f"SMB enumeration complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error enumerating SMB on {host}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _get_domain_info_nmap(host: str) -> dict:
    """Get domain/workgroup information using nmap SMB scripts."""
    result = {
        "domain": "",
        "os_info": "",
        "smb_version": ""
    }

    try:
        if not validate_ip_or_cidr(host):
            logger.warning(f"Invalid host IP in _get_domain_info_nmap: {host}")
            return result

        command = f"sudo nmap -p445 --script smb-os-discovery {shlex.quote(host)}"
        returncode, stdout, stderr = await run_command(command, timeout=120)

        if returncode == 0:
            # Parse nmap output for domain/workgroup
            for line in stdout.split('\n'):
                if 'Workgroup:' in line or 'Domain name:' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        result['domain'] = parts[1].strip()
                elif 'OS:' in line and '|' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        result['os_info'] = parts[1].strip()
                elif 'SMB' in line and 'dialect' in line.lower():
                    result['smb_version'] = line.strip()

    except Exception as e:
        logger.warning(f"Error getting domain info via nmap: {e}")

    return result


async def _enumerate_shares_smbclient(host: str) -> list:
    """Enumerate SMB shares using smbclient."""
    shares = []

    try:
        if not validate_ip_or_cidr(host):
            logger.warning(f"Invalid host IP in _enumerate_shares_smbclient: {host}")
            return shares

        # Use smbclient with null session
        command = f"smbclient -N -L {shlex.quote(f'//{host}/')}"
        returncode, stdout, stderr = await run_command(command, timeout=60)

        # smbclient may return non-zero on access denied, but still give partial results
        if returncode == 0 or 'Sharename' in stdout:
            in_share_section = False
            for line in stdout.split('\n'):
                if 'Sharename' in line and 'Type' in line:
                    in_share_section = True
                    continue
                if in_share_section:
                    # Stop at blank line or next section
                    if not line.strip() or line.startswith('SMB'):
                        break
                    # Parse share line
                    parts = line.strip().split()
                    if parts and not parts[0].startswith('-'):
                        shares.append(parts[0])

    except Exception as e:
        logger.warning(f"Error enumerating shares via smbclient: {e}")

    return shares


async def _enumerate_users_rpcclient(host: str) -> list:
    """Enumerate users using rpcclient with null session."""
    users = []

    try:
        if not validate_ip_or_cidr(host):
            logger.warning(f"Invalid host IP in _enumerate_users_rpcclient: {host}")
            return users

        # Try to enumerate users with rpcclient null session
        command = f"rpcclient -U '' -N {shlex.quote(host)} -c 'enumdomusers'"
        returncode, stdout, stderr = await run_command(command, timeout=60)

        if returncode == 0:
            # Parse rpcclient output: user:[username] rid:[0x...]
            for line in stdout.split('\n'):
                match = re.search(r'user:\[([^\]]+)\]', line)
                if match:
                    user = match.group(1)
                    if user and user not in users:
                        users.append(user)

    except Exception as e:
        logger.warning(f"Error enumerating users via rpcclient: {e}")

    return users


async def _get_os_info_cme(host: str) -> str:
    """Get OS information using crackmapexec."""
    try:
        if not validate_ip_or_cidr(host):
            logger.warning(f"Invalid host IP in _get_os_info_cme: {host}")
            return ""

        # Use crackmapexec for quick SMB enumeration
        command = f"crackmapexec smb {shlex.quote(host)}"
        returncode, stdout, stderr = await run_command(command, timeout=60)

        if returncode == 0:
            # Parse CME output for OS info
            for line in stdout.split('\n'):
                if 'Windows' in line or 'name:' in line.lower():
                    # Extract OS version from CME output
                    match = re.search(r'\(name:([^)]+)\)', line)
                    if match:
                        return match.group(1).strip()
                    # Alternative format
                    match = re.search(r'Windows[^\n\r]+', line)
                    if match:
                        return match.group(0).strip()

    except Exception as e:
        logger.warning(f"Error getting OS info via crackmapexec: {e}")

    return ""


async def _enumerate_ldap_anonymous(host: str) -> dict:
    """Enumerate Active Directory via anonymous LDAP."""
    result = {
        "domain": "",
        "users": [],
        "groups": [],
        "computers": []
    }

    try:
        if not validate_ip_or_cidr(host):
            logger.warning(f"Invalid host IP in _enumerate_ldap_anonymous: {host}")
            return result

        # Try anonymous LDAP bind to get base DN
        command = f"ldapsearch -x -H ldap://{shlex.quote(host)} -b '' -s base namingContexts"
        returncode, stdout, stderr = await run_command(command, timeout=30)

        if returncode == 0:
            # Extract domain from naming context
            match = re.search(r'DC=([^,\s]+)', stdout)
            if match:
                result['domain'] = match.group(1).upper()

                # Try to query for users/computers with anonymous bind
                base_dn = re.search(r'(DC=[^\n]+)', stdout)
                if base_dn:
                    base = base_dn.group(1).strip()

                    # Query for users
                    cmd = f"ldapsearch -x -H ldap://{shlex.quote(host)} -b {shlex.quote(base)} '(objectClass=user)' sAMAccountName"
                    ret, out, err = await run_command(cmd, timeout=60)
                    if ret == 0:
                        for line in out.split('\n'):
                            if line.startswith('sAMAccountName:'):
                                user = line.split(':', 1)[1].strip()
                                if user and user not in result['users']:
                                    result['users'].append(user)

    except Exception as e:
        logger.warning(f"Error enumerating via anonymous LDAP: {e}")

    return result


async def _enumerate_ad_authenticated(dc: str, username: str, password: str) -> dict:
    """Enumerate Active Directory with authenticated credentials using crackmapexec."""
    result = {
        "domain": "",
        "users": [],
        "groups": [],
        "computers": []
    }

    try:
        if not validate_ip_or_cidr(dc):
            logger.warning(f"Invalid DC IP in _enumerate_ad_authenticated: {dc}")
            return result

        if not validate_username(username):
            logger.warning(f"Invalid username in _enumerate_ad_authenticated: {username}")
            return result

        # Use crackmapexec to enumerate domain users
        command = f"crackmapexec smb {shlex.quote(dc)} -u {shlex.quote(username)} -p {shlex.quote(password)} --users"
        returncode, stdout, stderr = await run_command(command, timeout=120)

        if returncode == 0:
            # Parse crackmapexec users output
            for line in stdout.split('\n'):
                # CME format: [domain]\username
                match = re.search(r'\\([a-zA-Z0-9_\-\.]+)', line)
                if match:
                    user = match.group(1)
                    if user and user not in result['users']:
                        result['users'].append(user)

        # Try to get domain info
        cmd = f"crackmapexec smb {shlex.quote(dc)} -u {shlex.quote(username)} -p {shlex.quote(password)}"
        ret, out, err = await run_command(cmd, timeout=60)
        if ret == 0:
            match = re.search(r'domain:([^\s]+)', out, re.IGNORECASE)
            if match:
                result['domain'] = match.group(1).strip()

    except Exception as e:
        logger.warning(f"Error in authenticated AD enumeration: {e}")

    return result


async def _check_smb_signing(host: str) -> Optional[bool]:
    """Check if SMB signing is required using nmap."""
    try:
        # Validate host to prevent command injection (should already be validated by caller)
        if not validate_ip_or_cidr(host):
            logger.warning(f"Invalid host IP in _check_smb_signing: {host}")
            return None

        command = f"sudo nmap -p445 --script smb-security-mode {shlex.quote(host)}"
        returncode, stdout, stderr = await run_command(command, timeout=60)

        if returncode == 0:
            if 'message_signing: required' in stdout.lower():
                return True
            elif 'message_signing: disabled' in stdout.lower():
                return False

    except Exception as e:
        logger.warning(f"Error checking SMB signing: {e}")

    return None


async def enumerate_domain(
    domain_controller: str,
    username: str = "",
    password: str = ""
) -> dict:
    """
    Enumerate Active Directory domain controller.

    Args:
        domain_controller: DC IP address
        username: Optional username for authenticated enum
        password: Optional password

    Returns:
        {
            "status": "success",
            "dc": "192.168.1.10",
            "domain": "CORP.LOCAL",
            "users": [...],
            "groups": [...],
            "computers": [...],
            "policies": {...}
        }
    """
    try:
        logger.info(f"Enumerating Active Directory on {domain_controller}")

        # Validate domain_controller to prevent command injection
        if not validate_ip_or_cidr(domain_controller):
            logger.error(f"Invalid domain controller IP: {domain_controller}")
            return {"status": "error", "error": f"Invalid domain controller IP address: {domain_controller}"}

        # Validate username if provided
        if username and not validate_username(username):
            logger.error(f"Invalid username: {username}")
            return {"status": "error", "error": f"Invalid username format: {username}"}

        result = {
            "status": "success",
            "dc": domain_controller,
            "domain": "",
            "users": [],
            "groups": [],
            "computers": [],
            "policies": {},
        }

        # Use alternative tools for AD enumeration
        if not username:
            logger.info("Performing unauthenticated AD enumeration")
            # 1. Get domain info using nmap
            domain_info = await _get_domain_info_nmap(domain_controller)
            result.update(domain_info)

            # 2. Try RID cycling with rpcclient for users
            users = await _enumerate_users_rpcclient(domain_controller)
            result['users'] = users

            # 3. Try ldapsearch for basic AD info
            ad_info = await _enumerate_ldap_anonymous(domain_controller)
            result.update(ad_info)
        else:
            logger.info("Performing authenticated AD enumeration")
            # Use crackmapexec for authenticated enumeration
            ad_info = await _enumerate_ad_authenticated(domain_controller, username, password)
            result.update(ad_info)

        summary = f"Domain: {result['domain']}, " \
                  f"Users: {len(result['users'])}, " \
                  f"Groups: {len(result['groups'])}"

        result['summary'] = summary

        logger.info(f"AD enumeration complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error enumerating AD on {domain_controller}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


def main():
    """Main entry point for enum server."""
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("ntree-enum v2.0.0")
            return
        elif sys.argv[1] == "--test":
            print("NTREE Enumeration Server - Test Mode")
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
