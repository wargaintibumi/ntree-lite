"""
Nmap XML output parser
Converts nmap scan results into structured data
"""

try:
    import xmltodict
    _XMLTODICT_AVAILABLE = True
except ImportError:
    _XMLTODICT_AVAILABLE = False
from typing import Dict, List, Any, Optional
from pathlib import Path
from .logger import get_logger

logger = get_logger(__name__)


def parse_nmap_xml(xml_path: str) -> Dict[str, Any]:
    """
    Parse nmap XML output file into structured data.

    Args:
        xml_path: Path to nmap XML output file

    Returns:
        Dictionary with scan information and discovered hosts:
        {
            'scan_info': {
                'start_time': str,
                'end_time': str,
                'command': str,
                'version': str,
                'duration': float
            },
            'hosts': [
                {
                    'ip': '192.168.1.10',
                    'hostname': 'server01.local',
                    'status': 'up',
                    'os': 'Linux 4.x',
                    'os_accuracy': 95,
                    'services': [
                        {
                            'port': 22,
                            'protocol': 'tcp',
                            'state': 'open',
                            'service': 'ssh',
                            'product': 'OpenSSH',
                            'version': '7.4',
                            'extrainfo': 'protocol 2.0',
                            'cpe': 'cpe:/a:openbsd:openssh:7.4'
                        },
                        ...
                    ]
                },
                ...
            ]
        }

    Raises:
        FileNotFoundError: If XML file doesn't exist
        ValueError: If XML is malformed
    """
    xml_file = Path(xml_path)

    if not xml_file.exists():
        raise FileNotFoundError(f"Nmap XML file not found: {xml_path}")

    logger.debug(f"Parsing nmap XML: {xml_path}")

    try:
        with open(xml_file, 'r', encoding='utf-8', errors='replace') as f:
            xml_content = f.read()

        # Parse XML
        if not _XMLTODICT_AVAILABLE:
            raise ImportError("xmltodict is required to parse nmap XML. Install with: pip install xmltodict")
        doc = xmltodict.parse(xml_content)

        if 'nmaprun' not in doc:
            raise ValueError("Invalid nmap XML: missing 'nmaprun' element")

        nmaprun = doc['nmaprun']

        # Extract scan metadata
        result = {
            'scan_info': _extract_scan_info(nmaprun),
            'hosts': []
        }

        # Parse hosts
        hosts = nmaprun.get('host', [])

        # Ensure hosts is a list (single host returns dict)
        if isinstance(hosts, dict):
            hosts = [hosts]

        for host in hosts:
            host_data = _parse_host(host)
            if host_data:
                result['hosts'].append(host_data)

        logger.info(f"Parsed {len(result['hosts'])} hosts from nmap XML")
        return result

    except Exception as e:
        logger.error(f"Error parsing nmap XML: {e}")
        raise ValueError(f"Failed to parse nmap XML: {e}")


def _extract_scan_info(nmaprun: dict) -> dict:
    """Extract scan metadata from nmaprun element."""
    runstats = nmaprun.get('runstats', {})
    finished = runstats.get('finished', {})

    # Calculate duration
    start_time = nmaprun.get('@start', '0')
    end_time = finished.get('@time', '0')

    try:
        duration = float(end_time) - float(start_time)
    except (ValueError, TypeError):
        duration = 0.0

    return {
        'start_time': nmaprun.get('@startstr', 'Unknown'),
        'end_time': finished.get('@timestr', 'Unknown'),
        'command': nmaprun.get('@args', ''),
        'version': nmaprun.get('@version', 'Unknown'),
        'duration': duration,
        'exit_status': finished.get('@exit', 'unknown'),
    }


def _parse_host(host: dict) -> Optional[Dict[str, Any]]:
    """
    Parse a single host from nmap XML.

    Args:
        host: Host dictionary from XML

    Returns:
        Host data dictionary or None if host is invalid
    """
    # Get IP address
    address = host.get('address', {})

    # Handle multiple addresses (IPv4, IPv6, MAC)
    if isinstance(address, list):
        ipv4 = next((a['@addr'] for a in address if a.get('@addrtype') == 'ipv4'), None)
        mac = next((a['@addr'] for a in address if a.get('@addrtype') == 'mac'), None)
    else:
        ipv4 = address.get('@addr') if address.get('@addrtype') == 'ipv4' else None
        mac = None

    if not ipv4:
        logger.warning("Host entry missing IPv4 address, skipping")
        return None

    # Get hostname(s)
    hostnames_data = host.get('hostnames') or {}
    hostnames = hostnames_data.get('hostname', [])
    if isinstance(hostnames, dict):
        hostnames = [hostnames]

    hostname = hostnames[0].get('@name', '') if hostnames else ''

    # Get status
    status_elem = host.get('status', {})
    status = status_elem.get('@state', 'unknown')
    reason = status_elem.get('@reason', '')

    # Get OS detection
    os_guess, os_accuracy = _parse_os_detection(host.get('os', {}))

    # Get services/ports
    services = _parse_ports(host.get('ports', {}))

    return {
        'ip': ipv4,
        'mac': mac,
        'hostname': hostname,
        'status': status,
        'reason': reason,
        'os': os_guess,
        'os_accuracy': os_accuracy,
        'services': services,
    }


def _parse_os_detection(os_elem: dict) -> tuple:
    """
    Parse OS detection results.

    Returns:
        Tuple of (os_name, accuracy)
    """
    if not os_elem:
        return 'Unknown', 0

    osmatch = os_elem.get('osmatch', [])

    # Ensure osmatch is a list
    if isinstance(osmatch, dict):
        osmatch = [osmatch]

    if not osmatch:
        return 'Unknown', 0

    # Get best match (first one, they're sorted by accuracy)
    best_match = osmatch[0]

    os_name = best_match.get('@name', 'Unknown')
    try:
        accuracy = int(best_match.get('@accuracy', 0))
    except (ValueError, TypeError):
        accuracy = 0

    return os_name, accuracy


def _parse_ports(ports_elem: dict) -> List[Dict[str, Any]]:
    """Parse ports and services from ports element."""
    if not ports_elem:
        return []

    port_list = ports_elem.get('port', [])

    # Ensure port_list is a list
    if isinstance(port_list, dict):
        port_list = [port_list]

    services = []

    for port in port_list:
        service = _parse_service(port)
        if service:
            services.append(service)

    return services


def _parse_service(port: dict) -> Optional[Dict[str, Any]]:
    """Parse a single port/service entry."""
    try:
        port_num = int(port.get('@portid', 0))
    except (ValueError, TypeError):
        return None

    protocol = port.get('@protocol', 'tcp')

    # Port state
    state_elem = port.get('state', {})
    state = state_elem.get('@state', 'unknown')
    reason = state_elem.get('@reason', '')

    # Service information
    service_elem = port.get('service', {})

    service_name = service_elem.get('@name', 'unknown')
    product = service_elem.get('@product', '')
    version = service_elem.get('@version', '')
    extrainfo = service_elem.get('@extrainfo', '')
    ostype = service_elem.get('@ostype', '')
    method = service_elem.get('@method', '')
    conf = service_elem.get('@conf', '')

    # CPE (Common Platform Enumeration)
    cpe = service_elem.get('cpe', '')
    if isinstance(cpe, list):
        cpe = cpe[0] if cpe else ''

    # NSE scripts output
    scripts = _parse_scripts(port.get('script', []))

    return {
        'port': port_num,
        'protocol': protocol,
        'state': state,
        'reason': reason,
        'service': service_name,
        'product': product,
        'version': version,
        'extrainfo': extrainfo,
        'ostype': ostype,
        'method': method,
        'conf': conf,
        'cpe': cpe,
        'scripts': scripts,
    }


def _parse_scripts(script_elem) -> List[Dict[str, str]]:
    """Parse NSE script output."""
    if not script_elem:
        return []

    # Ensure it's a list
    if isinstance(script_elem, dict):
        script_elem = [script_elem]

    scripts = []

    for script in script_elem:
        scripts.append({
            'id': script.get('@id', ''),
            'output': script.get('@output', ''),
        })

    return scripts


def summarize_scan(scan_data: dict) -> str:
    """
    Create a human-readable summary of scan results.

    Args:
        scan_data: Parsed scan data from parse_nmap_xml()

    Returns:
        Summary string
    """
    total_hosts = len(scan_data['hosts'])
    up_hosts = sum(1 for h in scan_data['hosts'] if h['status'] == 'up')

    total_services = sum(len(h['services']) for h in scan_data['hosts'])
    open_services = sum(
        sum(1 for s in h['services'] if s['state'] == 'open')
        for h in scan_data['hosts']
    )

    duration = scan_data['scan_info'].get('duration', 0)

    summary = f"""Nmap Scan Summary:
Duration: {duration:.1f} seconds
Total hosts: {total_hosts}
Hosts up: {up_hosts}
Total services: {total_services}
Open services: {open_services}
"""

    # List hosts
    if scan_data['hosts']:
        summary += "\nHosts:\n"
        for host in scan_data['hosts']:
            hostname = f" ({host['hostname']})" if host['hostname'] else ""
            os = f" - {host['os']}" if host['os'] != 'Unknown' else ""
            open_ports = sum(1 for s in host['services'] if s['state'] == 'open')
            summary += f"  {host['ip']}{hostname}{os} - {open_ports} open ports\n"

    return summary
