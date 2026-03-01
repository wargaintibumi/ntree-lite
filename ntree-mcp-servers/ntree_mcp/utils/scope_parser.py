"""
Scope file parsing and IP validation
Ensures all pentest actions stay within authorized boundaries
"""

import fnmatch
import ipaddress
import re
import socket
from typing import List, Set, Tuple, Optional
from pathlib import Path
from .logger import get_logger

# Try to import netifaces for local IP detection
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

logger = get_logger(__name__)


def get_local_ips() -> Set[str]:
    """
    Get all IP addresses assigned to local interfaces.

    Returns:
        Set of local IP addresses as strings
    """
    local_ips = set()

    # Always include localhost
    local_ips.add('127.0.0.1')

    if HAS_NETIFACES:
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if 'addr' in addr:
                            local_ips.add(addr['addr'])
        except Exception as e:
            logger.warning(f"Error getting local IPs via netifaces: {e}")
    else:
        # Fallback: use socket to get hostname-based IP
        try:
            hostname = socket.gethostname()
            local_ips.add(socket.gethostbyname(hostname))
        except Exception as e:
            logger.warning(f"Error getting local IP via socket: {e}")

    logger.debug(f"Detected local IPs: {local_ips}")
    return local_ips


def is_self_target(target: str, local_ips: Set[str]) -> bool:
    """
    Check if target IP matches any local interface.

    Args:
        target: Target IP address string
        local_ips: Set of local IP addresses

    Returns:
        True if target is a local IP
    """
    try:
        target_ip = ipaddress.ip_address(target)
        return str(target_ip) in local_ips
    except ValueError:
        return False  # Not an IP, domain names pass through


class ScopeValidator:
    """
    Parse and validate penetration test scope.

    Supports:
    - CIDR notation (192.168.1.0/24)
    - Individual IPs (192.168.1.50)
    - Domains (example.com)
    - Wildcard domains (*.internal.example.com)
    - Exclusions (EXCLUDE 192.168.1.1)
    """

    def __init__(self, scope_file: Path):
        """
        Initialize scope validator from file.

        Args:
            scope_file: Path to scope file

        Raises:
            FileNotFoundError: If scope file doesn't exist
            ValueError: If scope file is invalid
        """
        self.scope_file = Path(scope_file)

        if not self.scope_file.exists():
            raise FileNotFoundError(f"Scope file not found: {scope_file}")

        # Inclusion lists
        self.included_ranges: List[ipaddress.IPv4Network] = []
        self.included_ips: Set[ipaddress.IPv4Address] = set()
        self.included_domains: Set[str] = set()

        # Exclusion lists
        self.excluded_ranges: List[ipaddress.IPv4Network] = []
        self.excluded_ips: Set[ipaddress.IPv4Address] = set()

        # Wi-Fi assessment permissions
        self.wifi_allowed: bool = False
        self.wifi_interface: str = "wlan1"  # Default to secondary interface
        self.wifi_bssid_scope: List[str] = []  # BSSID patterns (e.g., "AA:BB:CC:*")

        # Self-IP protection: detect local IPs and auto-exclude
        self._local_ips: Set[str] = get_local_ips()

        self._parse_scope_file()

        # Validate we have at least some targets
        # Allow Wi-Fi-only assessments (no traditional targets required if WIFI_ALLOWED)
        has_traditional_targets = bool(self.included_ranges or self.included_ips or self.included_domains)
        if not has_traditional_targets and not self.wifi_allowed:
            raise ValueError("Scope file contains no valid targets (and WIFI_ALLOWED not set)")

        # Log Wi-Fi status if enabled
        if self.wifi_allowed:
            logger.info(f"Wi-Fi assessment ENABLED - interface: {self.wifi_interface}")
            if self.wifi_bssid_scope:
                logger.info(f"Wi-Fi BSSID scope: {self.wifi_bssid_scope}")

        logger.info(f"Scope loaded: {self.get_scope_summary()}")
        logger.info(f"Self-IP protection: {len(self._local_ips)} local IPs auto-excluded")

    def _parse_scope_file(self):
        """Parse scope file and populate inclusion/exclusion lists."""
        logger.debug(f"Parsing scope file: {self.scope_file}")

        with open(self.scope_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                try:
                    # Handle Wi-Fi directives
                    line_upper = line.upper()

                    if line_upper.startswith('WIFI_ALLOWED:'):
                        value = line.split(':', 1)[1].strip().lower()
                        self.wifi_allowed = value in ['true', 'yes', '1']
                        logger.debug(f"Wi-Fi allowed: {self.wifi_allowed}")
                        continue

                    if line_upper.startswith('WIFI_INTERFACE:'):
                        value = line.split(':', 1)[1].strip()
                        if value:
                            self.wifi_interface = value
                        logger.debug(f"Wi-Fi interface: {self.wifi_interface}")
                        continue

                    if line_upper.startswith('WIFI_BSSID_SCOPE:'):
                        pattern = line.split(':', 1)[1].strip()
                        if pattern:
                            self.wifi_bssid_scope.append(pattern.upper())
                        logger.debug(f"Wi-Fi BSSID scope pattern: {pattern}")
                        continue

                    # Handle exclusions
                    if line_upper.startswith('EXCLUDE'):
                        # Remove 'EXCLUDE' prefix
                        target = line.split(maxsplit=1)[1] if len(line.split()) > 1 else ""
                        if target:
                            self._add_target(target, excluded=True)
                    else:
                        self._add_target(line, excluded=False)

                except Exception as e:
                    logger.warning(f"Line {line_num}: Error parsing '{line}': {e}")

    def _add_target(self, target: str, excluded: bool):
        """
        Add a target to included or excluded lists.

        Args:
            target: Target string (IP, CIDR, or domain)
            excluded: Whether this is an exclusion
        """
        target = target.strip()
        # Strip inline comments (e.g. "192.168.0.1  # comment")
        if '#' in target:
            target = target[:target.index('#')].strip()

        try:
            # Try parsing as network (CIDR notation)
            if '/' in target:
                network = ipaddress.IPv4Network(target, strict=False)
                if excluded:
                    self.excluded_ranges.append(network)
                    logger.debug(f"Added excluded range: {network}")
                else:
                    self.included_ranges.append(network)
                    logger.debug(f"Added included range: {network}")
                return

            # Try parsing as single IP
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                ip = ipaddress.IPv4Address(target)
                if excluded:
                    self.excluded_ips.add(ip)
                    logger.debug(f"Added excluded IP: {ip}")
                else:
                    self.included_ips.add(ip)
                    logger.debug(f"Added included IP: {ip}")
                return

            # Otherwise treat as domain
            # Basic domain validation (RFC 1035: max 253 chars)
            if len(target.lstrip("*.")) > 253:
                logger.warning(f"Domain name exceeds 253 characters, ignoring: {target[:60]}...")
                return
            if re.match(r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$', target):
                if not excluded:  # Domains can only be included, not excluded
                    self.included_domains.add(target.lower())
                    logger.debug(f"Added included domain: {target.lower()}")
                else:
                    logger.warning(f"Domain exclusions not supported, ignoring: {target}")
                return

            logger.warning(f"Invalid target format: {target}")

        except ValueError as e:
            logger.warning(f"Invalid target '{target}': {e}")

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is in scope.

        Args:
            target: IP address or domain to check

        Returns:
            Tuple of (in_scope: bool, reason: str)
        """
        # Self-IP protection: block targeting own machine
        if is_self_target(target, self._local_ips):
            logger.warning(f"BLOCKED: Attempted to target own machine: {target}")
            return False, f"BLOCKED: Cannot target own machine ({target})"

        # Try as IP address first
        try:
            ip = ipaddress.IPv4Address(target)
            return self._is_ip_in_scope(ip)
        except ValueError:
            pass

        # Try as domain
        return self._is_domain_in_scope(target)

    def _is_ip_in_scope(self, ip: ipaddress.IPv4Address) -> Tuple[bool, str]:
        """Check if an IP address is in scope."""
        # Check exclusions first (explicit denials take precedence)
        if ip in self.excluded_ips:
            return False, f"IP {ip} is explicitly excluded"

        for excluded_range in self.excluded_ranges:
            if ip in excluded_range:
                return False, f"IP {ip} is in excluded range {excluded_range}"

        # Check inclusions
        if ip in self.included_ips:
            return True, f"IP {ip} is explicitly included"

        for included_range in self.included_ranges:
            if ip in included_range:
                return True, f"IP {ip} is in included range {included_range}"

        # Not in any inclusion list
        return False, f"IP {ip} is not in any included scope"

    def _is_domain_in_scope(self, domain: str) -> Tuple[bool, str]:
        """Check if a domain is in scope."""
        domain = domain.lower()

        # Exact match
        if domain in self.included_domains:
            return True, f"Domain {domain} is explicitly included"

        # Wildcard match
        for scope_domain in self.included_domains:
            if scope_domain.startswith('*.'):
                # Extract base domain (everything after *.)
                base_domain = scope_domain[2:]

                # Check if target domain ends with base domain
                if domain.endswith(base_domain):
                    # Ensure it's actually a subdomain, not partial match
                    if domain == base_domain or domain.endswith('.' + base_domain):
                        return True, f"Domain {domain} matches wildcard {scope_domain}"

        return False, f"Domain {domain} is not in scope"

    def is_bssid_in_scope(self, bssid: str) -> Tuple[bool, str]:
        """
        Check if a BSSID is in Wi-Fi scope.

        Args:
            bssid: BSSID (MAC address) to check

        Returns:
            Tuple of (in_scope: bool, reason: str)
        """
        # First check if Wi-Fi is allowed at all
        if not self.wifi_allowed:
            return False, "Wi-Fi assessment not allowed (WIFI_ALLOWED not set)"

        # Normalize BSSID to uppercase
        bssid = bssid.upper().strip()

        # Validate BSSID format
        if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', bssid):
            return False, f"Invalid BSSID format: {bssid}"

        # If no BSSID scope patterns defined, all BSSIDs are in scope
        if not self.wifi_bssid_scope:
            return True, "No BSSID restrictions (all in scope)"

        # Check against BSSID patterns
        for pattern in self.wifi_bssid_scope:
            if fnmatch.fnmatch(bssid, pattern):
                return True, f"BSSID {bssid} matches pattern {pattern}"

        return False, f"BSSID {bssid} not in Wi-Fi scope"

    def get_local_ips(self) -> Set[str]:
        """
        Get detected local IP addresses.

        Returns:
            Set of local IP address strings
        """
        return self._local_ips.copy()

    def get_all_targets(self) -> List[str]:
        """
        Get all explicitly defined targets.

        Returns:
            List of target strings
        """
        targets = []
        targets.extend([str(ip) for ip in self.included_ips])
        targets.extend([str(net) for net in self.included_ranges])
        targets.extend(self.included_domains)
        return targets

    def get_scope_summary(self) -> dict:
        """
        Get a summary of the scope configuration.

        Returns:
            Dictionary with scope statistics
        """
        return {
            "included_ranges": len(self.included_ranges),
            "included_ips": len(self.included_ips),
            "included_domains": len(self.included_domains),
            "excluded_ranges": len(self.excluded_ranges),
            "excluded_ips": len(self.excluded_ips),
            "total_targets": len(self.get_all_targets()),
            "wifi_allowed": self.wifi_allowed,
            "wifi_interface": self.wifi_interface if self.wifi_allowed else None,
            "wifi_bssid_patterns": len(self.wifi_bssid_scope),
            "local_ips_protected": len(self._local_ips),
        }

    def validate_multiple(self, targets: List[str]) -> dict:
        """
        Validate multiple targets at once.

        Args:
            targets: List of targets to validate

        Returns:
            Dictionary with in_scope and out_of_scope lists
        """
        in_scope = []
        out_of_scope = []

        for target in targets:
            is_valid, reason = self.is_in_scope(target)
            if is_valid:
                in_scope.append({"target": target, "reason": reason})
            else:
                out_of_scope.append({"target": target, "reason": reason})

        return {
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "total_checked": len(targets),
        }

    def expand_ranges(self, max_hosts: int = 1000) -> List[str]:
        """
        Expand CIDR ranges to individual IPs.

        Args:
            max_hosts: Maximum number of hosts to expand (safety limit)

        Returns:
            List of IP addresses

        Raises:
            ValueError: If expansion would exceed max_hosts
        """
        ips = []

        # Add explicitly included IPs
        ips.extend([str(ip) for ip in self.included_ips])

        # Expand ranges
        total_hosts = sum(range.num_addresses for range in self.included_ranges)

        if total_hosts > max_hosts:
            raise ValueError(
                f"Range expansion would produce {total_hosts} hosts "
                f"(max: {max_hosts}). Use targeted scanning instead."
            )

        for network in self.included_ranges:
            for ip in network.hosts():
                # Skip if in exclusion list
                if ip in self.excluded_ips:
                    continue
                if any(ip in excluded_range for excluded_range in self.excluded_ranges):
                    continue

                ips.append(str(ip))

        return ips

    def __str__(self) -> str:
        """String representation of scope."""
        summary = self.get_scope_summary()
        return (
            f"ScopeValidator("
            f"{summary['included_ranges']} ranges, "
            f"{summary['included_ips']} IPs, "
            f"{summary['included_domains']} domains, "
            f"{summary['excluded_ips']} excluded IPs)"
        )
