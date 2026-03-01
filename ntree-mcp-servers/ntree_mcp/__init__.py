"""
NTREE MCP Servers
Model Context Protocol servers for penetration testing automation
"""

__version__ = "2.1.0"
__author__ = "NTREE Project"

from . import utils

# MCP Server modules
AVAILABLE_SERVERS = [
    "scope",      # Scope management and finding storage
    "scan",       # Network scanning with nmap/masscan/nuclei
    "enum",       # Service enumeration
    "vuln",       # Vulnerability testing
    "report",     # Report generation
]

__all__ = ["utils", "AVAILABLE_SERVERS"]
