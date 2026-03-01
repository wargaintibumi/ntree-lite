"""
Interactive Tools Detection
Identifies security tools that may require user input and flags them for manual review
"""

import re
from typing import List, Dict, Optional
from .logger import get_logger

logger = get_logger(__name__)


# Known interactive tools and their problematic flags/patterns
INTERACTIVE_TOOLS = {
    # Enumeration tools
    # Note: enum4linux removed - NTREE uses alternative tools (smbclient, rpcclient, nmap)
    "rpcclient": {
        "description": "SMB RPC client",
        "interactive_without": ["-N", "-U"],
        "safe_flags": ["-N", "-U", "--no-pass"],
        "prompts_for": ["password", "input"]
    },
    "smbclient": {
        "description": "SMB file client",
        "interactive_without": ["-N", "-U"],
        "safe_flags": ["-N", "-U anonymous", "--no-pass"],
        "prompts_for": ["password"]
    },
    "mysql": {
        "description": "MySQL client",
        "interactive_without": ["-p", "--password="],
        "safe_flags": ["-p<password>", "--password=<password>"],
        "prompts_for": ["password"]
    },
    "psql": {
        "description": "PostgreSQL client",
        "interactive_without": ["PGPASSWORD", "-W"],
        "safe_flags": ["PGPASSWORD=", "--no-password"],
        "prompts_for": ["password"]
    },
    "ssh": {
        "description": "SSH client",
        "interactive_without": ["-o", "StrictHostKeyChecking"],
        "safe_flags": ["-o StrictHostKeyChecking=no", "-o BatchMode=yes"],
        "prompts_for": ["password", "yes/no", "passphrase"]
    },
    "ftp": {
        "description": "FTP client",
        "interactive_without": ["-n"],
        "safe_flags": ["-n"],
        "prompts_for": ["username", "password"]
    },
    "telnet": {
        "description": "Telnet client",
        "interactive_without": ["always_interactive"],
        "safe_flags": [],
        "prompts_for": ["username", "password", "input"]
    },
    "msfconsole": {
        "description": "Metasploit console",
        "interactive_without": ["-q", "-x"],
        "safe_flags": ["-q", "-x"],
        "prompts_for": ["msf>", "input"]
    },
    "sqlmap": {
        "description": "SQL injection tool",
        "interactive_without": ["--batch"],
        "safe_flags": ["--batch"],
        "prompts_for": ["[Y/n]", "[y/N]"]
    },
    "hydra": {
        "description": "Password cracker",
        "interactive_without": ["requires_wordlist"],
        "safe_flags": ["-L", "-P", "-l", "-p"],
        "prompts_for": []  # Doesn't prompt but may hang if misconfigured
    },
    "john": {
        "description": "John the Ripper",
        "interactive_without": [],
        "safe_flags": ["--wordlist="],
        "prompts_for": []
    },
    "ncrack": {
        "description": "Network authentication cracker",
        "interactive_without": [],
        "safe_flags": ["-U", "-P"],
        "prompts_for": []
    },
    "ldapsearch": {
        "description": "LDAP search tool",
        "interactive_without": ["-w", "-W"],
        "safe_flags": ["-w <password>", "-x"],
        "prompts_for": ["password"]
    },
    "crackmapexec": {
        "description": "Network authentication tool",
        "interactive_without": [],
        "safe_flags": ["-u", "-p", "--no-bruteforce"],
        "prompts_for": []
    },
    "evil-winrm": {
        "description": "WinRM shell",
        "interactive_without": ["always_interactive"],
        "safe_flags": ["-e"],  # Execute and exit
        "prompts_for": ["shell>", "input"]
    },
    "impacket": {
        "description": "Impacket tools (various)",
        "interactive_without": ["-no-pass"],
        "safe_flags": ["-no-pass", "-hashes"],
        "prompts_for": ["password"]
    },
    # Wi-Fi/Wireless tools
    "airmon-ng": {
        "description": "Wireless interface monitor mode manager",
        "interactive_without": [],
        "safe_flags": ["start", "stop", "check", "--verbose"],
        "prompts_for": []  # Non-interactive with proper subcommands
    },
    "airodump-ng": {
        "description": "Wireless network scanner",
        "interactive_without": ["requires_ctrl_c"],
        "safe_flags": ["--write", "-w", "--output-format"],
        "prompts_for": []  # Requires Ctrl+C to stop, use timeout wrapper
    },
    "wash": {
        "description": "WPS scanner",
        "interactive_without": [],
        "safe_flags": ["-i", "-C", "-s"],
        "prompts_for": []  # Non-interactive
    },
    "aireplay-ng": {
        "description": "Wireless injection tool (BLOCKED - deauth attacks)",
        "interactive_without": ["always_blocked"],
        "safe_flags": [],
        "prompts_for": ["deauth", "injection"]
    },
    "aircrack-ng": {
        "description": "Wireless key cracker (BLOCKED)",
        "interactive_without": ["always_blocked"],
        "safe_flags": [],
        "prompts_for": ["cracking"]
    },
    "reaver": {
        "description": "WPS brute force tool (BLOCKED)",
        "interactive_without": ["always_blocked"],
        "safe_flags": [],
        "prompts_for": ["brute force"]
    },
    "bully": {
        "description": "WPS brute force tool (BLOCKED)",
        "interactive_without": ["always_blocked"],
        "safe_flags": [],
        "prompts_for": ["brute force"]
    },
}


# Patterns that indicate a process is waiting for user input
INTERACTIVE_PATTERNS = [
    r"[Pp]ass(?:word|wd|phrase).*:",  # Matches "password:", "Password for user:", "Passwd:", "passphrase:"
    r"[Uu]sername.*:",
    r"[Ll]ogin.*:",
    r"\[Y/n\]",
    r"\[y/N\]",
    r"\[yes/no\]",
    r"Are you sure",
    r"Continue\?",
    r"Press .* to continue",
    r"Enter .*:",
    r">\s*$",  # Shell prompt
    r"#\s*$",  # Root prompt
    r"msf\d*>",  # Metasploit prompt
    r"\$\s*$",  # Shell prompt
]


def get_tool_name(command: str) -> Optional[str]:
    """
    Extract tool name from command string.

    Args:
        command: Full command string

    Returns:
        Tool name if found, None otherwise
    """
    # Split command and get first element
    parts = command.strip().split()
    if not parts:
        return None

    # Handle sudo prefix
    tool = parts[0]
    if tool == "sudo" and len(parts) > 1:
        tool = parts[1]

    # Get base tool name (remove path)
    tool_base = tool.split("/")[-1]

    # Check for exact match
    if tool_base in INTERACTIVE_TOOLS:
        return tool_base

    # Check for partial match (e.g., impacket-* tools)
    for known_tool in INTERACTIVE_TOOLS.keys():
        if tool_base.startswith(known_tool):
            return known_tool

    return None


def is_tool_interactive(command: str) -> Dict[str, any]:
    """
    Check if a command uses an interactive tool without proper flags.

    Args:
        command: Full command string

    Returns:
        Dict with:
        - is_interactive: bool
        - tool: str (tool name)
        - reason: str (why it's interactive)
        - safe_flags: list (flags that would make it non-interactive)
        - recommendation: str (what to do)
    """
    tool_name = get_tool_name(command)

    if not tool_name:
        return {
            "is_interactive": False,
            "tool": None,
            "reason": None,
            "safe_flags": [],
            "recommendation": None
        }

    tool_info = INTERACTIVE_TOOLS[tool_name]

    # Check if tool is always interactive
    if "always_interactive" in tool_info.get("interactive_without", []):
        return {
            "is_interactive": True,
            "tool": tool_name,
            "reason": f"{tool_info['description']} is always interactive",
            "safe_flags": tool_info.get("safe_flags", []),
            "recommendation": f"Tool {tool_name} requires manual interaction. Consider using alternative non-interactive tools.",
            "prompts_for": tool_info.get("prompts_for", [])
        }

    # Check if command has required safe flags
    safe_flags = tool_info.get("safe_flags", [])
    interactive_without = tool_info.get("interactive_without", [])

    # Check if safe flags are present using word-boundary matching
    # For tools with multiple interactive_without flags, ALL must be satisfied
    cmd_parts = command.split()
    has_safe_flag = False
    if safe_flags:
        flags_found = 0
        for flag in safe_flags:
            # Handle flags with placeholders like "-p<password>"
            flag_base = flag.split("<")[0].split("=")[0]
            # Match as whole token, not substring
            if any(part == flag_base or part.startswith(flag_base + "=") for part in cmd_parts):
                flags_found += 1
        # Require all interactive_without conditions to be satisfied
        flags_needed = len(interactive_without) if interactive_without else 1
        has_safe_flag = flags_found >= flags_needed

    if not has_safe_flag and interactive_without:
        return {
            "is_interactive": True,
            "tool": tool_name,
            "reason": f"{tool_info['description']} may prompt for: {', '.join(tool_info.get('prompts_for', ['input']))}",
            "safe_flags": safe_flags,
            "recommendation": f"Add one of these flags to make non-interactive: {', '.join(safe_flags)}",
            "prompts_for": tool_info.get("prompts_for", [])
        }

    return {
        "is_interactive": False,
        "tool": tool_name,
        "reason": None,
        "safe_flags": [],
        "recommendation": None
    }


def detect_interactive_prompt(output: str) -> Optional[Dict[str, str]]:
    """
    Detect if output contains an interactive prompt.

    Args:
        output: Command output (stdout/stderr)

    Returns:
        Dict with prompt info if detected, None otherwise
    """
    # Check last few lines of output
    lines = output.strip().split('\n')
    last_lines = lines[-5:] if len(lines) >= 5 else lines

    for line in last_lines:
        for pattern in INTERACTIVE_PATTERNS:
            if re.search(pattern, line):
                return {
                    "detected": True,
                    "pattern": pattern,
                    "line": line,
                    "recommendation": "Command appears to be waiting for user input. Manual review required."
                }

    return None


def get_safe_alternative(command: str) -> Optional[str]:
    """
    Get a safe non-interactive alternative for an interactive command.

    Args:
        command: Original command

    Returns:
        Modified safe command, or None if no safe alternative
    """
    tool_name = get_tool_name(command)

    if not tool_name or tool_name not in INTERACTIVE_TOOLS:
        return None

    tool_info = INTERACTIVE_TOOLS[tool_name]
    safe_flags = tool_info.get("safe_flags", [])

    if not safe_flags:
        return None

    # For tools with always_interactive, no safe alternative
    if "always_interactive" in tool_info.get("interactive_without", []):
        return None

    # Add all safe flags that don't require placeholders
    flags_to_add = []
    for flag in safe_flags:
        if "<" in flag:
            continue  # Can't automatically fill in passwords
        flags_to_add.append(flag)

    if not flags_to_add:
        return None

    # Find tool position in command
    parts = command.split()
    tool_index = 0
    for i, part in enumerate(parts):
        if part.endswith(tool_name) or part == tool_name:
            tool_index = i
            break

    # Insert all safe flags after tool name (in reverse to maintain order)
    for flag in reversed(flags_to_add):
        # Skip if flag already present
        if flag not in parts:
            parts.insert(tool_index + 1, flag)

    return " ".join(parts)


def should_skip_command(command: str) -> Dict[str, any]:
    """
    Determine if a command should be skipped due to interactive concerns.

    Args:
        command: Command to check

    Returns:
        Dict with skip decision and details
    """
    interactive_check = is_tool_interactive(command)

    if not interactive_check["is_interactive"]:
        return {
            "should_skip": False,
            "reason": None,
            "alternative": None
        }

    # Try to get safe alternative
    safe_cmd = get_safe_alternative(command)

    if safe_cmd:
        return {
            "should_skip": True,
            "reason": interactive_check["reason"],
            "alternative": safe_cmd,
            "recommendation": f"Use alternative: {safe_cmd}"
        }
    else:
        return {
            "should_skip": True,
            "reason": interactive_check["reason"],
            "alternative": None,
            "recommendation": interactive_check["recommendation"]
        }


# Add new interactive tools to the list
def register_interactive_tool(
    name: str,
    description: str,
    interactive_without: List[str],
    safe_flags: List[str],
    prompts_for: List[str]
):
    """
    Register a new interactive tool for detection.

    Args:
        name: Tool name
        description: Tool description
        interactive_without: Conditions that make it interactive
        safe_flags: Flags that make it non-interactive
        prompts_for: What it prompts for
    """
    INTERACTIVE_TOOLS[name] = {
        "description": description,
        "interactive_without": interactive_without,
        "safe_flags": safe_flags,
        "prompts_for": prompts_for
    }
    logger.info(f"Registered interactive tool: {name}")
