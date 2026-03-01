#!/usr/bin/env python3
"""
NTREE Live Monitor - Real-time penetration test progress viewer

This script monitors NTREE pentest progress without affecting the running test
or consuming any Claude API quota. It watches:
- Agent logs for iteration progress
- Assessment directories for new findings/scans
- State changes and discovered assets
- Automatically switches to new assessments when started
- Memory usage (optional, useful for Pi 5)

Usage:
    ./ntree_monitor.py                      # Auto-detect and follow new assessments
    ./ntree_monitor.py --assessment assess_20260110_123456
    ./ntree_monitor.py --log-only           # Only show log output
    ./ntree_monitor.py --findings-only      # Only show new findings
    ./ntree_monitor.py --no-follow          # Don't auto-switch to new assessments
    ./ntree_monitor.py --show-memory        # Include memory stats (Pi 5)
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Set, Any, Tuple
import signal

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    WHITE = '\033[1;37m'
    GRAY = '\033[0;90m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'
    # ANSI escape sequences for cursor/line control
    CLEAR_LINE = '\033[2K'  # Clear entire line
    CURSOR_UP = '\033[1A'   # Move cursor up one line


def colored(text: str, color: str) -> str:
    """Wrap text in color codes."""
    return f"{color}{text}{Colors.NC}"


def print_banner():
    """Print monitor banner."""
    print(colored("""
╔═══════════════════════════════════════════════════════════════════╗
║                  NTREE LIVE MONITOR v1.1                          ║
║              Real-time Penetration Test Viewer                    ║
║           (Auto-follows new assessments by default)               ║
╚═══════════════════════════════════════════════════════════════════╝
""", Colors.CYAN))


def format_timestamp(ts: str) -> str:
    """Format ISO timestamp to readable format."""
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime('%H:%M:%S')
    except:
        return ts[:19] if len(ts) > 19 else ts


class NTREEMonitor:
    """Live monitor for NTREE penetration tests."""

    def __init__(self, ntree_home: str = None, assessment_id: str = None, follow_new: bool = True, show_memory: bool = False):
        _script_dir = str(Path(__file__).resolve().parent)
        self.ntree_home = Path(ntree_home or os.getenv("NTREE_HOME", _script_dir)).expanduser()
        self.logs_dir = self.ntree_home / "logs"
        self.assessments_dir = self.ntree_home / "assessments"

        self.assessment_id = assessment_id
        self.assessment_dir: Optional[Path] = None
        self.assessment_mtime: float = 0  # Track assessment creation time
        self.fixed_assessment = assessment_id is not None  # User specified specific assessment
        self.follow_new = follow_new and not self.fixed_assessment  # Auto-follow new assessments

        # Memory monitoring
        self.show_memory = show_memory
        self.memory_warn_threshold_mb = 1000
        self.memory_critical_threshold_mb = 500

        # Tracking state
        self.last_log_position = 0
        self.seen_findings: Set[str] = set()
        self.seen_scans: Set[str] = set()
        self.last_state_hash: Optional[str] = None
        self.last_iteration = 0

        # Stats
        self.stats = {
            "iterations": 0,
            "findings": 0,
            "scans": 0,
            "targets": 0,  # Target count from scope
            "services": 0,
            "start_time": None,
            "report_generated": False,
            "report_path": None
        }

        self.running = True

        # Check if output is a TTY (terminal) - if not, skip status line operations
        self.is_tty = sys.stdout.isatty()

    def find_latest_assessment(self) -> Optional[Path]:
        """Find the most recent assessment directory."""
        if not self.assessments_dir.exists():
            return None

        # Find all valid assessment directories (contain state.json or scope.txt)
        assessment_dirs = [
            d for d in self.assessments_dir.iterdir()
            if d.is_dir() and (
                (d / "state.json").exists() or
                (d / "scope.txt").exists()
            )
        ]

        if not assessment_dirs:
            return None

        # Sort by modification time, newest first
        assessment_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        return assessment_dirs[0]

    def count_scope_targets(self) -> int:
        """Count targets defined in scope.txt."""
        if not self.assessment_dir:
            return 0

        scope_file = self.assessment_dir / "scope.txt"
        if not scope_file.exists():
            return 0

        target_count = 0
        try:
            with open(scope_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Count CIDR ranges (e.g., 192.168.1.0/24)
                    if '/' in line:
                        try:
                            # Extract subnet size from CIDR
                            parts = line.split('/')
                            if len(parts) == 2:
                                prefix_len = int(parts[1])
                                # Calculate number of hosts in subnet (2^(32-prefix) - 2 for network/broadcast)
                                hosts = 2 ** (32 - prefix_len) - 2
                                target_count += max(1, hosts)  # At least count as 1
                        except:
                            target_count += 1

                    # Count IP ranges (e.g., 192.168.1.1-50)
                    elif '-' in line and '.' in line:
                        try:
                            # Extract range (e.g., 192.168.1.1-50)
                            parts = line.split('.')
                            if len(parts) == 4:
                                last_octet = parts[3]
                                if '-' in last_octet:
                                    range_parts = last_octet.split('-')
                                    if len(range_parts) == 2:
                                        start = int(range_parts[0])
                                        end = int(range_parts[1])
                                        target_count += (end - start + 1)
                                    else:
                                        target_count += 1
                                else:
                                    target_count += 1
                            else:
                                target_count += 1
                        except:
                            target_count += 1

                    # Count individual IPs or hostnames
                    else:
                        target_count += 1
        except Exception as e:
            pass

        return target_count

    def setup_assessment(self, silent: bool = False) -> bool:
        """Setup assessment directory to monitor."""
        if self.fixed_assessment and self.assessment_id:
            self.assessment_dir = self.assessments_dir / self.assessment_id
            if not self.assessment_dir.exists():
                print(colored(f"[ERROR] Assessment not found: {self.assessment_id}", Colors.RED))
                return False
        else:
            self.assessment_dir = self.find_latest_assessment()
            if not self.assessment_dir:
                if not silent:
                    print(colored("[WARN] No assessment found yet. Waiting...", Colors.YELLOW))
                return False
            self.assessment_id = self.assessment_dir.name

        # Track assessment creation time
        self.assessment_mtime = self.assessment_dir.stat().st_mtime

        # Count targets from scope
        self.stats["targets"] = self.count_scope_targets()

        if not silent:
            print(colored(f"[*] Monitoring assessment: {self.assessment_id}", Colors.GREEN))
            print(colored(f"[*] Directory: {self.assessment_dir}", Colors.GRAY))
            print(colored(f"[*] Targets in scope: {self.stats['targets']}", Colors.GRAY))
            if self.follow_new:
                print(colored("[*] Auto-follow enabled: will switch to new assessments", Colors.GRAY))
        return True

    def reset_tracking_state(self):
        """Reset all tracking state when switching to new assessment."""
        self.seen_findings.clear()
        self.seen_scans.clear()
        self.last_state_hash = None
        self.last_iteration = 0
        self.stats = {
            "iterations": 0,
            "findings": 0,
            "scans": 0,
            "targets": 0,
            "services": 0,
            "start_time": datetime.now(),
            "report_generated": False,
            "report_path": None
        }

    def check_for_new_assessment(self) -> Optional[Path]:
        """Check if a newer assessment exists."""
        if not self.follow_new:
            return None

        latest = self.find_latest_assessment()
        if not latest:
            return None

        # Check if this is a newer assessment
        latest_mtime = latest.stat().st_mtime
        if latest_mtime > self.assessment_mtime and latest.name != self.assessment_id:
            return latest

        return None

    def clear_screen(self):
        """Clear the terminal screen."""
        if self.is_tty:
            print("\033[2J\033[H", end="", flush=True)

    def switch_to_assessment(self, new_assessment: Path):
        """Switch monitoring to a new assessment."""
        old_id = self.assessment_id

        # Reset state
        self.reset_tracking_state()

        # Setup new assessment
        self.assessment_id = new_assessment.name
        self.assessment_dir = new_assessment
        self.assessment_mtime = new_assessment.stat().st_mtime

        # Count targets from new scope
        self.stats["targets"] = self.count_scope_targets()

        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Clear screen and announce the new assessment
        self.clear_screen()
        print_banner()
        print(colored(f"{'='*60}", Colors.GREEN))
        print(colored(f"[NEW ASSESSMENT DETECTED]", Colors.GREEN + Colors.BOLD))
        print(colored(f"{'='*60}", Colors.GREEN))
        print(colored(f"  Started at:      {start_time}", Colors.CYAN))
        print(colored(f"  Previous:        {old_id}", Colors.GRAY))
        print(colored(f"  Switching to:    {self.assessment_id}", Colors.GREEN))
        print(colored(f"  Directory:       {self.assessment_dir}", Colors.GRAY))
        print(colored(f"  Targets in scope: {self.stats['targets']}", Colors.GRAY))
        print(colored(f"{'='*60}", Colors.GREEN))

    def get_memory_stats(self) -> Tuple[int, int, int]:
        """Get memory statistics: (total_mb, used_mb, available_mb)."""
        try:
            result = subprocess.run(
                ["free", "-m"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('Mem:'):
                        parts = line.split()
                        total = int(parts[1])
                        used = int(parts[2])
                        available = int(parts[6]) if len(parts) > 6 else total - used
                        return (total, used, available)
        except Exception:
            pass
        return (0, 0, 0)

    def get_top_memory_processes(self, limit: int = 5) -> list:
        """Get top memory consuming processes."""
        processes = []
        try:
            result = subprocess.run(
                ["ps", "aux", "--sort=-%mem"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:limit+1]  # Skip header
                for line in lines:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            "user": parts[0],
                            "mem_pct": parts[3],
                            "mem_kb": int(parts[5]) if parts[5].isdigit() else 0,
                            "command": parts[10][:50]
                        })
        except Exception:
            pass
        return processes

    def get_ntree_processes(self) -> list:
        """Get NTREE-related processes."""
        processes = []
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if any(tool in line.lower() for tool in ['ntree', 'nmap', 'masscan', 'nikto', 'nuclei']):
                        if 'grep' not in line:
                            parts = line.split(None, 10)
                            if len(parts) >= 11:
                                processes.append({
                                    "user": parts[0],
                                    "mem_pct": parts[3],
                                    "mem_kb": int(parts[5]) if parts[5].isdigit() else 0,
                                    "command": parts[10][:50]
                                })
        except Exception:
            pass
        return processes

    def format_memory_display(self) -> list:
        """Format memory status for display."""
        lines = []
        total, used, available = self.get_memory_stats()

        if total == 0:
            return [f"{Colors.YELLOW}[MEM] Unable to read memory stats{Colors.NC}"]

        # Memory bar
        used_pct = (used / total) * 100 if total > 0 else 0
        bar_width = 30
        filled = int((used_pct / 100) * bar_width)
        bar = '█' * filled + '░' * (bar_width - filled)

        # Color based on available memory
        if available < self.memory_critical_threshold_mb:
            color = Colors.RED
            status = "CRITICAL"
        elif available < self.memory_warn_threshold_mb:
            color = Colors.YELLOW
            status = "LOW"
        else:
            color = Colors.GREEN
            status = "OK"

        lines.append(f"{color}[MEM {status}]{Colors.NC} [{bar}] {used_pct:.1f}% | Available: {available}MB / {total}MB")

        if available < self.memory_critical_threshold_mb:
            lines.append(f"{Colors.RED}  ⚠ CRITICAL: System may crash! Consider stopping scans.{Colors.NC}")

        # Show NTREE processes if memory is concerning
        if available < self.memory_warn_threshold_mb or self.show_memory:
            ntree_procs = self.get_ntree_processes()
            if ntree_procs:
                lines.append(f"{Colors.CYAN}  NTREE Processes:{Colors.NC}")
                for proc in ntree_procs[:3]:
                    mem_mb = proc['mem_kb'] / 1024
                    lines.append(f"    {proc['mem_pct']}% {mem_mb:.1f}MB {proc['command']}")

        return lines

    def print_status_line(self):
        """Print current status summary line (only on TTY)."""
        # Skip status line updates when not on a TTY (e.g., output redirected to file)
        if not self.is_tty:
            return

        elapsed = ""
        if self.stats["start_time"]:
            delta = datetime.now() - self.stats["start_time"]
            minutes = int(delta.total_seconds() // 60)
            seconds = int(delta.total_seconds() % 60)
            elapsed = f"{minutes}m{seconds}s"

        # Add memory info if enabled
        mem_str = ""
        if self.show_memory:
            _, _, available = self.get_memory_stats()
            if available < self.memory_critical_threshold_mb:
                mem_str = f" | {Colors.RED}Mem:{available}MB{Colors.NC}"
            elif available < self.memory_warn_threshold_mb:
                mem_str = f" | {Colors.YELLOW}Mem:{available}MB{Colors.NC}"
            else:
                mem_str = f" | {Colors.GREEN}Mem:{available}MB{Colors.NC}"

        status = (
            f"{Colors.GRAY}[{elapsed}]{Colors.NC} "
            f"{Colors.CYAN}Iter:{self.stats['iterations']}{Colors.NC} | "
            f"{Colors.RED}Findings:{self.stats['findings']}{Colors.NC} | "
            f"{Colors.BLUE}Scans:{self.stats['scans']}{Colors.NC} | "
            f"{Colors.GREEN}Targets:{self.stats['targets']}{Colors.NC} | "
            f"{Colors.YELLOW}Services:{self.stats['services']}{Colors.NC}"
            f"{mem_str}"
        )
        # Use ANSI escape to clear line properly (works better than spaces)
        # \r moves to start of line, \033[2K clears entire line
        print(f"\r{Colors.CLEAR_LINE}{status}", end="", flush=True)

    def watch_log_file(self) -> list:
        """Watch agent log file for new entries."""
        log_file = self.logs_dir / "ntree_agent.log"
        new_lines = []

        if not log_file.exists():
            return new_lines

        try:
            with open(log_file, 'r') as f:
                f.seek(self.last_log_position)
                new_content = f.read()
                self.last_log_position = f.tell()

                if new_content:
                    # Filter out empty lines
                    new_lines = [line for line in new_content.split('\n') if line.strip()]
        except Exception as e:
            pass

        return new_lines

    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line and extract relevant info."""
        if not line.strip():
            return None

        # Extract timestamp and message
        parts = line.split(' - ', 2)
        if len(parts) < 3:
            return None

        timestamp = parts[0]
        level_module = parts[1]
        message = parts[2] if len(parts) > 2 else ""

        # Detect iteration changes
        if "ITERATION" in message:
            try:
                # Extract iteration number
                import re
                match = re.search(r'ITERATION (\d+)/(\d+)', message)
                if match:
                    return {
                        "type": "iteration",
                        "current": int(match.group(1)),
                        "max": int(match.group(2)),
                        "timestamp": timestamp
                    }
            except:
                pass

        # Detect tool calls
        if "Tool called:" in message:
            tool_name = message.split("Tool called:")[-1].strip()
            return {
                "type": "tool_call",
                "tool": tool_name,
                "timestamp": timestamp
            }

        # Detect completion
        if "PENETRATION TEST COMPLETE" in message:
            return {
                "type": "complete",
                "timestamp": timestamp
            }

        # Detect new pentest start
        if "STARTING AUTONOMOUS PENETRATION TEST" in message:
            return {
                "type": "new_pentest",
                "timestamp": timestamp
            }

        # Detect errors
        if "ERROR" in level_module or "error" in message.lower():
            return {
                "type": "error",
                "message": message,
                "timestamp": timestamp
            }

        # Detect collected responses
        if "Collected" in message and "text blocks" in message:
            return {
                "type": "response",
                "message": message,
                "timestamp": timestamp
            }

        return None

    def check_new_findings(self) -> list:
        """Check for new findings in assessment directory."""
        new_findings = []

        if not self.assessment_dir:
            return new_findings

        findings_dir = self.assessment_dir / "findings"
        if not findings_dir.exists():
            return new_findings

        for finding_file in findings_dir.glob("*.json"):
            if finding_file.name not in self.seen_findings:
                self.seen_findings.add(finding_file.name)
                try:
                    with open(finding_file) as f:
                        finding = json.load(f)
                        new_findings.append(finding)
                except:
                    pass

        return new_findings

    def check_new_scans(self) -> list:
        """Check for new scan files."""
        new_scans = []

        if not self.assessment_dir:
            return new_scans

        scans_dir = self.assessment_dir / "scans"
        if not scans_dir.exists():
            return new_scans

        for scan_file in scans_dir.iterdir():
            if scan_file.name not in self.seen_scans:
                self.seen_scans.add(scan_file.name)
                new_scans.append({
                    "filename": scan_file.name,
                    "size": scan_file.stat().st_size,
                    "modified": datetime.fromtimestamp(scan_file.stat().st_mtime)
                })

        return new_scans

    def check_for_report(self) -> Optional[str]:
        """Check if report has been generated."""
        if not self.assessment_dir or self.stats["report_generated"]:
            return None

        reports_dir = self.assessment_dir / "reports"
        if not reports_dir.exists():
            return None

        # Look for comprehensive HTML report (primary report)
        html_reports = list(reports_dir.glob("comprehensive_report.html"))
        if html_reports:
            report_path = html_reports[0]
            self.stats["report_generated"] = True
            self.stats["report_path"] = str(report_path)
            return str(report_path)

        # Also check for any HTML reports
        html_reports = list(reports_dir.glob("*.html"))
        if html_reports:
            report_path = html_reports[0]
            self.stats["report_generated"] = True
            self.stats["report_path"] = str(report_path)
            return str(report_path)

        return None

    def check_state_changes(self) -> Optional[Dict]:
        """Check for state.json changes."""
        if not self.assessment_dir:
            return None

        state_file = self.assessment_dir / "state.json"
        if not state_file.exists():
            return None

        try:
            with open(state_file) as f:
                content = f.read()
                state = json.load(f) if content else {}

            # Simple hash to detect changes
            current_hash = str(hash(content))
            if current_hash != self.last_state_hash:
                self.last_state_hash = current_hash
                return state
        except:
            pass

        return None

    def format_finding(self, finding: Dict) -> str:
        """Format a finding for display."""
        severity = finding.get("severity", "unknown").upper()
        severity_colors = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.BLUE,
            "INFO": Colors.GRAY
        }
        color = severity_colors.get(severity, Colors.WHITE)

        title = finding.get("title", "Unknown Finding")
        hosts = finding.get("affected_hosts", [])
        cvss = finding.get("cvss_score", "N/A")

        lines = []
        lines.append(f"{color}{'='*60}{Colors.NC}")
        lines.append(f"{color}[{severity}]{Colors.NC} {Colors.BOLD}{title}{Colors.NC}")
        lines.append(f"{color}{'='*60}{Colors.NC}")

        if hosts:
            host_str = f"  {Colors.CYAN}Affected:{Colors.NC} {', '.join(hosts[:5])}"
            if len(hosts) > 5:
                host_str += f" (+{len(hosts)-5} more)"
            lines.append(host_str)

        if cvss != "N/A":
            lines.append(f"  {Colors.CYAN}CVSS:{Colors.NC} {cvss}")

        desc = finding.get("description", "")
        if desc:
            # Truncate long descriptions
            if len(desc) > 200:
                desc = desc[:200] + "..."
            lines.append(f"  {Colors.GRAY}{desc}{Colors.NC}")

        return "\n".join(lines)

    def format_scan(self, scan: Dict) -> str:
        """Format a scan file notification."""
        size_kb = scan["size"] / 1024
        time_str = scan["modified"].strftime("%H:%M:%S")
        return f"  {Colors.BLUE}[SCAN]{Colors.NC} {scan['filename']} ({size_kb:.1f}KB) @ {time_str}"

    async def monitor_loop(self, log_only: bool = False, findings_only: bool = False):
        """Main monitoring loop."""
        print(colored("\n[*] Starting live monitor (Ctrl+C to stop)...\n", Colors.GREEN))
        self.stats["start_time"] = datetime.now()

        # Initial status
        self.print_status_line()

        check_interval = 1.0  # seconds

        while self.running:
            try:
                output_lines = []

                # Check log file
                if not findings_only:
                    new_log_lines = self.watch_log_file()
                    for line in new_log_lines:
                        parsed = self.parse_log_line(line)
                        if parsed:
                            if parsed["type"] == "iteration":
                                self.stats["iterations"] = parsed["current"]
                                if parsed["current"] > self.last_iteration:
                                    self.last_iteration = parsed["current"]
                                    output_lines.append(
                                        f"{Colors.CYAN}[ITERATION {parsed['current']}/{parsed['max']}]{Colors.NC}"
                                    )

                            elif parsed["type"] == "tool_call":
                                output_lines.append(
                                    f"  {Colors.MAGENTA}[TOOL]{Colors.NC} {parsed['tool']}"
                                )

                            elif parsed["type"] == "complete":
                                output_lines.append(f"{Colors.GREEN}{'='*60}{Colors.NC}")
                                output_lines.append(f"{Colors.GREEN}[COMPLETE] Penetration test finished!{Colors.NC}")
                                output_lines.append(f"{Colors.GREEN}{'='*60}{Colors.NC}")

                            elif parsed["type"] == "new_pentest":
                                start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                self.clear_screen()
                                print_banner()
                                print(colored(f"{'='*60}", Colors.CYAN))
                                print(colored(f"[NEW PENTEST] Starting autonomous penetration test...", Colors.CYAN + Colors.BOLD))
                                print(colored(f"  Started at: {start_time}", Colors.CYAN))
                                print(colored(f"{'='*60}", Colors.CYAN))
                                # Check for new assessment shortly after
                                await asyncio.sleep(2)

                            elif parsed["type"] == "error":
                                output_lines.append(
                                    f"  {Colors.RED}[ERROR]{Colors.NC} {parsed['message'][:100]}"
                                )

                            elif parsed["type"] == "response":
                                output_lines.append(
                                    f"  {Colors.GRAY}[RESPONSE]{Colors.NC} {parsed['message']}"
                                )

                # Check for assessment if not set
                if not self.assessment_dir:
                    if self.setup_assessment(silent=True):
                        output_lines.append(
                            f"{Colors.GREEN}[*] Now monitoring: {self.assessment_id}{Colors.NC}"
                        )

                # Check for new assessment (auto-follow)
                if self.follow_new and self.assessment_dir:
                    new_assessment = self.check_for_new_assessment()
                    if new_assessment:
                        self.switch_to_assessment(new_assessment)

                # Check findings
                if not log_only:
                    new_findings = self.check_new_findings()
                    for finding in new_findings:
                        self.stats["findings"] += 1
                        output_lines.append(self.format_finding(finding))

                # Check scans
                if not log_only and not findings_only:
                    new_scans = self.check_new_scans()
                    for scan in new_scans:
                        self.stats["scans"] += 1
                        output_lines.append(self.format_scan(scan))

                # Check for report generation
                if not log_only and not findings_only:
                    report_path = self.check_for_report()
                    if report_path:
                        output_lines.append(f"{Colors.GREEN}{'='*60}{Colors.NC}")
                        output_lines.append(f"{Colors.GREEN}[REPORT GENERATED]{Colors.NC}")
                        output_lines.append(f"{Colors.GREEN}{'='*60}{Colors.NC}")
                        output_lines.append(f"  {Colors.CYAN}Location:{Colors.NC} {report_path}")
                        output_lines.append(f"  {Colors.GRAY}Open with:{Colors.NC} xdg-open {report_path}")
                        output_lines.append(f"{Colors.GREEN}{'='*60}{Colors.NC}")

                # Show memory stats periodically (every 10 iterations = ~10 seconds)
                if self.show_memory and hasattr(self, '_memory_counter'):
                    self._memory_counter += 1
                    if self._memory_counter >= 10:
                        self._memory_counter = 0
                        mem_lines = self.format_memory_display()
                        output_lines.extend(mem_lines)
                elif self.show_memory:
                    self._memory_counter = 0

                # Check state changes (track services and phase)
                if not log_only and not findings_only:
                    state = self.check_state_changes()
                    if state:
                        assets = state.get("discovered_assets", {})
                        services = assets.get("services", [])

                        # Update service count
                        if len(services) != self.stats["services"]:
                            new_services = len(services) - self.stats["services"]
                            old_count = self.stats["services"]
                            self.stats["services"] = len(services)
                            if new_services > 0:
                                output_lines.append(
                                    f"  {Colors.YELLOW}[SERVICES]{Colors.NC} +{new_services} found (total: {len(services)})"
                                )

                        phase = state.get("phase", "")
                        if phase:
                            output_lines.append(
                                f"  {Colors.CYAN}[PHASE]{Colors.NC} {phase}"
                            )

                    # Force stats refresh every loop iteration
                    # This ensures the status line stays updated even if no events occurred
                    else:
                        # Try to read state file directly to ensure stats are current
                        if self.assessment_dir:
                            state_file = self.assessment_dir / "state.json"
                            if state_file.exists():
                                try:
                                    with open(state_file) as f:
                                        state = json.load(f)
                                        assets = state.get("discovered_assets", {})
                                        self.stats["services"] = len(assets.get("services", []))
                                except:
                                    pass

                # Print output
                if output_lines:
                    # Clear status line before printing new output (only on TTY)
                    if self.is_tty:
                        print(f"\r{Colors.CLEAR_LINE}", end="", flush=True)

                    # ANSI escape pattern for stripping color codes
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

                    # Collect all non-empty lines first
                    lines_to_print = []
                    for item in output_lines:
                        if not item:
                            continue
                        # Handle multi-line strings (e.g., from format_finding)
                        for line in item.split('\n'):
                            # Strip ANSI codes for empty check but print original
                            stripped = ansi_escape.sub('', line)
                            # Only include if there's actual visible content
                            if stripped.strip():
                                lines_to_print.append(line)

                    # Print all collected lines
                    for line in lines_to_print:
                        print(line)

                    self.print_status_line()
                else:
                    # Even if no events, refresh the status line to show elapsed time
                    self.print_status_line()

                await asyncio.sleep(check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"\n{Colors.RED}[ERROR] {e}{Colors.NC}")
                await asyncio.sleep(check_interval)

    def stop(self):
        """Stop the monitor."""
        self.running = False


def main():
    parser = argparse.ArgumentParser(
        description="NTREE Live Monitor - Real-time penetration test viewer"
    )
    parser.add_argument(
        "--assessment", "-e",
        help="Specific assessment ID to monitor (default: latest)"
    )
    parser.add_argument(
        "--home",
        help="NTREE home directory (default: script directory or $NTREE_HOME)"
    )
    parser.add_argument(
        "--log-only", "-l",
        action="store_true",
        help="Only show log output, no findings/scans"
    )
    parser.add_argument(
        "--findings-only", "-f",
        action="store_true",
        help="Only show new findings"
    )
    parser.add_argument(
        "--no-follow",
        action="store_true",
        help="Don't auto-switch to new assessments"
    )
    parser.add_argument(
        "--show-memory", "-m",
        action="store_true",
        help="Show memory usage stats (useful for Pi 5)"
    )

    args = parser.parse_args()

    print_banner()

    monitor = NTREEMonitor(
        ntree_home=args.home,
        assessment_id=args.assessment,
        follow_new=not args.no_follow,
        show_memory=args.show_memory
    )

    # Setup signal handler
    def signal_handler(sig, frame):
        # Clear status line and print exit message
        if monitor.is_tty:
            print(f"\r{Colors.CLEAR_LINE}", end="")
        print(colored("\n[*] Stopping monitor...", Colors.YELLOW))
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Try to setup assessment
    monitor.setup_assessment()

    # Run monitor
    try:
        asyncio.run(monitor.monitor_loop(
            log_only=args.log_only,
            findings_only=args.findings_only
        ))
    except KeyboardInterrupt:
        pass

    # Print final stats - clear any remaining status line first
    if monitor.is_tty:
        print(f"\r{Colors.CLEAR_LINE}", end="")
    print(colored("\n[*] Final Statistics:", Colors.CYAN))
    print(f"  Iterations: {monitor.stats['iterations']}")
    print(f"  Findings:   {monitor.stats['findings']}")
    print(f"  Scans:      {monitor.stats['scans']}")
    print(f"  Targets:    {monitor.stats['targets']}")
    print(f"  Services:   {monitor.stats['services']}")

    if monitor.stats["start_time"]:
        elapsed = datetime.now() - monitor.stats["start_time"]
        print(f"  Duration:   {int(elapsed.total_seconds())}s")

    if monitor.stats.get("report_generated") and monitor.stats.get("report_path"):
        print(colored(f"\n[*] Report Generated:", Colors.GREEN))
        print(f"  {monitor.stats['report_path']}")
        print(f"  {colored('Open with:', Colors.GRAY)} xdg-open {monitor.stats['report_path']}")


if __name__ == "__main__":
    main()
