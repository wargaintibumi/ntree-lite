"""
NTREE Audit Logger
Comprehensive logging for full audit trail of penetration testing activities.

Logs include:
- Tool invocations and outputs
- Prompts sent to Claude
- Responses received
- Errors and exceptions
- Session metadata
- Timing information
"""

import json
import os
import sys
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from enum import Enum
import threading
import hashlib
import uuid
import gzip
import shutil


class AuditEventType(Enum):
    """Types of audit events"""
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    TOOL_CALL = "tool_call"
    TOOL_OUTPUT = "tool_output"
    TOOL_ERROR = "tool_error"
    PROMPT_SENT = "prompt_sent"
    RESPONSE_RECEIVED = "response_received"
    SCOPE_VALIDATION = "scope_validation"
    FINDING_SAVED = "finding_saved"
    COMMAND_EXECUTED = "command_executed"
    COMMAND_OUTPUT = "command_output"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    PHASE_CHANGE = "phase_change"
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    ASSESSMENT_INIT = "assessment_init"
    ASSESSMENT_COMPLETE = "assessment_complete"
    REPORT_GENERATED = "report_generated"


class AuditLogger:
    """
    Central audit logger for NTREE.

    Creates structured JSON logs for complete audit trail.
    Supports session-based logging, log rotation, and compression.

    Uses environment variables to share session ID across processes:
    - NTREE_AUDIT_SESSION_ID: Shared session ID for all processes
    - NTREE_AUDIT_ASSESSMENT_ID: Assessment ID for log file naming
    """

    _instance = None
    _lock = threading.Lock()
    _file_lock = threading.Lock()  # Lock for file writes

    def __new__(cls, *args, **kwargs):
        """Singleton pattern for global audit logger"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        log_dir: Optional[str] = None,
        session_id: Optional[str] = None,
        assessment_id: Optional[str] = None,
        max_log_size_mb: int = 100,
        compress_old_logs: bool = True,
        console_output: bool = False
    ):
        """
        Initialize the audit logger.

        Args:
            log_dir: Directory for log files (default: ~/ntree/logs/audit)
            session_id: Unique session identifier (auto-generated if not provided)
            assessment_id: Assessment ID to associate with logs
            max_log_size_mb: Maximum log file size before rotation
            compress_old_logs: Whether to gzip old log files
            console_output: Whether to also output to console
        """
        if self._initialized:
            return

        self._initialized = True

        # Set up paths
        self.log_dir = Path(log_dir or os.path.expanduser("~/ntree/logs/audit"))

        # Check for shared session ID from environment (for cross-process logging)
        env_session_id = os.environ.get("NTREE_AUDIT_SESSION_ID")
        env_assessment_id = os.environ.get("NTREE_AUDIT_ASSESSMENT_ID")

        # Use environment variables if available, otherwise use provided or generate
        self.session_id = env_session_id or session_id or self._generate_session_id()
        self.assessment_id = env_assessment_id or assessment_id

        # If assessment_id is known, use assessment-local log directory
        if self.assessment_id:
            ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
            assessment_log_dir = ntree_home / "assessments" / self.assessment_id / "logs"
            if assessment_log_dir.parent.exists():
                assessment_log_dir.mkdir(parents=True, exist_ok=True)
                self.log_dir = assessment_log_dir

        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_start = datetime.now()

        # Track if we're the primary (SDK) or secondary (MCP server) process
        self.is_primary = env_session_id is None

        # Configuration
        self.max_log_size_bytes = max_log_size_mb * 1024 * 1024
        self.compress_old_logs = compress_old_logs
        self.console_output = console_output

        # Log files - use assessment_id if available for unified logging
        if self.assessment_id:
            self.session_log_file = self.log_dir / f"assessment_{self.assessment_id}.jsonl"
        else:
            self.session_log_file = self.log_dir / f"session_{self.session_id}.jsonl"
        self.current_log_file = self.log_dir / "current_session.jsonl"

        # If primary process, set environment variables for MCP servers
        if self.is_primary:
            os.environ["NTREE_AUDIT_SESSION_ID"] = self.session_id
            if self.assessment_id:
                os.environ["NTREE_AUDIT_ASSESSMENT_ID"] = self.assessment_id

        # Statistics
        self.stats = {
            "tools_called": 0,
            "commands_executed": 0,
            "errors": 0,
            "warnings": 0,
            "findings_saved": 0,
            "prompts_sent": 0,
            "responses_received": 0
        }

        # Tool call tracking for timing
        self._pending_tool_calls: Dict[str, datetime] = {}

        # Command type mapping: command_id -> command binary name
        self._command_type_map: Dict[str, str] = {}

        # Initialize session
        self._log_session_start()

        # Set up Python logging integration
        self._setup_python_logging()

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = uuid.uuid4().hex[:8]
        return f"{timestamp}_{random_suffix}"

    def _setup_python_logging(self):
        """Set up Python logging to also write to audit log"""
        self.python_logger = logging.getLogger("ntree.audit")
        self.python_logger.setLevel(logging.DEBUG)

        # Create handler that writes to audit log
        class AuditHandler(logging.Handler):
            def __init__(self, audit_logger):
                super().__init__()
                self.audit_logger = audit_logger

            def emit(self, record):
                try:
                    self.audit_logger.log_event(
                        event_type=AuditEventType.INFO if record.levelno < logging.WARNING
                                   else AuditEventType.WARNING if record.levelno < logging.ERROR
                                   else AuditEventType.ERROR,
                        message=record.getMessage(),
                        data={
                            "logger": record.name,
                            "level": record.levelname,
                            "module": record.module,
                            "line": record.lineno
                        }
                    )
                except Exception:
                    pass

        self.python_logger.addHandler(AuditHandler(self))

    def _write_log_entry(self, entry: Dict[str, Any]):
        """Write a log entry to the log files with cross-process file locking"""
        import fcntl

        # Lazy assessment ID discovery for MCP server subprocesses.
        # MCP servers start before init_assessment runs, so they miss the env var.
        # Check env var first (fast), then marker file (filesystem).
        if not self.assessment_id:
            env_id = os.environ.get("NTREE_AUDIT_ASSESSMENT_ID")
            if env_id:
                self.set_assessment_id(env_id)
            else:
                try:
                    ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
                    marker = ntree_home / "current_assessment.txt"
                    if marker.exists():
                        aid = marker.read_text().strip()
                        if aid:
                            self.set_assessment_id(aid)
                except Exception:
                    pass

        try:
            # Add process info for debugging cross-process logging
            entry["_process_id"] = os.getpid()
            entry["_is_primary"] = self.is_primary

            log_line = json.dumps(entry, default=str) + "\n"

            # Use file locking for cross-process safety
            with self._file_lock:
                # Check for log rotation
                if self.session_log_file.exists():
                    if self.session_log_file.stat().st_size > self.max_log_size_bytes:
                        self._rotate_log()

                # Write to session log file with exclusive lock
                with open(self.session_log_file, "a") as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    try:
                        f.write(log_line)
                        f.flush()
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                # Also write to current session file (primary only to avoid duplicates)
                if self.is_primary:
                    with open(self.current_log_file, "a") as f:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        try:
                            f.write(log_line)
                            f.flush()
                        finally:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            # Console output if enabled
            if self.console_output:
                self._console_output(entry)

        except Exception as e:
            # Fallback to stderr if logging fails
            print(f"[AUDIT LOG ERROR] Failed to write log: {e}", file=sys.stderr)

    def _console_output(self, entry: Dict[str, Any]):
        """Output log entry to console in readable format"""
        event_type = entry.get("event_type", "unknown")
        timestamp = entry.get("timestamp", "")
        message = entry.get("message", "")

        # Color codes
        colors = {
            "session_start": "\033[92m",  # Green
            "session_end": "\033[92m",
            "tool_call": "\033[94m",      # Blue
            "tool_output": "\033[96m",    # Cyan
            "command_executed": "\033[93m", # Yellow
            "error": "\033[91m",          # Red
            "warning": "\033[93m",
            "prompt_sent": "\033[95m",    # Magenta
            "response_received": "\033[95m",
        }
        reset = "\033[0m"
        color = colors.get(event_type, "")

        print(f"{color}[{timestamp}] [{event_type.upper()}] {message}{reset}")

    def _rotate_log(self):
        """Rotate log file when it gets too large"""
        if self.compress_old_logs:
            # Compress old log
            old_log = self.session_log_file.with_suffix(".jsonl.1")
            if old_log.exists():
                with open(old_log, 'rb') as f_in:
                    with gzip.open(old_log.with_suffix(".jsonl.1.gz"), 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                old_log.unlink()

            # Rename current log
            self.session_log_file.rename(old_log)
        else:
            # Just rename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated = self.session_log_file.with_suffix(f".{timestamp}.jsonl")
            self.session_log_file.rename(rotated)

    def _log_session_start(self):
        """Log session start event"""
        self.log_event(
            event_type=AuditEventType.SESSION_START,
            message="NTREE audit session started",
            data={
                "start_time": self.session_start.isoformat(),
                "hostname": os.uname().nodename,
                "user": os.getenv("USER", "unknown"),
                "python_version": sys.version,
                "working_directory": os.getcwd()
            }
        )

    def log_event(
        self,
        event_type: AuditEventType,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        tool_name: Optional[str] = None,
        target: Optional[str] = None,
        duration_ms: Optional[float] = None
    ):
        """
        Log an audit event.

        Args:
            event_type: Type of event
            message: Human-readable message
            data: Additional structured data
            tool_name: Name of tool (for tool events)
            target: Target being tested (for scope-related events)
            duration_ms: Duration in milliseconds (for timed events)
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type.value,
            "message": message,
            "sequence": self._get_sequence_number()
        }

        if tool_name:
            entry["tool_name"] = tool_name
        if target:
            entry["target"] = target
        if duration_ms is not None:
            entry["duration_ms"] = duration_ms
        if data:
            entry["data"] = data

        # Update statistics
        self._update_stats(event_type)

        self._write_log_entry(entry)

    _sequence_counter = 0
    _sequence_lock = threading.Lock()

    def _get_sequence_number(self) -> int:
        """Get monotonically increasing sequence number"""
        with self._sequence_lock:
            AuditLogger._sequence_counter += 1
            return AuditLogger._sequence_counter

    def _update_stats(self, event_type: AuditEventType):
        """Update statistics based on event type"""
        if event_type == AuditEventType.TOOL_CALL:
            self.stats["tools_called"] += 1
        elif event_type == AuditEventType.COMMAND_EXECUTED:
            self.stats["commands_executed"] += 1
        elif event_type == AuditEventType.ERROR:
            self.stats["errors"] += 1
        elif event_type == AuditEventType.WARNING:
            self.stats["warnings"] += 1
        elif event_type == AuditEventType.FINDING_SAVED:
            self.stats["findings_saved"] += 1
        elif event_type == AuditEventType.PROMPT_SENT:
            self.stats["prompts_sent"] += 1
        elif event_type == AuditEventType.RESPONSE_RECEIVED:
            self.stats["responses_received"] += 1

    # Convenience methods for common events

    def log_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        target: Optional[str] = None
    ) -> str:
        """
        Log a tool call. Returns call_id for matching with output.
        """
        call_id = uuid.uuid4().hex[:12]
        self._pending_tool_calls[call_id] = datetime.now()

        # Sanitize sensitive data
        safe_args = self._sanitize_arguments(arguments)

        self.log_event(
            event_type=AuditEventType.TOOL_CALL,
            message=f"Tool called: {tool_name}",
            tool_name=tool_name,
            target=target,
            data={
                "call_id": call_id,
                "arguments": safe_args
            }
        )
        return call_id

    def log_tool_output(
        self,
        tool_name: str,
        call_id: str,
        output: Any,
        status: str = "success",
        truncate_output: int = 10000
    ):
        """Log tool output"""
        # Calculate duration
        duration_ms = None
        if call_id in self._pending_tool_calls:
            start_time = self._pending_tool_calls.pop(call_id)
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000

        # Record to performance metrics
        if duration_ms is not None:
            perf = self._get_perf_metrics()
            if perf:
                perf.record_tool_call(tool_name, duration_ms, success=True)

        # Truncate large outputs
        output_str = str(output)
        if len(output_str) > truncate_output:
            output_str = output_str[:truncate_output] + f"... [truncated, total {len(str(output))} chars]"

        self.log_event(
            event_type=AuditEventType.TOOL_OUTPUT,
            message=f"Tool output: {tool_name} ({status})",
            tool_name=tool_name,
            duration_ms=duration_ms,
            data={
                "call_id": call_id,
                "status": status,
                "output": output_str,
                "output_length": len(str(output))
            }
        )

    def log_tool_error(
        self,
        tool_name: str,
        call_id: str,
        error: Exception,
        target: Optional[str] = None
    ):
        """Log tool error"""
        duration_ms = None
        if call_id in self._pending_tool_calls:
            start_time = self._pending_tool_calls.pop(call_id)
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000

        # Record to performance metrics
        if duration_ms is not None:
            perf = self._get_perf_metrics()
            if perf:
                perf.record_tool_call(tool_name, duration_ms, success=False)

        self.log_event(
            event_type=AuditEventType.TOOL_ERROR,
            message=f"Tool error: {tool_name} - {str(error)}",
            tool_name=tool_name,
            target=target,
            duration_ms=duration_ms,
            data={
                "call_id": call_id,
                "error_type": type(error).__name__,
                "error_message": str(error),
                "traceback": traceback.format_exc()
            }
        )

    def log_command_executed(
        self,
        command: str,
        tool_name: Optional[str] = None,
        target: Optional[str] = None
    ) -> str:
        """Log command execution. Returns command_id for matching with output."""
        command_id = uuid.uuid4().hex[:12]
        self._pending_tool_calls[command_id] = datetime.now()

        # Track command type for performance metrics
        self._command_type_map[command_id] = self._extract_command_type(command)

        # Sanitize command (remove potential credentials)
        safe_command = self._sanitize_command(command)

        self.log_event(
            event_type=AuditEventType.COMMAND_EXECUTED,
            message=f"Command executed: {safe_command[:100]}...",
            tool_name=tool_name,
            target=target,
            data={
                "command_id": command_id,
                "command": safe_command,
                "command_hash": hashlib.sha256(command.encode()).hexdigest()[:16]
            }
        )
        return command_id

    def log_command_output(
        self,
        command_id: str,
        output: str,
        return_code: int,
        stderr: Optional[str] = None,
        truncate_output: int = 50000
    ):
        """Log command output"""
        duration_ms = None
        if command_id in self._pending_tool_calls:
            start_time = self._pending_tool_calls.pop(command_id)
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000

        # Record to performance metrics
        if duration_ms is not None:
            cmd_type = self._command_type_map.pop(command_id, "unknown")
            perf = self._get_perf_metrics()
            if perf:
                perf.record_command(
                    cmd_type, duration_ms,
                    success=(return_code == 0),
                    return_code=return_code,
                )

        # Truncate large outputs
        output_truncated = output
        if len(output) > truncate_output:
            output_truncated = output[:truncate_output] + f"\n... [truncated, total {len(output)} chars]"

        self.log_event(
            event_type=AuditEventType.COMMAND_OUTPUT,
            message=f"Command completed (exit code: {return_code})",
            duration_ms=duration_ms,
            data={
                "command_id": command_id,
                "return_code": return_code,
                "output": output_truncated,
                "output_length": len(output),
                "stderr": stderr[:5000] if stderr and len(stderr) > 5000 else stderr
            }
        )

    def log_prompt_sent(
        self,
        prompt: str,
        truncate: int = 50000
    ):
        """Log prompt sent to Claude"""
        prompt_truncated = prompt
        if len(prompt) > truncate:
            prompt_truncated = prompt[:truncate] + f"\n... [truncated, total {len(prompt)} chars]"

        self.log_event(
            event_type=AuditEventType.PROMPT_SENT,
            message=f"Prompt sent to Claude ({len(prompt)} chars)",
            data={
                "prompt": prompt_truncated,
                "prompt_length": len(prompt),
                "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16]
            }
        )

    def log_response_received(
        self,
        response: str,
        truncate: int = 50000
    ):
        """Log response received from Claude"""
        response_truncated = response
        if len(response) > truncate:
            response_truncated = response[:truncate] + f"\n... [truncated, total {len(response)} chars]"

        self.log_event(
            event_type=AuditEventType.RESPONSE_RECEIVED,
            message=f"Response received from Claude ({len(response)} chars)",
            data={
                "response": response_truncated,
                "response_length": len(response),
                "response_hash": hashlib.sha256(response.encode()).hexdigest()[:16]
            }
        )

    def log_scope_validation(
        self,
        target: str,
        in_scope: bool,
        reason: Optional[str] = None
    ):
        """Log scope validation check"""
        self.log_event(
            event_type=AuditEventType.SCOPE_VALIDATION,
            message=f"Scope check: {target} - {'IN SCOPE' if in_scope else 'OUT OF SCOPE'}",
            target=target,
            data={
                "in_scope": in_scope,
                "reason": reason
            }
        )

    def log_finding(
        self,
        title: str,
        severity: str,
        target: str,
        finding_id: Optional[str] = None
    ):
        """Log finding saved"""
        self.log_event(
            event_type=AuditEventType.FINDING_SAVED,
            message=f"Finding saved: {title} ({severity})",
            target=target,
            data={
                "finding_id": finding_id,
                "title": title,
                "severity": severity
            }
        )

    def log_phase_change(self, old_phase: str, new_phase: str):
        """Log assessment phase change"""
        self.log_event(
            event_type=AuditEventType.PHASE_CHANGE,
            message=f"Phase change: {old_phase} -> {new_phase}",
            data={
                "old_phase": old_phase,
                "new_phase": new_phase
            }
        )

    def log_error(
        self,
        error: Union[Exception, str],
        context: Optional[str] = None,
        tool_name: Optional[str] = None
    ):
        """Log an error"""
        error_msg = str(error)
        tb = traceback.format_exc() if isinstance(error, Exception) else None

        self.log_event(
            event_type=AuditEventType.ERROR,
            message=f"Error: {error_msg}",
            tool_name=tool_name,
            data={
                "error_type": type(error).__name__ if isinstance(error, Exception) else "string",
                "error_message": error_msg,
                "context": context,
                "traceback": tb
            }
        )

    def log_warning(self, message: str, data: Optional[Dict] = None):
        """Log a warning"""
        self.log_event(
            event_type=AuditEventType.WARNING,
            message=message,
            data=data
        )

    def log_info(self, message: str, data: Optional[Dict] = None):
        """Log info message"""
        self.log_event(
            event_type=AuditEventType.INFO,
            message=message,
            data=data
        )

    def log_assessment_init(
        self,
        assessment_id: str,
        scope_file: str,
        roe_file: Optional[str] = None,
        targets: Optional[List[str]] = None
    ):
        """Log assessment initialization"""
        self.set_assessment_id(assessment_id)

        self.log_event(
            event_type=AuditEventType.ASSESSMENT_INIT,
            message=f"Assessment initialized: {assessment_id}",
            data={
                "scope_file": scope_file,
                "roe_file": roe_file,
                "target_count": len(targets) if targets else 0,
                "targets": targets[:20] if targets else None  # Limit to first 20
            }
        )

    def log_assessment_complete(
        self,
        assessment_id: str,
        findings_count: int,
        reports_generated: List[str]
    ):
        """Log assessment completion"""
        self.log_event(
            event_type=AuditEventType.ASSESSMENT_COMPLETE,
            message=f"Assessment completed: {assessment_id}",
            data={
                "findings_count": findings_count,
                "reports_generated": reports_generated,
                "duration_seconds": (datetime.now() - self.session_start).total_seconds()
            }
        )

    def log_report_generated(
        self,
        report_type: str,
        report_path: str,
        format: str
    ):
        """Log report generation"""
        self.log_event(
            event_type=AuditEventType.REPORT_GENERATED,
            message=f"Report generated: {report_type} ({format})",
            data={
                "report_type": report_type,
                "report_path": report_path,
                "format": format
            }
        )

    def set_assessment_id(self, assessment_id: str):
        """
        Set or update the assessment ID and update log file path.

        This should be called when the assessment_id becomes known
        (e.g., after init_assessment is called).  Migrates the log
        directory from the global staging area into the assessment-local
        ``logs/`` directory so each assessment is self-contained.

        Args:
            assessment_id: The assessment ID to use
        """
        self.assessment_id = assessment_id

        # Update environment variable for MCP servers
        os.environ["NTREE_AUDIT_ASSESSMENT_ID"] = assessment_id

        # Migrate log directory to assessment-local path
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        new_log_dir = ntree_home / "assessments" / assessment_id / "logs"
        new_log_dir.mkdir(parents=True, exist_ok=True)
        old_log_dir = self.log_dir
        self.log_dir = new_log_dir

        # Update log file path to use assessment_id
        new_log_file = self.log_dir / f"assessment_{assessment_id}.jsonl"

        # If we already have entries in the old log file, copy them
        if self.session_log_file.exists() and self.session_log_file != new_log_file:
            try:
                import fcntl
                with open(self.session_log_file, "r") as old_f:
                    with open(new_log_file, "a") as new_f:
                        fcntl.flock(new_f.fileno(), fcntl.LOCK_EX)
                        try:
                            for line in old_f:
                                new_f.write(line)
                        finally:
                            fcntl.flock(new_f.fileno(), fcntl.LOCK_UN)
                # Remove old file after successful copy
                self.session_log_file.unlink()
            except Exception as e:
                print(f"[AUDIT LOG] Warning: Could not migrate log file: {e}", file=sys.stderr)

        self.session_log_file = new_log_file
        self.current_log_file = self.log_dir / "current_session.jsonl"

    def start_session(self, metadata: Optional[Dict[str, Any]] = None):
        """
        Start or restart the audit session with optional metadata.

        This is typically called automatically on initialization,
        but can be called again to update session metadata.

        Args:
            metadata: Optional metadata to include in session start event
        """
        # Update assessment_id if provided in metadata
        if metadata and "assessment_id" in metadata and metadata["assessment_id"]:
            self.set_assessment_id(metadata["assessment_id"])

        self.log_event(
            event_type=AuditEventType.SESSION_START,
            message="NTREE audit session started/updated",
            data={
                "start_time": self.session_start.isoformat(),
                "hostname": os.uname().nodename,
                "user": os.getenv("USER", "unknown"),
                "metadata": metadata
            }
        )

    def end_session(self, metadata: Optional[Dict[str, Any]] = None):
        """End the audit session and write final statistics"""
        duration = (datetime.now() - self.session_start).total_seconds()

        data = {
            "duration_seconds": duration,
            "statistics": self.stats
        }
        if metadata:
            data["metadata"] = metadata

        self.log_event(
            event_type=AuditEventType.SESSION_END,
            message="NTREE audit session ended",
            data=data
        )

        # Write session summary
        summary_file = self.log_dir / f"session_{self.session_id}_summary.json"
        summary = {
            "session_id": self.session_id,
            "assessment_id": self.assessment_id,
            "start_time": self.session_start.isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration_seconds": duration,
            "statistics": self.stats,
            "log_file": str(self.session_log_file)
        }

        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

    @staticmethod
    def _get_perf_metrics():
        """Performance metrics not available in lite edition."""
        return None

    @staticmethod
    def _extract_command_type(command: str) -> str:
        """Extract binary name from a command string, stripping sudo prefix."""
        parts = command.strip().split()
        if not parts:
            return "unknown"
        # Strip sudo prefix
        idx = 0
        if parts[idx] == "sudo" and len(parts) > 1:
            idx = 1
        binary = parts[idx].split("/")[-1]  # handle absolute paths
        return binary

    def _sanitize_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from arguments"""
        sensitive_keys = ["password", "secret", "key", "token", "credential", "hash"]
        sanitized = {}

        for key, value in arguments.items():
            key_lower = key.lower()
            if any(s in key_lower for s in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_arguments(value)
            else:
                sanitized[key] = value

        return sanitized

    def _sanitize_command(self, command: str) -> str:
        """Remove potential credentials from command strings"""
        import re

        # Patterns for credentials
        patterns = [
            (r'(sshpass\s+-p\s*)[^\s]+', r'\1[REDACTED]'),  # sshpass -p password
            (r'((?:crackmapexec|cme|mysql|psql|smbclient|rpcclient|impacket|hydra)\b.*\s-p\s*)[^\s]+', r'\1[REDACTED]'),  # tool -p password
            (r'(--password[=\s])[^\s]+', r'\1[REDACTED]'),
            (r'(PGPASSWORD=)[^\s]+', r'\1[REDACTED]'),
            (r'(:\/\/[^:]+:)[^@]+(@)', r'\1[REDACTED]\2'),  # user:pass@host
        ]

        sanitized = command
        for pattern, replacement in patterns:
            sanitized = re.sub(pattern, replacement, sanitized)

        return sanitized

    def get_session_log_path(self) -> Path:
        """Get path to current session log file"""
        return self.session_log_file

    def get_statistics(self) -> Dict[str, int]:
        """Get current session statistics"""
        return self.stats.copy()

    def get_session_stats(self) -> Dict[str, Any]:
        """Get comprehensive session statistics including timing"""
        duration = (datetime.now() - self.session_start).total_seconds()
        return {
            "session_id": self.session_id,
            "assessment_id": self.assessment_id,
            "duration_seconds": duration,
            "statistics": self.stats.copy()
        }


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger(
    log_dir: Optional[str] = None,
    session_id: Optional[str] = None,
    assessment_id: Optional[str] = None,
    **kwargs
) -> AuditLogger:
    """
    Get or create the global audit logger instance.

    Args:
        log_dir: Directory for log files
        session_id: Unique session identifier
        assessment_id: Assessment ID
        **kwargs: Additional arguments for AuditLogger

    Returns:
        AuditLogger instance
    """
    global _audit_logger

    if _audit_logger is None:
        _audit_logger = AuditLogger(
            log_dir=log_dir,
            session_id=session_id,
            assessment_id=assessment_id,
            **kwargs
        )

    return _audit_logger


def reset_audit_logger():
    """Reset the global audit logger (for testing)"""
    global _audit_logger
    if _audit_logger is not None:
        _audit_logger.end_session()
        _audit_logger._initialized = False
        _audit_logger = None
