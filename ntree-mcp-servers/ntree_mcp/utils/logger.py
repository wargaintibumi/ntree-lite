"""
Logging utilities for NTREE MCP servers
Provides consistent logging across all servers with color support
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

try:
    import colorlog
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


def setup_logging(
    name: str,
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    use_color: bool = True
) -> logging.Logger:
    """
    Set up logging with optional file output and color support.

    Args:
        name: Logger name (typically module name)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        use_color: Use colored output (if colorlog available)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Console handler with color
    if HAS_COLOR and use_color:
        formatter = colorlog.ColoredFormatter(
            "%(log_color)s%(levelname)-8s%(reset)s %(blue)s%(name)s%(reset)s: %(message)s",
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )
    else:
        formatter = logging.Formatter(
            "%(levelname)-8s %(name)s: %(message)s"
        )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_formatter = logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Get or create a logger with standard configuration.

    Args:
        name: Logger name
        level: Logging level

    Returns:
        Logger instance
    """
    # Use NTREE_HOME for log file if set
    import os
    ntree_home = os.getenv("NTREE_HOME")

    log_file = None
    if ntree_home:
        log_dir = Path(ntree_home) / "logs"
        log_file = log_dir / f"{name}_{datetime.now().strftime('%Y%m%d')}.log"

    return setup_logging(name, level, log_file)


# Audit logging for security events
class AuditLogger:
    """
    Special logger for security-critical events.
    Ensures all pentest actions are logged for compliance.
    """

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self.logger = get_logger(f"audit.{assessment_id}")

        # Also log to assessment-specific file
        import os
        ntree_home = os.getenv("NTREE_HOME", str(Path.home() / "ntree"))
        audit_file = Path(ntree_home) / "assessments" / assessment_id / "audit.log"

        if not any(isinstance(h, logging.FileHandler) for h in self.logger.handlers):
            audit_file.parent.mkdir(parents=True, exist_ok=True)
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            handler = logging.FileHandler(audit_file)
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_action(
        self,
        phase: str,
        action: str,
        target: str,
        tool: str,
        result: str,
        details: Optional[dict] = None
    ):
        """Log a pentest action for audit trail."""
        msg = f"[{phase}] {action} on {target} using {tool}: {result}"
        if details:
            msg += f" | Details: {details}"
        self.logger.info(msg)

    def log_approval(self, action: str, approved: bool, reason: str = ""):
        """Log human approval decisions."""
        status = "APPROVED" if approved else "DENIED"
        msg = f"APPROVAL: {action} - {status}"
        if reason:
            msg += f" | Reason: {reason}"
        self.logger.warning(msg)

    def log_finding(self, severity: str, title: str, target: str):
        """Log discovery of a security finding."""
        msg = f"FINDING [{severity}]: {title} on {target}"
        self.logger.warning(msg)

    def log_scope_violation(self, target: str, reason: str):
        """Log attempted scope violations (critical)."""
        msg = f"SCOPE VIOLATION BLOCKED: {target} | Reason: {reason}"
        self.logger.critical(msg)
