"""
NTREE MCP Utilities
Common utilities for MCP servers
"""

from .logger import get_logger, setup_logging
from .command_runner import CommandRunner, run_command
from .scope_parser import ScopeValidator
from .nmap_parser import parse_nmap_xml
from .interactive_tools import (
    INTERACTIVE_TOOLS,
    is_tool_interactive,
    detect_interactive_prompt,
    get_safe_alternative,
    should_skip_command,
)
from .audit_logger import (
    AuditLogger,
    AuditEventType,
    get_audit_logger,
    reset_audit_logger,
)
from .state_manager import (
    StateManager,
    StateLockError,
    get_state_manager,
    clear_state_manager_cache,
)
from .evidence_validator import (
    validate_evidence,
    enrich_finding_with_validation,
    get_evidence_quality_summary,
    EvidenceQuality,
    ValidationResult,
)
from .report_generator import (
    ReportGenerator,
    generate_report,
)

__all__ = [
    # Logger
    "get_logger",
    "setup_logging",
    # Command runner
    "CommandRunner",
    "run_command",
    # Scope
    "ScopeValidator",
    # Parsers
    "parse_nmap_xml",
    # Interactive tools
    "INTERACTIVE_TOOLS",
    "is_tool_interactive",
    "detect_interactive_prompt",
    "get_safe_alternative",
    "should_skip_command",
    # Audit logger
    "AuditLogger",
    "AuditEventType",
    "get_audit_logger",
    "reset_audit_logger",
    # State manager
    "StateManager",
    "StateLockError",
    "get_state_manager",
    "clear_state_manager_cache",
    # Evidence validator
    "validate_evidence",
    "enrich_finding_with_validation",
    "get_evidence_quality_summary",
    "EvidenceQuality",
    "ValidationResult",
    # Report generator
    "ReportGenerator",
    "generate_report",
]
