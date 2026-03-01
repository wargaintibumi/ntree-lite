"""
NTREE Centralized State Manager
File-based state management with cross-process locking for reliable state sharing.
"""

import json
import os
import fcntl
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from contextlib import contextmanager

from .logger import get_logger

logger = get_logger(__name__)


class StateLockError(Exception):
    """Raised when state lock cannot be acquired."""
    pass


class StateManager:
    """
    Centralized state manager for NTREE assessments.

    Provides file-based state management with:
    - Cross-process file locking
    - Atomic updates
    - Checkpoint/resume support
    - State history tracking
    """

    def __init__(self, assessment_id: str, base_dir: Optional[str] = None):
        """
        Initialize state manager for an assessment.

        Args:
            assessment_id: Unique assessment identifier
            base_dir: Base directory for assessments (default: ~/ntree/assessments)
        """
        self.assessment_id = assessment_id
        self.base_dir = Path(base_dir or os.path.expanduser("~/ntree/assessments"))
        self.assessment_dir = self.base_dir / assessment_id
        self.state_file = self.assessment_dir / "state.json"
        self.lock_file = self.assessment_dir / ".state.lock"
        self.checkpoint_dir = self.assessment_dir / "checkpoints"

        # Ensure directories exist
        self.assessment_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_dir.mkdir(exist_ok=True)

        # Initialize state if not exists
        if not self.state_file.exists():
            self._initialize_state()

    def _initialize_state(self):
        """Initialize empty state file."""
        initial_state = {
            "assessment_id": self.assessment_id,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "phase": "INIT",
            "status": "active",
            "hosts": [],
            "services": [],
            "credentials": [],
            "findings_count": 0,
            "scans_performed": 0,
            "errors": [],
            "checkpoints": [],
            "metadata": {}
        }
        self._write_state(initial_state)

    @contextmanager
    def _file_lock(self, timeout: float = 30.0):
        """
        Acquire exclusive file lock with timeout.

        Args:
            timeout: Maximum time to wait for lock in seconds
        """
        lock_fd = None
        try:
            lock_fd = open(self.lock_file, 'w')
            start_time = time.time()

            while True:
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except IOError:
                    if time.time() - start_time > timeout:
                        raise StateLockError(f"Could not acquire state lock within {timeout}s")
                    time.sleep(0.1)

            yield lock_fd

        finally:
            if lock_fd:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                lock_fd.close()

    def _read_state(self) -> Dict[str, Any]:
        """Read state from file."""
        if not self.state_file.exists():
            self._initialize_state()

        with open(self.state_file, 'r') as f:
            return json.load(f)

    def _write_state(self, state: Dict[str, Any]):
        """Write state to file atomically."""
        state["updated_at"] = datetime.now().isoformat()

        # Write to temp file first, then rename (atomic on POSIX)
        temp_file = self.state_file.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(state, f, indent=2, default=str)
        temp_file.rename(self.state_file)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a value from state.

        Args:
            key: State key to retrieve
            default: Default value if key not found
        """
        with self._file_lock():
            state = self._read_state()
            return state.get(key, default)

    def set(self, key: str, value: Any):
        """
        Set a value in state.

        Args:
            key: State key to set
            value: Value to store
        """
        with self._file_lock():
            state = self._read_state()
            state[key] = value
            self._write_state(state)

    def update(self, **kwargs):
        """
        Update multiple state values atomically.

        Args:
            **kwargs: Key-value pairs to update
        """
        with self._file_lock():
            state = self._read_state()
            state.update(kwargs)
            self._write_state(state)

    def append_to_list(self, key: str, value: Any, unique: bool = True):
        """
        Append value to a list in state.

        Args:
            key: State key (must be a list)
            value: Value to append
            unique: If True, only append if not already present
        """
        with self._file_lock():
            state = self._read_state()
            if key not in state:
                state[key] = []

            if not unique or value not in state[key]:
                state[key].append(value)

            self._write_state(state)

    def extend_list(self, key: str, values: List[Any], unique: bool = True):
        """
        Extend a list in state with multiple values.

        Args:
            key: State key (must be a list)
            values: Values to add
            unique: If True, only add values not already present
        """
        with self._file_lock():
            state = self._read_state()
            if key not in state:
                state[key] = []

            for value in values:
                if not unique or value not in state[key]:
                    state[key].append(value)

            self._write_state(state)

    def increment(self, key: str, amount: int = 1) -> int:
        """
        Increment a counter in state.

        Args:
            key: State key (must be numeric)
            amount: Amount to increment by

        Returns:
            New value after increment
        """
        with self._file_lock():
            state = self._read_state()
            state[key] = state.get(key, 0) + amount
            self._write_state(state)
            return state[key]

    def get_full_state(self) -> Dict[str, Any]:
        """Get complete state dictionary."""
        with self._file_lock():
            return self._read_state()

    def set_phase(self, phase: str):
        """
        Update assessment phase and create checkpoint.

        Args:
            phase: New phase (INIT, RECON, ENUM, VULN, POST, REPORT, COMPLETE)
        """
        with self._file_lock():
            state = self._read_state()
            old_phase = state.get("phase", "INIT")
            if old_phase == phase:
                return  # Skip no-op phase transition
            state["phase"] = phase
            state["phase_history"] = state.get("phase_history", [])
            state["phase_history"].append({
                "from": old_phase,
                "to": phase,
                "timestamp": datetime.now().isoformat()
            })
            self._write_state(state)

        # Create checkpoint on phase change
        self.create_checkpoint(f"phase_{phase.lower()}")
        logger.info(f"Phase changed: {old_phase} -> {phase}")

    def add_error(self, error: str, context: str = ""):
        """
        Log an error to state.

        Args:
            error: Error message
            context: Context where error occurred
        """
        error_entry = {
            "timestamp": datetime.now().isoformat(),
            "error": str(error),
            "context": context
        }
        self.append_to_list("errors", error_entry, unique=False)

    def create_checkpoint(self, name: str = "") -> str:
        """
        Create a checkpoint of current state for resume capability.

        Args:
            name: Optional checkpoint name

        Returns:
            Checkpoint filename
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        checkpoint_name = f"checkpoint_{timestamp}"
        if name:
            checkpoint_name += f"_{name}"
        checkpoint_name += ".json"

        checkpoint_file = self.checkpoint_dir / checkpoint_name

        with self._file_lock():
            state = self._read_state()
            state["checkpoint_name"] = checkpoint_name
            state["checkpoint_time"] = datetime.now().isoformat()

            with open(checkpoint_file, 'w') as f:
                json.dump(state, f, indent=2, default=str)

            # Track checkpoint in state
            state["checkpoints"] = state.get("checkpoints", [])
            state["checkpoints"].append({
                "name": checkpoint_name,
                "timestamp": datetime.now().isoformat(),
                "phase": state.get("phase", "UNKNOWN")
            })
            self._write_state(state)

        logger.info(f"Checkpoint created: {checkpoint_name}")
        return checkpoint_name

    def list_checkpoints(self) -> List[Dict[str, Any]]:
        """List all available checkpoints."""
        checkpoints = []
        for f in sorted(self.checkpoint_dir.glob("checkpoint_*.json")):
            try:
                with open(f) as fp:
                    data = json.load(fp)
                checkpoints.append({
                    "file": f.name,
                    "phase": data.get("phase", "UNKNOWN"),
                    "timestamp": data.get("checkpoint_time", ""),
                    "hosts": len(data.get("hosts", [])),
                    "findings": data.get("findings_count", 0)
                })
            except Exception as e:
                logger.warning(f"Error reading checkpoint {f}: {e}")
        return checkpoints

    def restore_checkpoint(self, checkpoint_name: str) -> bool:
        """
        Restore state from a checkpoint.

        Args:
            checkpoint_name: Checkpoint filename to restore

        Returns:
            True if successful, False otherwise
        """
        checkpoint_file = self.checkpoint_dir / checkpoint_name
        if not checkpoint_file.exists():
            logger.error(f"Checkpoint not found: {checkpoint_name}")
            return False

        try:
            with open(checkpoint_file, 'r') as f:
                checkpoint_state = json.load(f)

            # Mark as resumed
            checkpoint_state["resumed_from"] = checkpoint_name
            checkpoint_state["resumed_at"] = datetime.now().isoformat()
            checkpoint_state["status"] = "resumed"

            with self._file_lock():
                self._write_state(checkpoint_state)

            logger.info(f"State restored from checkpoint: {checkpoint_name}")
            return True

        except Exception as e:
            logger.error(f"Error restoring checkpoint: {e}")
            return False

    def get_latest_checkpoint(self) -> Optional[str]:
        """Get the most recent checkpoint filename."""
        checkpoints = list(self.checkpoint_dir.glob("checkpoint_*.json"))
        if not checkpoints:
            return None
        return sorted(checkpoints)[-1].name

    def is_resumable(self) -> bool:
        """Check if assessment can be resumed."""
        state = self.get_full_state()
        return (
            state.get("status") in ("active", "paused", "resumed") and
            state.get("phase") not in ("COMPLETE", "FAILED") and
            len(self.list_checkpoints()) > 0
        )

    def mark_complete(self, summary: Dict[str, Any] = None):
        """Mark assessment as complete."""
        with self._file_lock():
            state = self._read_state()
            state["status"] = "complete"
            state["phase"] = "COMPLETE"
            state["completed_at"] = datetime.now().isoformat()
            if summary:
                state["summary"] = summary
            self._write_state(state)

        self.create_checkpoint("complete")

    def mark_failed(self, error: str):
        """Mark assessment as failed."""
        self.add_error(error, "fatal")
        self.update(status="failed", phase="FAILED")
        self.create_checkpoint("failed")


# Global state manager instance cache
_state_managers: Dict[str, StateManager] = {}


def get_state_manager(assessment_id: str) -> StateManager:
    """
    Get or create state manager for an assessment.

    Args:
        assessment_id: Assessment identifier

    Returns:
        StateManager instance
    """
    if assessment_id not in _state_managers:
        _state_managers[assessment_id] = StateManager(assessment_id)
    return _state_managers[assessment_id]


def clear_state_manager_cache():
    """Clear the state manager cache."""
    global _state_managers
    _state_managers = {}
