"""
Safe command execution utilities
Provides secure subprocess execution with timeout and logging
"""

import asyncio
import os
import shlex
import subprocess
from pathlib import Path
from typing import Tuple, Optional, List, Dict
from .logger import get_logger
from .interactive_tools import (
    is_tool_interactive,
    detect_interactive_prompt,
    should_skip_command,
    get_safe_alternative
)

logger = get_logger(__name__)

# Lazy import audit logger to avoid circular imports
_audit_logger = None

def _get_audit_logger():
    """Get audit logger instance (lazy initialization with env var sync)"""
    global _audit_logger
    if _audit_logger is None:
        try:
            from .audit_logger import get_audit_logger
            _audit_logger = get_audit_logger()
        except Exception:
            pass

    # Sync with environment variables (set by SDK agent)
    if _audit_logger is not None:
        env_session_id = os.environ.get("NTREE_AUDIT_SESSION_ID")
        env_assessment_id = os.environ.get("NTREE_AUDIT_ASSESSMENT_ID")

        if env_session_id and _audit_logger.session_id != env_session_id:
            _audit_logger.session_id = env_session_id
        if env_assessment_id and _audit_logger.assessment_id != env_assessment_id:
            _audit_logger.set_assessment_id(env_assessment_id)

    return _audit_logger


class CommandRunner:
    """Execute shell commands safely with logging and timeout."""

    def __init__(self, timeout: int = 300, max_output_size: int = 5_000_000):
        """
        Initialize command runner.

        Args:
            timeout: Maximum execution time in seconds (default 5 minutes)
            max_output_size: Maximum output size in bytes (default 5MB, optimized for Pi 5)
        """
        self.timeout = timeout
        self.max_output_size = max_output_size

    async def run_async(
        self,
        command: str,
        shell: bool = False,
        capture_output: bool = True,
        check: bool = False,
        cwd: Optional[Path] = None,
        env: Optional[dict] = None,
        skip_interactive_check: bool = False,
    ) -> Tuple[int, str, str]:
        """
        Execute a command asynchronously.

        Args:
            command: Command to execute
            shell: Whether to use shell (avoid when possible)
            capture_output: Capture stdout/stderr
            check: Raise exception on non-zero exit
            cwd: Working directory
            env: Environment variables
            skip_interactive_check: Skip interactive tool detection (use with caution)

        Returns:
            Tuple of (returncode, stdout, stderr)
            If tool requires manual review: returncode=-2, stdout contains JSON with details
        """
        logger.debug(f"Executing command: {command}")

        # Audit logging
        audit = _get_audit_logger()
        command_id = None
        if audit:
            command_id = audit.log_command_executed(command)

        # PRE-EXECUTION: Check if tool is interactive
        if not skip_interactive_check:
            interactive_check = is_tool_interactive(command)
            if interactive_check["is_interactive"]:
                logger.warning(f"Interactive tool detected: {interactive_check['tool']}")
                logger.warning(f"Reason: {interactive_check['reason']}")
                logger.warning(f"Recommendation: {interactive_check['recommendation']}")

                # Try to get safe alternative
                safe_cmd = get_safe_alternative(command)

                # Return special status for manual review
                import json
                manual_review_data = {
                    "status": "needs_manual_review",
                    "reason": "Interactive tool detected",
                    "tool": interactive_check["tool"],
                    "details": interactive_check["reason"],
                    "recommendation": interactive_check["recommendation"],
                    "safe_alternative": safe_cmd,
                    "prompts_for": interactive_check.get("prompts_for", []),
                    "original_command": command
                }

                return (-2, json.dumps(manual_review_data, indent=2), "Tool requires manual review")

        try:
            if not shell:
                cmd_list = shlex.split(command)
            else:
                cmd_list = command

            # Use asyncio subprocess
            if isinstance(cmd_list, list):
                process = await asyncio.create_subprocess_exec(
                    *cmd_list,
                    stdout=asyncio.subprocess.PIPE if capture_output else None,
                    stderr=asyncio.subprocess.PIPE if capture_output else None,
                    stdin=asyncio.subprocess.DEVNULL,
                    cwd=cwd,
                    env=env,
                )
            else:
                process = await asyncio.create_subprocess_shell(
                    cmd_list,
                    stdout=asyncio.subprocess.PIPE if capture_output else None,
                    stderr=asyncio.subprocess.PIPE if capture_output else None,
                    stdin=asyncio.subprocess.DEVNULL,
                    cwd=cwd,
                    env=env,
                )

            # Wait for completion with timeout
            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.error(f"Command timed out after {self.timeout}s: {command}")
                return -1, "", f"Command timed out after {self.timeout}s"

            # Decode output
            stdout = stdout_data.decode('utf-8', errors='replace') if stdout_data else ""
            stderr = stderr_data.decode('utf-8', errors='replace') if stderr_data else ""

            # Check output size
            if len(stdout) > self.max_output_size:
                logger.warning(f"stdout truncated (exceeded {self.max_output_size} bytes)")
                stdout = stdout[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"

            if len(stderr) > self.max_output_size:
                logger.warning(f"stderr truncated (exceeded {self.max_output_size} bytes)")
                stderr = stderr[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"

            returncode = process.returncode
            logger.debug(f"Command completed with returncode: {returncode}")

            # POST-EXECUTION: Check if output indicates interactive prompt
            if not skip_interactive_check:
                combined_output = stdout + "\n" + stderr
                prompt_detected = detect_interactive_prompt(combined_output)

                if prompt_detected:
                    logger.warning(f"Interactive prompt detected in output: {prompt_detected['line']}")
                    logger.warning(f"Recommendation: {prompt_detected['recommendation']}")

                    # Return special status for manual review
                    import json
                    manual_review_data = {
                        "status": "needs_manual_review",
                        "reason": "Interactive prompt detected in output",
                        "prompt_detected": prompt_detected["line"],
                        "pattern": prompt_detected["pattern"],
                        "recommendation": prompt_detected["recommendation"],
                        "original_command": command,
                        "partial_output": combined_output[-500:] if len(combined_output) > 500 else combined_output
                    }

                    return (-2, json.dumps(manual_review_data, indent=2), "Tool prompted for user input")

            # Audit log command output
            if audit and command_id:
                audit.log_command_output(command_id, stdout, returncode, stderr)

            if check and returncode != 0:
                raise subprocess.CalledProcessError(returncode, command, stdout, stderr)

            return returncode, stdout, stderr

        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with returncode {e.returncode}: {command}")
            # Audit log error
            if audit and command_id:
                audit.log_command_output(command_id, e.stdout or "", e.returncode, e.stderr)
            return e.returncode, e.stdout or "", e.stderr or ""

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            # Audit log error
            if audit and command_id:
                audit.log_error(e, context=f"Command: {command}")
            return -1, "", str(e)

    def run_sync(
        self,
        command: str,
        shell: bool = False,
        capture_output: bool = True,
        check: bool = False,
        cwd: Optional[Path] = None,
        env: Optional[dict] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute a command synchronously.

        Args:
            command: Command to execute
            shell: Whether to use shell
            capture_output: Capture stdout/stderr
            check: Raise exception on non-zero exit
            cwd: Working directory
            env: Environment variables

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        logger.debug(f"Executing command (sync): {command}")

        try:
            if not shell:
                cmd_list = shlex.split(command)
            else:
                cmd_list = command

            result = subprocess.run(
                cmd_list,
                shell=shell,
                capture_output=capture_output,
                text=True,
                timeout=self.timeout,
                check=check,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
            )

            stdout = result.stdout or ""
            stderr = result.stderr or ""

            # Check output size
            if len(stdout) > self.max_output_size:
                logger.warning(f"stdout truncated (exceeded {self.max_output_size} bytes)")
                stdout = stdout[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"

            if len(stderr) > self.max_output_size:
                logger.warning(f"stderr truncated (exceeded {self.max_output_size} bytes)")
                stderr = stderr[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"

            logger.debug(f"Command completed with returncode: {result.returncode}")
            return result.returncode, stdout, stderr

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {self.timeout}s: {command}")
            return -1, "", f"Command timed out after {self.timeout}s"

        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with returncode {e.returncode}: {command}")
            return e.returncode, e.stdout or "", e.stderr or ""

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return -1, "", str(e)


# Convenience functions
async def run_command(
    command: str,
    timeout: int = 300,
    skip_interactive_check: bool = False,
    **kwargs
) -> Tuple[int, str, str]:
    """
    Convenience function to run a command asynchronously.

    Args:
        command: Command to execute
        timeout: Timeout in seconds
        skip_interactive_check: Skip interactive tool detection (use with caution)
        **kwargs: Additional arguments for CommandRunner.run_async()

    Returns:
        Tuple of (returncode, stdout, stderr)
        If tool requires manual review: returncode=-2, stdout contains JSON with details
    """
    runner = CommandRunner(timeout=timeout)
    return await runner.run_async(command, skip_interactive_check=skip_interactive_check, **kwargs)


def run_command_sync(
    command: str,
    timeout: int = 300,
    **kwargs
) -> Tuple[int, str, str]:
    """
    Convenience function to run a command synchronously.

    Args:
        command: Command to execute
        timeout: Timeout in seconds
        **kwargs: Additional arguments for CommandRunner.run_sync()

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    runner = CommandRunner(timeout=timeout)
    return runner.run_sync(command, **kwargs)


# Security tool wrappers
class SecurityTools:
    """Wrappers for common security tools with safe defaults."""

    @staticmethod
    async def nmap(
        targets: str,
        ports: Optional[str] = None,
        scan_type: str = "-sV",
        output_file: Optional[Path] = None,
        extra_args: str = "",
        timeout: int = 600
    ) -> Tuple[int, str, str]:
        """
        Run nmap with safe defaults.

        Args:
            targets: Target IPs/ranges
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            scan_type: Scan type flags (default: -sV version detection)
            output_file: Output XML file path
            extra_args: Additional nmap arguments
            timeout: Command timeout

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        cmd_parts = ["sudo", "nmap", scan_type]

        if ports:
            cmd_parts.extend(["-p", ports])

        if output_file:
            cmd_parts.extend(["-oX", str(output_file)])

        if extra_args:
            cmd_parts.append(extra_args)

        cmd_parts.append(targets)

        command = " ".join(cmd_parts)
        return await run_command(command, timeout=timeout)

    @staticmethod
    async def enum4linux(
        target: str,
        output_file: Optional[Path] = None,
        timeout: int = 300
    ) -> Tuple[int, str, str]:
        """
        Run enum4linux for SMB enumeration.

        Args:
            target: Target IP address
            output_file: Output file path
            timeout: Command timeout

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        command = f"enum4linux -a {target}"

        returncode, stdout, stderr = await run_command(command, timeout=timeout)

        if output_file and stdout:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(stdout)

        return returncode, stdout, stderr

    @staticmethod
    async def nikto(
        url: str,
        output_file: Optional[Path] = None,
        timeout: int = 600
    ) -> Tuple[int, str, str]:
        """
        Run nikto web vulnerability scanner.

        Args:
            url: Target URL
            output_file: Output file path
            timeout: Command timeout

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        cmd_parts = ["nikto", "-h", url]

        if output_file:
            cmd_parts.extend(["-output", str(output_file)])

        command = " ".join(cmd_parts)
        return await run_command(command, timeout=timeout)
