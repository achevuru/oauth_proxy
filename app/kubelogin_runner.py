"""Helpers for invoking kubelogin to obtain AKS tokens."""

from __future__ import annotations

import json
import logging
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

from .config import get_settings

logger = logging.getLogger(__name__)


class KubeloginError(Exception):
    """Raised when the kubelogin invocation fails."""


@dataclass
class KubeloginResult:
    """Represents the minimal information returned by kubelogin."""

    access_token: str
    expires_on: int


class KubeloginJob:
    """Background worker that executes kubelogin and captures its output."""

    def __init__(self, command: list[str]):
        self.id = uuid.uuid4().hex
        self._command = command
        self._message_event = threading.Event()
        self._done_event = threading.Event()
        self._message: Optional[str] = None
        self._result: Optional[KubeloginResult] = None
        self._error: Optional[str] = None
        self._thread = threading.Thread(target=self._run, name=f"kubelogin-{self.id}")
        self._thread.daemon = True
        self._thread.start()

    @property
    def message(self) -> Optional[str]:
        return self._message

    @property
    def error(self) -> Optional[str]:
        return self._error

    @property
    def result(self) -> Optional[KubeloginResult]:
        return self._result

    def wait_for_message(self, timeout: float | None = None) -> Optional[str]:
        self._message_event.wait(timeout=timeout)
        return self._message

    def is_finished(self) -> bool:
        return self._done_event.is_set()

    def wait(self, timeout: float | None = None) -> None:
        self._done_event.wait(timeout=timeout)

    def _run(self) -> None:
        settings = get_settings()
        logger.info("Starting kubelogin job %s", self.id)
        try:
            process = subprocess.Popen(
                self._command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            self._error = (
                f"kubelogin binary '{settings.kubelogin_binary}' was not found on PATH"
            )
            logger.error("%s", self._error)
            self._message_event.set()
            self._done_event.set()
            return

        stdout_lines: list[str] = []
        json_lines: list[str] = []
        pre_json_lines: list[str] = []
        json_started = False

        if process.stdout is None or process.stderr is None:
            self._error = "kubelogin process did not expose stdout/stderr"
            self._message_event.set()
            self._done_event.set()
            return

        for line in iter(process.stdout.readline, ""):
            stdout_lines.append(line)
            stripped = line.lstrip()
            if not json_started and stripped.startswith("{"):
                json_started = True
                json_lines.append(line)
                continue

            if json_started:
                json_lines.append(line)
            else:
                pre_json_lines.append(line)
                lowered = line.lower()
                if "microsoft.com/devicelogin" in lowered and not self._message_event.is_set():
                    self._message = "".join(pre_json_lines).strip()
                    self._message_event.set()

        stdout_remaining = process.stdout.read()
        if stdout_remaining:
            stdout_lines.append(stdout_remaining)
            if json_started:
                json_lines.append(stdout_remaining)
            else:
                pre_json_lines.append(stdout_remaining)

        stderr_output = process.stderr.read()
        process.wait()

        if not self._message_event.is_set():
            # Either there was no interactive prompt or kubelogin reused cached tokens.
            self._message = "".join(pre_json_lines).strip() or None
            self._message_event.set()

        if process.returncode != 0:
            combined_output = "".join(stdout_lines)
            details = stderr_output.strip() or combined_output.strip()
            self._error = (
                f"kubelogin exited with code {process.returncode}. Output: {details}"
            )
            logger.error("kubelogin job %s failed: %s", self.id, self._error)
            self._done_event.set()
            return

        json_payload = "".join(json_lines).strip()
        if not json_payload:
            self._error = "kubelogin did not emit ExecCredential JSON"
            logger.error("kubelogin job %s produced no JSON payload", self.id)
            self._done_event.set()
            return

        try:
            parsed = json.loads(json_payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            self._error = f"Failed to decode kubelogin output: {exc}"
            logger.error("kubelogin job %s returned malformed JSON: %s", self.id, exc)
            self._done_event.set()
            return

        status = parsed.get("status") or {}
        token = status.get("token")
        expiration = status.get("expirationTimestamp")
        if not token or not expiration:
            self._error = "kubelogin output missing token or expiration"
            logger.error("kubelogin job %s returned incomplete status", self.id)
            self._done_event.set()
            return

        try:
            expires_on = _parse_expiration(expiration)
        except ValueError as exc:  # pragma: no cover - indicates malformed timestamp
            self._error = f"Invalid expiration timestamp from kubelogin: {exc}"
            logger.error("kubelogin job %s returned invalid expiration: %s", self.id, exc)
            self._done_event.set()
            return

        self._result = KubeloginResult(access_token=token, expires_on=expires_on)
        logger.info("kubelogin job %s succeeded", self.id)
        self._done_event.set()


def _parse_expiration(expiration: str) -> int:
    """Convert an RFC3339 timestamp to epoch seconds."""

    exp = expiration.strip()
    if exp.endswith("Z"):
        exp = exp[:-1] + "+00:00"
    dt = datetime.fromisoformat(exp)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


_jobs: Dict[str, KubeloginJob] = {}
_jobs_lock = threading.Lock()


def start_job(login_hint: Optional[str]) -> KubeloginJob:
    """Launch kubelogin in the background and return the job handle."""

    settings = get_settings()
    if not settings.kubelogin_enabled:
        raise KubeloginError("kubelogin integration is disabled")

    command = [
        settings.kubelogin_binary,
        "get-token",
        "--login",
        settings.kubelogin_login,
        "--server-id",
        settings.aks_server_app_id,
        "--tenant-id",
        settings.tenant_id,
        "--client-id",
        settings.kubelogin_client_id,
        "--environment",
        settings.kubelogin_environment,
    ]
    if login_hint:
        command.extend(["--login-hint", login_hint])

    job = KubeloginJob(command)
    with _jobs_lock:
        _jobs[job.id] = job
    return job


def get_job(job_id: str) -> Optional[KubeloginJob]:
    with _jobs_lock:
        return _jobs.get(job_id)


def remove_job(job_id: str) -> None:
    with _jobs_lock:
        _jobs.pop(job_id, None)


def build_token_entry(result: KubeloginResult, scope: str) -> Dict[str, object]:
    """Convert a kubelogin result into the session token structure."""

    return {
        "access_token": result.access_token,
        "expires_on": result.expires_on,
        "scope": scope,
        "token_type": "Bearer",
        "acquired_at": int(time.time()),
    }
