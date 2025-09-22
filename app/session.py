"""In-memory session manager for the OAuth proxy."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class SessionEntry:
    """Internal representation of a single session."""

    data: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_access: float = field(default_factory=time.time)


class SessionHandle:
    """Lightweight wrapper returned to request handlers."""

    def __init__(self, manager: "SessionManager", session_id: str, entry: SessionEntry):
        self._manager = manager
        self._session_id = session_id
        self._entry = entry

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def data(self) -> Dict[str, Any]:
        return self._entry.data

    def commit(self, response) -> None:
        """Persist the session metadata and attach the cookie to the response."""

        self._entry.last_access = time.time()
        self._manager._set_cookie(response, self._session_id)

    def rotate(self, response) -> Dict[str, Any]:
        """Replace the current session with a new one and set the cookie."""

        new_session_id, new_entry = self._manager._rotate_session(self._session_id)
        self._session_id = new_session_id
        self._entry = new_entry
        self._manager._set_cookie(response, new_session_id)
        return self._entry.data


class SessionManager:
    """A minimal in-memory session store keyed by a secure random cookie."""

    def __init__(
        self,
        cookie_name: str,
        idle_timeout_seconds: int,
        absolute_timeout_seconds: int,
        *,
        cookie_secure: bool,
        cookie_samesite: str,
    ) -> None:
        self._cookie_name = cookie_name
        self._idle_timeout = idle_timeout_seconds
        self._absolute_timeout = absolute_timeout_seconds
        self._cookie_secure = cookie_secure
        self._cookie_samesite = cookie_samesite
        self._sessions: Dict[str, SessionEntry] = {}
        self._lock = threading.Lock()

    def load_session(self, request) -> SessionHandle:
        """Retrieve or create the session associated with the incoming request."""

        session_id = request.cookies.get(self._cookie_name)
        now = time.time()
        with self._lock:
            # Clean up any expired sessions to keep the in-memory store
            # bounded. This is a lightweight operation because the number of
            # sessions is typically small.
            self._purge_expired(now)
            entry = None
            if session_id:
                entry = self._sessions.get(session_id)
                if entry and self._is_expired(entry, now):
                    # If the cookie references an expired session we discard
                    # it to force creation of a fresh session entry.
                    del self._sessions[session_id]
                    entry = None

            if entry is None:
                # Either no session cookie was presented, or the referenced
                # session expired. Create a new entry and return it to the
                # caller.
                session_id, entry = self._create_session_locked()
            else:
                # For existing sessions we simply mark the last access time
                # so idle expiry works correctly.
                entry.last_access = now

        return SessionHandle(self, session_id, entry)

    def _create_session_locked(self) -> tuple[str, SessionEntry]:
        session_id = secrets.token_urlsafe(32)
        entry = SessionEntry()
        self._sessions[session_id] = entry
        return session_id, entry

    def _rotate_session(self, old_session_id: str) -> tuple[str, SessionEntry]:
        with self._lock:
            if old_session_id in self._sessions:
                # Drop the old session entirely; rotation is used when the
                # user signs in to prevent session fixation.
                del self._sessions[old_session_id]
            return self._create_session_locked()

    def _purge_expired(self, now: float) -> None:
        # Collect keys first so we can safely delete while iterating.
        expired = [
            session_id
            for session_id, entry in self._sessions.items()
            if self._is_expired(entry, now)
        ]
        for session_id in expired:
            del self._sessions[session_id]

    def _is_expired(self, entry: SessionEntry, now: float) -> bool:
        # The idle timeout ensures sessions disappear after inactivity,
        # whereas the absolute timeout bounds the maximum lifetime even for
        # busy sessions.
        if self._idle_timeout and now - entry.last_access > self._idle_timeout:
            return True
        if self._absolute_timeout and now - entry.created_at > self._absolute_timeout:
            return True
        return False

    def _set_cookie(self, response, session_id: str) -> None:
        max_age = self._absolute_timeout if self._absolute_timeout > 0 else None
        response.set_cookie(
            self._cookie_name,
            session_id,
            max_age=max_age,
            httponly=True,
            secure=self._cookie_secure,
            samesite=self._cookie_samesite,
            path="/",
        )

