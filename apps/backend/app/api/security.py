from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

from fastapi import Request, Response, WebSocket, WebSocketDisconnect
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


@dataclass
class Session:
    token: str
    csrf: str
    created_at: float
    last_seen: float
    expires_at: float


class SecurityManager:
    """Ephemeral capability/session authority; secrets never enter SQLite or process arguments."""

    def __init__(self, origin: str = "http://127.0.0.1:0", bootstrap_ticket: str | None = None):
        self.origin = origin.rstrip("/")
        self._bootstrap: dict[str, float] = {}
        self._sessions: dict[str, Session] = {}
        self._ws_tickets: dict[str, tuple[str, float]] = {}
        self._configured_bootstrap = bootstrap_ticket
        if bootstrap_ticket:
            self._bootstrap[bootstrap_ticket] = time.time() + 30

    def issue_bootstrap_ticket(self) -> str:
        self._prune()
        if len(self._bootstrap) >= 64:
            raise RuntimeError("Too many pending bootstrap tickets")
        ticket = secrets.token_urlsafe(32)
        self._bootstrap[ticket] = time.time() + 30
        return ticket

    def _prune(self):
        now = time.time()
        self._bootstrap = {key: expiry for key, expiry in self._bootstrap.items() if expiry > now}
        self._ws_tickets = {key: item for key, item in self._ws_tickets.items() if item[1] > now}
        self._sessions = {key: item for key, item in self._sessions.items() if item.expires_at > now}

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def exchange(self, ticket: str) -> Session | None:
        self._prune()
        now = time.time()
        expiry = self._bootstrap.pop(ticket, None)
        if expiry is None or expiry < now or not hmac.compare_digest(ticket, ticket.strip()) or len(self._sessions) >= 64:
            return None
        session = Session(secrets.token_urlsafe(32), secrets.token_urlsafe(32), now, now, now + 12 * 3600)
        self._sessions[session.token] = session
        return session

    def current(self, token: str | None) -> Session | None:
        if not token:
            return None
        session = self._sessions.get(token)
        if session is None or session.expires_at <= time.time():
            if session:
                self._sessions.pop(token, None)
            return None
        session.last_seen = time.time()
        return session

    def revoke(self, token: str | None):
        if token:
            self._sessions.pop(token, None)

    def issue_ws_ticket(self, session: Session) -> str:
        self._prune()
        if len(self._ws_tickets) >= 128:
            raise RuntimeError("Too many pending WebSocket tickets")
        ticket = secrets.token_urlsafe(32)
        self._ws_tickets[ticket] = (session.token, time.time() + 30)
        return ticket

    def consume_ws_ticket(self, ticket: str, session: Session | None) -> bool:
        item = self._ws_tickets.pop(ticket, None)
        if item is None or session is None or item[1] < time.time():
            return False
        return hmac.compare_digest(item[0], session.token)

    def set_session_cookie(self, response: Response, session: Session):
        response.set_cookie("tm_session", session.token, httponly=True, samesite="strict", max_age=43200,
                            path="/", secure=False)

    def clear_session_cookie(self, response: Response):
        response.delete_cookie("tm_session", path="/")

    async def authenticate_websocket(self, websocket: WebSocket) -> Session | None:
        if not self.check_origin(websocket.headers.get("origin"), websocket.headers.get("host"), require_origin=True):
            await websocket.close(code=1008)
            return None
        token = websocket.cookies.get("tm_session")
        session = self.current(token)
        if session is None:
            await websocket.close(code=1008)
            return None
        try:
            await websocket.accept()
            frame = await asyncio.wait_for(websocket.receive_json(), timeout=3)
        except (TimeoutError, WebSocketDisconnect, RuntimeError, ValueError):
            await websocket.close(code=1008)
            return None
        ticket = frame.get("ticket") if isinstance(frame, dict) and frame.get("type") == "authenticate" else None
        if not isinstance(ticket, str) or not self.consume_ws_ticket(ticket, session):
            await websocket.close(code=1008)
            return None
        return session

    def check_origin(self, origin: str | None, host: str | None, require_origin: bool = False) -> bool:
        expected_host = self.origin.split("://", 1)[-1]
        if host != expected_host:
            return False
        return origin == self.origin if require_origin else origin in (None, self.origin)


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, security: SecurityManager):
        super().__init__(app)
        self.security = security

    async def dispatch(self, request: Request, call_next):
        if not self.security.check_origin(request.headers.get("origin"), request.headers.get("host")):
            return JSONResponse({"code": "ORIGIN_REJECTED", "message": "Host or Origin is not this loopback instance"}, status_code=403)
        request.state.session = self.security.current(request.cookies.get("tm_session"))
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path not in (
                "/healthz", "/api/v1/sessions/exchange"):
            session = request.state.session
            csrf = request.headers.get("x-csrf-token")
            valid_csrf = bool(session and csrf and csrf.isascii() and hmac.compare_digest(csrf, session.csrf))
            if not valid_csrf:
                return JSONResponse({"code": "CSRF_REQUIRED", "message": "A valid session and CSRF token are required"}, status_code=401)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


def session_digest(session: Session | None) -> str | None:
    return SecurityManager._digest(session.token) if session else None
