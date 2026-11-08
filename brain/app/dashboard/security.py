import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request

COOKIE_NAME = "city_dashboard_session"


@dataclass(frozen=True)
class DashboardSession:
    role: str
    csrf: str
    expires_at: datetime


class DashboardSessions:
    def __init__(self, lifetime_seconds: int) -> None:
        self.lifetime = timedelta(seconds=lifetime_seconds)
        self._sessions: dict[str, DashboardSession] = {}

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def create(self, role: str) -> tuple[str, DashboardSession]:
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        session = DashboardSession(role, csrf, datetime.now(UTC) + self.lifetime)
        self._sessions[self._digest(token)] = session
        return token, session

    def get(self, token: str | None) -> DashboardSession:
        session = self._sessions.get(self._digest(token or ""))
        if session is None or session.expires_at <= datetime.now(UTC):
            raise HTTPException(401, "dashboard session expired")
        return session

    def revoke(self, token: str | None) -> None:
        self._sessions.pop(self._digest(token or ""), None)


def dashboard_session(request: Request) -> DashboardSession:
    return request.app.state.dashboard_sessions.get(request.cookies.get(COOKIE_NAME))


def require_dashboard_role(request: Request, *roles: str) -> DashboardSession:
    session = dashboard_session(request)
    if session.role not in roles:
        raise HTTPException(403, "insufficient dashboard role")
    return session


def require_csrf(request: Request, session: DashboardSession) -> None:
    supplied = request.headers.get("X-Dashboard-CSRF", "")
    if not supplied or not secrets.compare_digest(supplied, session.csrf):
        raise HTTPException(403, "invalid dashboard CSRF token")
