from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from silentbug_lite.models import ParsedModule

AUTH_HINTS = (
    "current_user", "current_admin", "current_active", "auth", "token", "jwt",
    "login_required", "require", "permission", "role", "scope", "principal",
    "identity", "guard", "protect", "verify", "logged_in", "staff",
    "superuser", "admin_required",
)
# Deliberately absent: "session". `Depends(get_db_session)` is a database handle, and
# treating it as auth would invent an auth pattern that isn't there.
RATE_LIMIT_HINTS = ("limit", "throttl", "ratelimit", "rate_limit")
DESTRUCTIVE_WORDS = (
    "delete", "remove", "destroy", "drop", "purge", "wipe", "reset", "truncate",
    "revoke", "ban", "deactivate", "disable", "refund", "transfer", "payout",
    "withdraw", "grant", "promote", "erase", "clear",
)
DESTRUCTIVE_METHODS = frozenset({"DELETE", "PUT", "PATCH", "POST", "ANY"})

_NOT_AUTH = ("require_http_methods", "require_get", "require_post", "require_safe",
             "requirement", "requires_csrf")


def looks_like_auth(name: str) -> bool:
    lowered = name.lower()
    if lowered.split(".")[-1].startswith(_NOT_AUTH):
        return False  # Django's HTTP-method decorators say nothing about who may call
    return any(hint in lowered for hint in AUTH_HINTS)


def looks_like_rate_limit(name: str) -> bool:
    """A throttle guard (`ThrottlerGuard`) is not an auth check, though it ends in Guard."""
    lowered = name.lower()
    return any(hint in lowered for hint in RATE_LIMIT_HINTS)


@dataclass(frozen=True)
class Route:
    """One HTTP handler, described the same way for every framework."""

    framework: str
    method: str  # GET, POST, ... or ANY when the framework doesn't say
    path: str
    name: str
    line: int  # where the handler is defined
    node: Any  # the handler node (ast or tree-sitter)
    auth: frozenset[str] = frozenset()  # auth markers found on this route
    public: bool = False  # explicitly public (AllowAny, @Public, ...): never flagged


class FrameworkAdapter(Protocol):
    name: str
    languages: frozenset[str]

    def routes(self, module: ParsedModule) -> list[Route]: ...
