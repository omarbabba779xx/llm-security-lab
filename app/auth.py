"""Authentication & Authorization — JWT short-lived tokens + capability-based RBAC.

Supports two modes:
- **JWT mode** (production-like): issues short-lived tokens via /auth/token, validated with HS256.
- **Static token mode** (backward-compatible demo): env-var tokens for quick testing.

Set LLM_LAB_AUTH_MODE=jwt to enable JWT. Default is static for backward compatibility.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from enum import Enum

from fastapi import Header, HTTPException

# ---------------------------------------------------------------------------
# Capabilities (fine-grained permissions)
# ---------------------------------------------------------------------------

class Capability(str, Enum):
    RAG_READ = "rag:read"
    RAG_WRITE = "rag:write"
    TOOL_READ_FILE = "tool:read_file"
    TOOL_WRITE_FILE = "tool:write_file"
    TOOL_SEND_EMAIL = "tool:send_email"
    TOOL_CALCULATOR = "tool:calculator"
    TOOL_SEARCH_DB = "tool:search_db"
    TOOL_SHELL = "tool:shell"
    SECURITY_SCAN = "security:scan"
    SECURITY_AUDIT = "security:audit"
    ADMIN = "admin"


ROLE_CAPABILITIES: dict[str, frozenset[Capability]] = {
    "reader": frozenset({
        Capability.RAG_READ,
        Capability.TOOL_READ_FILE,
        Capability.TOOL_CALCULATOR,
        Capability.TOOL_SEARCH_DB,
        Capability.SECURITY_SCAN,
    }),
    "editor": frozenset({
        Capability.RAG_READ,
        Capability.RAG_WRITE,
        Capability.TOOL_READ_FILE,
        Capability.TOOL_WRITE_FILE,
        Capability.TOOL_SEND_EMAIL,
        Capability.TOOL_CALCULATOR,
        Capability.TOOL_SEARCH_DB,
        Capability.SECURITY_SCAN,
    }),
    "admin": frozenset({
        Capability.RAG_READ,
        Capability.RAG_WRITE,
        Capability.TOOL_READ_FILE,
        Capability.TOOL_WRITE_FILE,
        Capability.TOOL_SEND_EMAIL,
        Capability.TOOL_CALCULATOR,
        Capability.TOOL_SEARCH_DB,
        Capability.TOOL_SHELL,
        Capability.SECURITY_SCAN,
        Capability.SECURITY_AUDIT,
        Capability.ADMIN,
    }),
}

TOOL_CAPABILITY_MAP: dict[str, Capability] = {
    "read_file": Capability.TOOL_READ_FILE,
    "write_file": Capability.TOOL_WRITE_FILE,
    "send_email": Capability.TOOL_SEND_EMAIL,
    "calculator": Capability.TOOL_CALCULATOR,
    "search_db": Capability.TOOL_SEARCH_DB,
    "shell": Capability.TOOL_SHELL,
}


# ---------------------------------------------------------------------------
# AuthContext
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthContext:
    user_id: str
    roles: frozenset[str]
    capabilities: frozenset[Capability] = field(default_factory=frozenset)
    token_exp: datetime.datetime | None = None
    correlation_id: str = ""

    def has_capability(self, cap: Capability) -> bool:
        return cap in self.capabilities

    def has_any_role(self, *roles: str) -> bool:
        return bool(set(roles).intersection(self.roles))


# ---------------------------------------------------------------------------
# JWT helpers (no PyJWT dependency — lightweight HS256 implementation)
# ---------------------------------------------------------------------------

_JWT_SECRET = os.getenv("LLM_LAB_JWT_SECRET", secrets.token_urlsafe(32))
_JWT_ISSUER = "llm-security-lab"
_JWT_TTL_MINUTES = int(os.getenv("LLM_LAB_JWT_TTL_MINUTES", "30"))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def create_jwt(user_id: str, roles: list[str]) -> dict:
    """Create a short-lived JWT token."""
    now = datetime.datetime.now(datetime.UTC)
    exp = now + datetime.timedelta(minutes=_JWT_TTL_MINUTES)

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "roles": roles,
        "iss": _JWT_ISSUER,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    header_b64 = _b64url_encode(json.dumps(header).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    signature_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(_JWT_SECRET.encode(), signature_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)

    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": _JWT_TTL_MINUTES * 60,
        "expires_at": exp.isoformat(),
    }


def verify_jwt(token: str) -> dict:
    """Verify and decode a JWT token. Raises ValueError on failure."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    header_b64, payload_b64, signature_b64 = parts

    expected_sig = hmac.new(
        _JWT_SECRET.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256,
    ).digest()
    actual_sig = _b64url_decode(signature_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid JWT signature")

    payload = json.loads(_b64url_decode(payload_b64))

    if payload.get("iss") != _JWT_ISSUER:
        raise ValueError("Invalid JWT issuer")

    now = datetime.datetime.now(datetime.UTC).timestamp()
    if payload.get("exp", 0) < now:
        raise ValueError("JWT token expired")

    return payload


# ---------------------------------------------------------------------------
# Static tokens (backward-compatible)
# ---------------------------------------------------------------------------

_STATIC_TOKENS = {
    "admin": os.getenv("LLM_LAB_ADMIN_TOKEN") or secrets.token_urlsafe(24),
    "editor": os.getenv("LLM_LAB_EDITOR_TOKEN") or secrets.token_urlsafe(24),
    "reader": os.getenv("LLM_LAB_READER_TOKEN") or secrets.token_urlsafe(24),
}


def get_demo_api_key(role: str) -> str:
    """Expose demo tokens for tests and local integration."""
    if role not in _STATIC_TOKENS:
        raise KeyError(f"Role inconnu: {role}")
    return _STATIC_TOKENS[role]


_STATIC_TOKEN_MAP: dict[str, AuthContext] = {}


def _build_static_token_map() -> dict[str, AuthContext]:
    if not _STATIC_TOKEN_MAP:
        for role_name, token_value in _STATIC_TOKENS.items():
            roles_set = frozenset(
                r for r in ["admin", "editor", "reader"]
                if list(["admin", "editor", "reader"]).index(r) >= list(["admin", "editor", "reader"]).index(role_name)
            )
            caps = frozenset().union(*(ROLE_CAPABILITIES.get(r, frozenset()) for r in roles_set))
            _STATIC_TOKEN_MAP[token_value] = AuthContext(
                user_id=f"lab-{role_name}",
                roles=roles_set,
                capabilities=caps,
            )
    return _STATIC_TOKEN_MAP


# ---------------------------------------------------------------------------
# Auth mode detection
# ---------------------------------------------------------------------------

def _auth_mode() -> str:
    return os.getenv("LLM_LAB_AUTH_MODE", "static").strip().lower()


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

def resolve_auth(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
) -> AuthContext:
    """Resolve identity from static token or JWT Bearer."""
    # Try JWT first if Authorization header present
    if authorization and authorization.lower().startswith("bearer "):
        jwt_token = authorization[7:].strip()
        try:
            payload = verify_jwt(jwt_token)
            roles = frozenset(payload.get("roles", []))
            caps = frozenset().union(*(ROLE_CAPABILITIES.get(r, frozenset()) for r in roles))
            return AuthContext(
                user_id=payload["sub"],
                roles=roles,
                capabilities=caps,
                token_exp=datetime.datetime.fromtimestamp(payload["exp"], tz=datetime.UTC),
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=f"JWT invalide: {exc}") from exc

    # Fallback to static token
    if x_api_key:
        token_map = _build_static_token_map()
        ctx = token_map.get(x_api_key)
        if ctx is not None:
            return ctx
        raise HTTPException(status_code=401, detail="Jeton API invalide")

    raise HTTPException(status_code=401, detail="Authentification requise (X-API-Key ou Bearer JWT)")


def require_capability(*caps: Capability):
    """Factory for a FastAPI dependency that requires specific capabilities."""
    from fastapi import Depends

    def dependency(user: AuthContext = Depends(resolve_auth)) -> AuthContext:
        missing = [c for c in caps if not user.has_capability(c)]
        if missing:
            raise HTTPException(
                status_code=403,
                detail=f"Capabilities manquantes: {', '.join(c.value for c in missing)}",
            )
        return user

    return dependency


def require_roles(*required_roles: str):
    """Factory for a FastAPI dependency that requires at least one of the roles."""
    from fastapi import Depends

    def dependency(user: AuthContext = Depends(resolve_auth)) -> AuthContext:
        if not user.has_any_role(*required_roles):
            raise HTTPException(status_code=403, detail="Role insuffisant")
        return user

    return dependency
