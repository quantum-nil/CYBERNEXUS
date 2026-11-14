"""OIDC-compatible JWT/JWKS validation and identity synchronization."""
import json
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any
import jwt
from fastapi import HTTPException, Header, Cookie, Depends
from jwt import PyJWKClient
from backend.app.core.config import settings
from backend.app.models.models import AppUser, LegacyIdentityLink, Tenant, TenantMember, AuditLog
from backend.app.db.session import get_db

_jwks: PyJWKClient | None = None

@dataclass
class Principal:
    user_id: str
    external_subject: str | None
    role: str
    authenticated: bool
    tenant_id: str = "default"
    email: str | None = None
    legacy_ids: tuple[str, ...] = ()

def _admin_roles() -> set[str]:
    return {x.strip() for x in settings.oidc_admin_roles.split(",") if x.strip()}

def _roles(claims: dict[str, Any]) -> set[str]:
    roles = set(claims.get("roles") or [])
    if claims.get("role"):
        roles.add(str(claims["role"]))
    roles.update(claims.get("groups") or [])
    roles.update((claims.get("realm_access") or {}).get("roles") or [])
    return {str(x).lower() for x in roles}

def issue_jwt_token(user_id: str, email: str, role: str = "member", tenant_id: str = "default", name: str = "") -> str:
    """Issue a cryptographically signed JWT conveying authenticated identity, role, and tenant claims."""
    now = datetime.now(timezone.utc)
    secret = settings.admin_api_token or "cybernexus-platform-secret-key-32b"
    claims = {
        "sub": user_id,
        "email": email,
        "name": name or email.split("@")[0],
        "role": role,
        "roles": [role],
        "tenant_id": tenant_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.session_max_age_seconds)).timestamp()),
        "iss": "cybernexus-auth",
        "aud": "cybernexus-platform"
    }
    return jwt.encode(claims, secret, algorithm="HS256")

def verify_token(token: str) -> dict[str, Any]:
    global _jwks
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise HTTPException(401, "Invalid token format") from exc

    alg = header.get("alg", "HS256")
    if alg in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"} and settings.oidc_issuer_url and settings.oidc_audience:
        try:
            _jwks = _jwks or PyJWKClient(settings.oidc_jwks_url or settings.oidc_issuer_url.rstrip("/") + "/.well-known/jwks.json")
            key = _jwks.get_signing_key_from_jwt(token)
            return jwt.decode(token, key.key, algorithms=[alg], audience=settings.oidc_audience, issuer=settings.oidc_issuer_url, options={"require": ["exp", "sub"]})
        except Exception as exc:
            raise HTTPException(401, "Invalid or expired OIDC authentication token") from exc
    else:
        secret = settings.admin_api_token or "cybernexus-platform-secret-key-32b"
        try:
            return jwt.decode(token, secret, algorithms=["HS256"], options={"verify_aud": False})
        except Exception as exc:
            raise HTTPException(401, "Invalid or expired authentication token") from exc

def record_audit_event(
    db,
    user_id: str,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    tenant_id: str = "default",
    ip_address: str | None = None
) -> AuditLog:
    """Record an immutable audit log entry for privileged actions, auth events, and access checks."""
    entry = AuditLog(
        tenant_id=tenant_id or "default",
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        details_json=json.dumps(details or {}),
        ip_address=ip_address,
        timestamp=datetime.now(timezone.utc)
    )
    db.add(entry)
    db.flush()
    return entry

def sync_user(db, claims: dict[str, Any]) -> Principal:
    subject = str(claims.get("sub") or claims.get("email") or "unknown")
    roles = _roles(claims)
    if "admin" in roles or bool(roles & _admin_roles()):
        role = "admin"
    elif "analyst" in roles:
        role = "analyst"
    else:
        role = "member"
    now = datetime.now(timezone.utc)
    tenant_id = str(claims.get("tenant_id") or "default")
    email = claims.get("email")
    display_name = claims.get("name") or claims.get("preferred_username") or (email.split("@")[0] if email else subject)
    user = db.query(AppUser).filter(AppUser.external_subject == subject).first()
    if not user:
        user = AppUser(external_subject=subject, email=email, display_name=display_name, role=role, account_status="active", last_login_at=now)
        db.add(user)
        db.flush()
    else:
        user.email = email or user.email
        user.display_name = display_name or user.display_name
        user.role = role
        user.last_login_at = now
    if user.account_status != "active":
        raise HTTPException(403, "Account is not active")

    # Ensure tenant exists
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        tenant = Tenant(id=tenant_id, name=f"{tenant_id.replace('-', ' ').title()} Organization")
        db.add(tenant)
        db.flush()

    # Ensure tenant membership
    member = db.query(TenantMember).filter(TenantMember.tenant_id == tenant_id, TenantMember.user_id == f"user:{user.id}").first()
    if not member:
        member = TenantMember(tenant_id=tenant_id, user_id=f"user:{user.id}", role=role)
        db.add(member)
        db.flush()

    legacy_ids = tuple(link.legacy_user_id for link in db.query(LegacyIdentityLink).filter(LegacyIdentityLink.external_subject == subject).all())
    return Principal(user_id=f"user:{user.id}", external_subject=subject, role=user.role, authenticated=True, tenant_id=tenant_id, email=email, legacy_ids=legacy_ids)

def principal_from_headers(db, authorization: str | None, cookie: str | None, legacy_header: str | None) -> Principal:
    token = authorization.removeprefix("Bearer ").strip() if authorization and authorization.startswith("Bearer ") else cookie
    if token:
        return sync_user(db, verify_token(token))
    if settings.auth_required:
        raise HTTPException(401, "Authentication required")
    # Anonymous passive access is allowed when AUTH_REQUIRED is disabled.
    legacy = (legacy_header or "anonymous").strip()[:160] or "anonymous"
    return Principal(user_id=legacy, external_subject=None, role="user", authenticated=False, tenant_id="default", legacy_ids=(legacy,))

def get_current_principal(authorization: str | None = Header(default=None), digital_trust_session: str | None = Cookie(default=None), x_user_id: str | None = Header(default=None, alias="X-User-ID"), db=Depends(get_db)) -> Principal:
    return principal_from_headers(db, authorization, digital_trust_session, x_user_id)
