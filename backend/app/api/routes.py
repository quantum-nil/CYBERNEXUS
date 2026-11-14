import hashlib
import json
import re
import secrets
import httpx
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Header, UploadFile, File, BackgroundTasks, Query, Response, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import asc, case, cast, desc, func, or_, String as SQLString
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from backend.app.db.session import get_db, SessionLocal
from backend.app.models.models import Scan, CommunityReport, DomainIntelligence, ProviderVerdict, ThreatIndicator, RedirectHop, BrandRegistry, BrandVerificationEvidence, BrandVerificationChallenge, BrandVerificationAudit, BrandLogoAsset, BrandImageReference, WebsiteImageCandidate, ImageComparison, CertificateRecord, CertificateChainLink, CertificateValidationResult, CertificateRevocationResult, CertificateRevocationJob, CertificateTransparencyEntry, CertificateTransparencyAnomaly, CertificateRiskAssessment, EmailAnalysis, EmailHeader, EmailAuthenticationResult, EmailHeaderAnomaly, EmailRawMessage, EmailSmtpContext, EmailVerificationRun, MessageAnalysisRecord, MessageIndicatorResult, MessageDomainSpoofingFinding, EmailProviderRegistry, ContactRiskAssessment, IntelligenceVerification, BackgroundTaskRun, MessageAnalysisMetadata, MessageContent, MessageAnalysisEvent, AppUser, LegacyIdentityLink, MessageReview, MessageReviewAudit, MessageReviewFeedback, MLDatasetVersion, MLModelVersion, MLDeploymentHistory, MLTrainingRun, SecurityAssessment, SecurityFinding, RemediationRecord, SecurityAuthorization, AssessmentEvent, ThreatIntelligenceReport, ReportRevision, WalletChallenge, WalletIdentity, DigitalSignature, EvidenceObject, FindingEvidenceProvenance, Tenant, TenantMember, RateLimitRecord, AbuseEvent, AuditLog
from backend.app.schemas.schemas import ScanRequest, ReportRequest, LinkRevisionRequest, VerifyHashRequest
from backend.app.services.scanner import scan
from backend.app.services.scanner import _destination_providers
from backend.app.services.evidence_provenance import extract_and_persist_provenance, serialize_provenance, verify_content_hash, canonicalize_evidence
from backend.app.engines.threats import check as check_threats
from backend.app.engines.domain_intelligence import collect as collect_domain_intelligence
from backend.app.engines.redirect_risk import score_redirect_chain
from backend.app.engines.risk import calculate
from backend.app.engines.infrastructure_graph import build_graph
from backend.app.engines.logo_similarity import fingerprint, compare, MAX_IMAGE_BYTES
from backend.app.engines.logo_similarity import compare_fingerprints
from backend.app.engines.brand_verification import create_challenge, verify as verify_brand_challenge
from backend.app.engines.message import analyze_message
from backend.app.engines.email_analysis import analyze_email, MAX_EMAIL_BYTES, verify_dkim_signatures, evaluate_spf_context, evaluate_dmarc_alignment
from backend.app.engines.message_intelligence import analyze_indicators
from backend.app.engines.correlation import correlate
from backend.app.services.infrastructure_correlation import run_infrastructure_correlation
from backend.app.services.message_similarity import correlate_messages, message_similarity_history
from backend.app.services.incident_campaigns import group_incidents, list_campaigns, set_campaign_status, reject_campaign_incident, merge_campaigns, split_campaign
from backend.app.services.investigation_graph import get_campaign_graph, get_incident_graph, campaign_timeline, incident_timeline
from backend.app.services.campaign_summaries import generate_campaign_summary, summary_history
from backend.app.engines.commitments import commitment
from backend.app.engines.ml import status as ml_status
from backend.app.services.llm import configuration_status, verify_connection as verify_llm_connection
from backend.app.core.config import settings
from backend.app.engines.contact_intelligence import phone_analysis, phone_provider_status
from backend.app.engines.email_authentication_verification import verify as verify_email_authentication
from backend.app.engines import email_security_investigation
from backend.app.services.cache import health as cache_health
from backend.app.services.auth import Principal, get_current_principal, sync_user, verify_token, issue_jwt_token, record_audit_event
from backend.app.db.session import engine
from backend.app.engines.google_safe_browsing import configuration_status as google_safe_browsing_configuration, verify_connection as verify_google_safe_browsing
from backend.app.engines.virustotal import configuration_status as virustotal_configuration, lookup_url as lookup_virustotal_url, submit_url as submit_virustotal_url, poll_analysis as poll_virustotal_analysis
from backend.app.engines.external_intelligence import status as external_intelligence_status, urlhaus_status as urlhaus_connectivity_status
from backend.app.engines.certificate_chain import _trusted_roots
from backend.app.engines.certificate_revocation import analyze_chain
from backend.app.services.security_assessments import create_assessment, serialize_assessment, serialize_finding, can_access, attach_scan_to_assessment
from backend.app.services.finding_management import accessible_query, managed_finding, remediation_status_expression, update_remediation, REMEDIATION_STATUSES
from backend.app.services.security_authorization import create as create_security_authorization, serialize as serialize_security_authorization, transition as transition_security_authorization, scope_allows as authorization_scope_allows, expire_if_needed as expire_security_authorization, AuthorizationStopped
from backend.app.engines.ca_reputation import configuration_status as ca_reputation_configuration
from backend.app.services.message_reports import bundle as build_message_report, csv_bytes as report_csv_bytes, pdf_bytes as report_pdf_bytes
from backend.app.services.security_assessment_reports import build_report as build_security_assessment_report, csv_bytes as security_report_csv_bytes, json_bytes as security_report_json_bytes, pdf_bytes as security_report_pdf_bytes, record_generation as record_security_report_generation, history as security_report_history, FORMATS as SECURITY_REPORT_FORMATS
from backend.app.services.decentralized_threat_intelligence import create_report as create_threat_report, serialize_report as serialize_threat_report, serialize_revision as serialize_threat_revision, get_owned_report as get_owned_threat_report, add_revision as add_threat_revision, commitment_for_revision as threat_commitment_for_revision, verify_local_commitment, provenance as threat_provenance, validation_history as threat_validation_history, blockchain_metadata as threat_blockchain_metadata, calculate_commitment
from backend.app.services.ledger import ledger_checkpoint, verify_ledger
from backend.app.services.scan_jobs import create_job, submit as submit_scan_job
from backend.app.services.privacy import privacy_summary
from backend.app.services.blockchain_anchor import verify_external_receipt, verify_configuration as blockchain_configuration_status
from backend.app.services.evm_blockchain import EVMBlockchainAdapter
from backend.app.services.wallet_signatures import ownership_challenge, verify_ownership, signature_challenge, verify_signature
from backend.app.services.evidence_storage import upload as upload_evidence, serialize_object as serialize_evidence, verify_object as verify_evidence, read_verified as read_verified_evidence, manifest_details, verify_manifest, pin_to_ipfs, cleanup_expired, can_access as can_access_evidence
from backend.app.services.ml_registry import validate_dataset, artifact_metadata, _safe_artifact, POINTER, MODEL_ROOT
from backend.app.workers import tasks as worker_tasks
from backend.app.services.local_ml_worker import submit as submit_local_retraining
from cryptography import x509

router = APIRouter()

def _refresh_revocation_job(job_id: int, scan_id: int):
    db=SessionLocal(); job=db.get(CertificateRevocationJob,job_id)
    try:
        if not job: return
        job.status="RUNNING"; job.started_at=datetime.now(timezone.utc); db.commit()
        scan_row=db.get(Scan,scan_id)
        if not scan_row: raise ValueError("scan_not_found")
        result=json.loads(scan_row.result_json); certificate=result.get("certificate",{}); items=[]
        for item in certificate.get("certificates",[]):
            if item.get("der"):
                items.append((x509.load_der_x509_certificate(bytes.fromhex(item["der"])),bytes.fromhex(item["der"])))
        refreshed=analyze_chain(items,_trusted_roots(),db) if items else {"status":"UNAVAILABLE","certificates":[]}
        certificate["revocation"]=refreshed; result["certificate"]=certificate; scan_row.result_json=json.dumps(result)
        db.query(CertificateRevocationResult).filter(CertificateRevocationResult.scan_id==scan_id).delete(synchronize_session=False)
        for item in refreshed.get("certificates",[]):
            aggregate=item.get("aggregate",{}); sources=aggregate.get("sources",{}); ca=item.get("ca_trust",{})
            db.add(CertificateRevocationResult(scan_id=scan_id,certificate_fingerprint=item.get("fingerprint_sha256",""),role=item.get("role","unknown"),status=aggregate.get("status","UNKNOWN"),ocsp_status=(sources.get("ocsp") or {}).get("status"),crl_status=(sources.get("crl") or {}).get("status"),distrust_status=ca.get("status"),ca_reputation=ca.get("ca_reputation"),evidence_json=json.dumps(item),checked_at=datetime.now(timezone.utc)))
        job.status="COMPLETED"; job.completed_at=datetime.now(timezone.utc); db.commit()
    except Exception as exc:
        db.rollback(); job=db.get(CertificateRevocationJob,job_id)
        if job: job.status="FAILED"; job.error=type(exc).__name__; job.completed_at=datetime.now(timezone.utc); db.commit()
    finally: db.close()

def admin_only(x_admin_token: str | None = Header(default=None), principal: Principal = Depends(get_current_principal)):
    if principal.role != "admin" and not _admin(x_admin_token): raise HTTPException(403, "Administrator role required")

def _owner(x_user_id: str | None) -> str:
    value = (x_user_id or "anonymous").strip()
    return value[:160] if value else "anonymous"

def _admin(x_admin_token: str | None) -> bool:
    # Static admin tokens are retained for local development only. Production
    # administration must come from the verified OIDC role claim.
    return settings.environment.lower() != "production" and bool(x_admin_token and x_admin_token == settings.admin_api_token)

def _scan_authorization(db, payload: ScanRequest, principal: Principal):
    """Validate scan mode and authorization boundary for a scanner request."""
    mode = (getattr(payload, "scan_mode", "PUBLIC_PASSIVE") or "PUBLIC_PASSIVE").upper()
    if mode == "AUTHORIZED_ACTIVE":
        if payload.authorization_id is None:
            raise HTTPException(403, "An approved authorization_id is required before active scanning")
        authorization = db.get(SecurityAuthorization, payload.authorization_id)
        if not authorization:
            raise HTTPException(403, "Authorization record not found")
        expire_security_authorization(db, authorization)
        if authorization.requester_user_id != principal.user_id and principal.role != "admin":
            raise HTTPException(403, "Authorization belongs to another requester")
        categories = [str(x).upper() for x in (payload.allowed_categories or ["FULL_SCAN"])]
        if not authorization_scope_allows(authorization, payload.url, None):
            raise HTTPException(403, "Target is outside the approved authorization scope")
        approved_categories = {str(x).upper() for x in json.loads(authorization.allowed_categories_json or "[]")}
        if "FULL_SCAN" not in approved_categories and "*" not in approved_categories and any(category not in approved_categories for category in categories):
            raise HTTPException(403, "Requested scan category is outside the approved authorization")
        if authorization.approval_status != "APPROVED":
            raise HTTPException(403, "Authorization is not approved")
        def guard():
            expire_security_authorization(db, authorization)
            db.refresh(authorization)
            if authorization.approval_status != "APPROVED" or not authorization_scope_allows(authorization, payload.url, None):
                raise AuthorizationStopped("active scan authorization is no longer valid")
        return authorization, guard
    elif mode == "AUTHENTICATED_PASSIVE":
        if not principal.authenticated and settings.auth_required:
            raise HTTPException(401, "Authentication required for user-owned scan history")
        return None, None
    elif mode == "ADMIN_REVIEW":
        if principal.role != "admin":
            raise HTTPException(403, "Administrator privilege required for admin review mode")
        return None, None
    else: # PUBLIC_PASSIVE
        required = settings.enforce_scan_authorization
        if required and payload.authorization_id is None:
            raise HTTPException(403, "An approved authorization_id is required when ENFORCE_SCAN_AUTHORIZATION is active")
        return None, None

def _enforce_rate_limits(db: Session, client_ip: str, principal: Principal, mode: str):
    if principal.role == "admin":
        return
    now = datetime.now(timezone.utc)
    minute_bucket = now.strftime("%Y-%m-%d-%H-%M")
    day_bucket = now.strftime("%Y-%m-%d")
    client_key = f"ip:{client_ip}" if not principal.authenticated else f"user:{principal.user_id}"
    min_record = db.query(RateLimitRecord).filter(RateLimitRecord.client_key == client_key, RateLimitRecord.window_bucket == minute_bucket).first()
    if min_record:
        if min_record.request_count >= 5 and mode == "PUBLIC_PASSIVE":
            db.add(AbuseEvent(event_type="RATE_LIMIT_EXCEEDED", client_ip=client_ip, user_id=principal.user_id, details_json=json.dumps({"limit": 5, "window": "minute"})))
            db.commit()
            raise HTTPException(429, "Rate limit exceeded. Maximum 5 scans per minute for public mode.")
        min_record.request_count += 1
        min_record.last_request_at = now
    else:
        db.add(RateLimitRecord(client_key=client_key, window_bucket=minute_bucket, request_count=1, last_request_at=now))
    if not principal.authenticated:
        day_record = db.query(RateLimitRecord).filter(RateLimitRecord.client_key == f"anon:{client_ip}", RateLimitRecord.window_bucket == day_bucket).first()
        if day_record:
            if day_record.request_count >= 50:
                db.add(AbuseEvent(event_type="DAILY_QUOTA_EXCEEDED", client_ip=client_ip, user_id="anonymous", details_json=json.dumps({"limit": 50, "window": "day"})))
                db.commit()
                raise HTTPException(429, "Daily quota exceeded for anonymous scans.")
            day_record.request_count += 1
            day_record.last_request_at = now
        else:
            db.add(RateLimitRecord(client_key=f"anon:{client_ip}", window_bucket=day_bucket, request_count=1, last_request_at=now))
    db.commit()

def _can_view(meta: MessageAnalysisMetadata, user_id: str, admin: bool, legacy_ids: tuple[str, ...] = ()) -> bool:
    return admin or meta.user_id in (user_id, *legacy_ids)

def _metadata_summary(meta: MessageAnalysisMetadata) -> dict:
    return {"analysis_id": meta.message_analysis_id or meta.email_analysis_id, "kind": meta.input_type, "user_id": meta.user_id, "sender": meta.sender, "subject": meta.subject, "created_at": meta.created_at, "risk_score": meta.risk_score, "classification": meta.classification, "ml_prediction": meta.ml_prediction, "ml_confidence": meta.ml_confidence, "llm_status": meta.llm_status, "model_version": meta.model_version, "analysis_status": meta.analysis_status, "duplicate_of_id": meta.duplicate_of_id}

@router.get("/health")
def health():
    database = "ok"
    try:
        with engine.connect() as connection: connection.execute(__import__("sqlalchemy").text("SELECT 1"))
    except Exception: database = "unavailable"
    return {"status": "ok" if database == "ok" else "degraded", "service": "digital-trust-intelligence", "database": database, "cache": cache_health()}

@router.get("/auth/config")
def auth_config():
    configured = bool(settings.oidc_issuer_url and settings.oidc_audience and settings.oidc_client_id and (settings.oidc_jwks_url or settings.oidc_issuer_url))
    configuration_error = None
    if settings.auth_required and not configured:
        configuration_error = "OIDC issuer, audience, client ID, and signing keys must be configured before organization sign-in can be used."
    if settings.auth_required and not settings.oidc_authorization_url:
        configuration_error = "OIDC authorization URL is not configured for this deployment."
    token_url = settings.oidc_token_url or ((settings.oidc_issuer_url.rstrip("/") + "/protocol/openid-connect/token") if settings.oidc_issuer_url else None)
    return {"provider": "OIDC", "required": settings.auth_required, "configured": configured, "configuration_error": configuration_error, "authorization_url": settings.oidc_authorization_url or None, "token_url": token_url, "client_id": settings.oidc_client_id or None, "redirect_uri": settings.oidc_redirect_uri, "scopes": settings.oidc_scopes.split()}

@router.get("/auth/oidc/start")
def auth_oidc_start(response: Response):
    if not settings.oidc_authorization_url:
        raise HTTPException(503, "OIDC authorization URL is not configured")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    parsed = urlparse(settings.oidc_authorization_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update({"client_id": settings.oidc_client_id, "response_type": "code", "scope": settings.oidc_scopes, "redirect_uri": settings.oidc_redirect_uri, "state": state, "nonce": nonce})
    redirect = RedirectResponse(urlunparse(parsed._replace(query=urlencode(query))))
    redirect.set_cookie("cybernexus_oidc_state", state, max_age=600, httponly=True, secure=settings.environment.lower() == "production", samesite="lax", path="/")
    redirect.set_cookie("cybernexus_oidc_nonce", nonce, max_age=600, httponly=True, secure=settings.environment.lower() == "production", samesite="lax", path="/")
    return redirect

@router.get("/auth/oidc/callback")
async def auth_oidc_callback(code: str, state: str, response: Response, request: Request, db: Session = Depends(get_db)):
    expected_state = request.cookies.get("cybernexus_oidc_state")
    if not expected_state or not secrets.compare_digest(expected_state, state):
        raise HTTPException(400, "Invalid OIDC state")
    token_url = settings.oidc_token_url or (settings.oidc_issuer_url.rstrip("/") + "/protocol/openid-connect/token")
    if not settings.oidc_client_id or not token_url:
        raise HTTPException(503, "OIDC token exchange is not configured")
    form = {"grant_type": "authorization_code", "code": code, "client_id": settings.oidc_client_id, "redirect_uri": settings.oidc_redirect_uri}
    if settings.oidc_client_secret:
        form["client_secret"] = settings.oidc_client_secret
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            token_response = await client.post(token_url, data=form)
            token_response.raise_for_status()
            tokens = token_response.json()
    except Exception as exc:
        raise HTTPException(502, "OIDC token exchange failed") from exc
    token = tokens.get("id_token") or tokens.get("access_token")
    if not token:
        raise HTTPException(502, "OIDC provider returned no usable token")
    claims = verify_token(token)
    expected_nonce = request.cookies.get("cybernexus_oidc_nonce")
    if expected_nonce and claims.get("nonce") and not secrets.compare_digest(expected_nonce, str(claims.get("nonce"))):
        raise HTTPException(401, "Invalid OIDC nonce")
    principal = sync_user(db, claims)
    record_audit_event(db=db, user_id=principal.user_id, action="AUTH_LOGIN", resource_type="auth", resource_id=principal.user_id, details={"provider": "OIDC", "tenant_id": principal.tenant_id}, tenant_id=principal.tenant_id, ip_address=request.client.host if request.client else None)
    db.commit()
    response.set_cookie(settings.session_cookie_name, token, max_age=settings.session_max_age_seconds, httponly=True, secure=settings.environment.lower() == "production", samesite="lax", path="/")
    response.delete_cookie("cybernexus_oidc_state", path="/")
    response.delete_cookie("cybernexus_oidc_nonce", path="/")
    return {"authenticated": True, "user_id": principal.user_id, "role": principal.role, "tenant_id": principal.tenant_id}

@router.get("/auth/me")
def auth_me(principal: Principal = Depends(get_current_principal)):
    if not principal.authenticated: return {"authenticated": False, "mode": "development"}
    return {
        "authenticated": True,
        "user_id": principal.user_id,
        "external_subject": principal.external_subject,
        "email": principal.email or principal.external_subject,
        "role": principal.role,
        "tenant_id": principal.tenant_id
    }

@router.post("/auth/login")
def auth_login(payload: dict, response: Response, request: Request, db: Session = Depends(get_db)):
    if settings.auth_required or settings.environment.lower() == "production":
        raise HTTPException(403, "Local sign-in is disabled; use the configured OIDC provider")
    email = str(payload.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(400, "Email is required")
    role = str(payload.get("role") or "member").strip().lower()
    if role not in {"admin", "analyst", "member"}:
        role = "member"
    tenant_id = str(payload.get("tenant_id") or "tenant_default").strip()
    name = str(payload.get("name") or email.split("@")[0]).strip()

    # Generate cryptographically signed JWT with tenant and role claims
    token = issue_jwt_token(user_id=email, email=email, role=role, name=name, tenant_id=tenant_id)
    claims = verify_token(token)
    principal = sync_user(db, claims)

    # Record login in audit log
    client_ip = request.client.host if request.client else "127.0.0.1"
    record_audit_event(
        db=db,
        user_id=principal.user_id,
        action="AUTH_LOGIN",
        resource_type="auth",
        resource_id=principal.user_id,
        details={"email": email, "role": principal.role, "tenant_id": principal.tenant_id, "provider": "local_jwt"},
        tenant_id=principal.tenant_id,
        ip_address=client_ip
    )
    db.commit()

    # Issue secure HttpOnly session cookie
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        secure=settings.environment.lower() == "production",
        samesite="lax",
        path="/"
    )
    return {
        "authenticated": True,
        "token": token,
        "user": {
            "user_id": principal.user_id,
            "email": email,
            "name": name,
            "role": principal.role,
            "tenant_id": principal.tenant_id
        }
    }

@router.post("/auth/session")
def auth_session(response: Response, authorization: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401, "Bearer token required")
    token = authorization[7:].strip(); principal = sync_user(db, verify_token(token)); db.commit(); response.set_cookie(settings.session_cookie_name, token, max_age=settings.session_max_age_seconds, httponly=True, secure=settings.environment.lower() == "production", samesite="lax", path="/")
    return {"authenticated": True, "user_id": principal.user_id, "role": principal.role, "tenant_id": principal.tenant_id}

@router.post("/auth/logout")
def auth_logout(response: Response, request: Request, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    if principal.authenticated:
        client_ip = request.client.host if request.client else "127.0.0.1"
        record_audit_event(
            db=db,
            user_id=principal.user_id,
            action="AUTH_LOGOUT",
            resource_type="auth",
            resource_id=principal.user_id,
            details={"email": principal.email or principal.external_subject},
            tenant_id=principal.tenant_id,
            ip_address=client_ip
        )
        db.commit()
    response.delete_cookie(settings.session_cookie_name, path="/")
    return {"logged_out": True}

@router.get("/audit-logs")
def list_audit_logs(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    limit: int = 50,
    action: str | None = None
):
    if not principal.authenticated and settings.auth_required:
        raise HTTPException(401, "Authentication required to access audit logs")
    query = db.query(AuditLog)
    # Tenant isolation: unless admin, only view own tenant's logs
    if principal.role != "admin" or not principal.authenticated:
        query = query.filter(AuditLog.tenant_id == principal.tenant_id)
    if action:
        query = query.filter(AuditLog.action == action)
    logs = query.order_by(AuditLog.timestamp.desc()).limit(min(limit, 200)).all()
    return [
        {
            "id": log.id,
            "tenant_id": log.tenant_id,
            "user_id": log.user_id,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": json.loads(log.details_json) if log.details_json else {},
            "ip_address": log.ip_address,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None
        }
        for log in logs
    ]

@router.get("/tenants")
def list_tenants(db: Session = Depends(get_db)):
    tenants = db.query(Tenant).all()
    if not tenants:
        return [
            {"id": "tenant_default", "name": "CYBERNEXUS Enterprise Tenant"},
            {"id": "tenant_soc", "name": "Security Operations Center (SOC)"},
            {"id": "tenant_redteam", "name": "Adversary Simulation / Red Team"}
        ]
    return [{"id": t.id, "name": t.name} for t in tenants]

@router.get("/auth/permissions")
def auth_permissions(principal: Principal = Depends(get_current_principal)):
    return {"authenticated": principal.authenticated, "user_id": principal.user_id, "role": principal.role, "tenant_id": principal.tenant_id, "capabilities": {"passive_scans": True, "active_scans": principal.authenticated, "admin_operations": principal.role == "admin", "private_evidence": principal.authenticated}}

@router.post("/privacy/redact")
def privacy_redact(payload: dict, principal: Principal = Depends(get_current_principal)):
    if not principal.authenticated and settings.auth_required:
        raise HTTPException(401, "Authentication required for privacy processing")
    return privacy_summary(payload)

@router.post("/security-assessments")
def create_security_assessment(payload: dict, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    """Create a normalized assessment from an existing scan or a pending target.

    Raw client findings are intentionally not accepted; findings are derived from
    the persisted scanner result so the assessment remains evidence-backed.
    """
    target_url = str(payload.get("target_url") or payload.get("url") or "").strip()
    scan_id = payload.get("scan_id")
    mode = str(payload.get("assessment_mode") or "PASSIVE").upper()
    authorization_id = payload.get("authorization_id")
    if mode == "ACTIVE":
        try: authorization_id = int(authorization_id)
        except (TypeError, ValueError): raise HTTPException(403, "Approved authorization_id is required for active assessments")
        authorization = db.get(SecurityAuthorization, authorization_id)
        if not authorization: raise HTTPException(403, "Authorization record not found")
        expire_security_authorization(db, authorization)
        requested_categories = payload.get("allowed_categories") or ["TLS", "REDIRECTS", "SECURITY_HEADERS"]
        if authorization.requester_user_id != principal.user_id and principal.role != "admin": raise HTTPException(403, "Authorization belongs to another requester")
        if not authorization_scope_allows(authorization, target_url, None) or any(not authorization_scope_allows(authorization, target_url, category) for category in requested_categories):
            raise HTTPException(403, "Target or requested assessment category is outside the approved authorization")
        if authorization.approval_status != "APPROVED": raise HTTPException(403, "Authorization is not approved")
    elif mode != "PASSIVE":
        raise HTTPException(400, "assessment_mode must be PASSIVE or ACTIVE")
    try:
        scan_id = int(scan_id) if scan_id is not None else None
        row = create_assessment(db, user_id=principal.user_id, target_url=target_url, scan_id=scan_id, assessment_mode=mode, authorization_id=authorization_id)
    except (ValueError, LookupError) as exc:
        db.rollback(); raise HTTPException(400 if isinstance(exc, ValueError) else 404, str(exc)) from exc
    return serialize_assessment(db, row)

@router.post("/security-authorizations")
def request_security_authorization(payload: dict, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: return serialize_security_authorization(db, create_security_authorization(db, principal.user_id, payload))
    except ValueError as exc: db.rollback(); raise HTTPException(400, str(exc)) from exc

@router.get("/security-authorizations")
def list_security_authorizations(principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    query = db.query(SecurityAuthorization)
    if principal.role != "admin": query = query.filter(SecurityAuthorization.requester_user_id == principal.user_id)
    return {"items": [serialize_security_authorization(db, row) for row in query.order_by(SecurityAuthorization.created_at.desc()).all()]}

@router.get("/security-authorizations/{authorization_id}")
def get_security_authorization(authorization_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(SecurityAuthorization, authorization_id)
    if not row: raise HTTPException(404, "Authorization record not found")
    if principal.role != "admin" and row.requester_user_id != principal.user_id: raise HTTPException(403, "Authorization access denied")
    return serialize_security_authorization(db, row)

@router.post("/security-authorizations/{authorization_id}/approve")
def approve_security_authorization(authorization_id: int, note: str = "", principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row = db.get(SecurityAuthorization, authorization_id)
    if not row: raise HTTPException(404, "Authorization record not found")
    if row.approval_status not in {"PENDING", "REJECTED"}: raise HTTPException(409, "Authorization cannot be approved from its current state")
    return serialize_security_authorization(db, transition_security_authorization(db, row, principal.external_subject or principal.user_id, "APPROVED", "APPROVED", note))

@router.post("/security-authorizations/{authorization_id}/reject")
def reject_security_authorization(authorization_id: int, note: str = "", principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row = db.get(SecurityAuthorization, authorization_id)
    if not row: raise HTTPException(404, "Authorization record not found")
    if row.approval_status not in {"PENDING", "APPROVED"}: raise HTTPException(409, "Authorization cannot be rejected from its current state")
    return serialize_security_authorization(db, transition_security_authorization(db, row, principal.external_subject or principal.user_id, "REJECTED", "REJECTED", note))

@router.post("/security-authorizations/{authorization_id}/revoke")
def revoke_security_authorization(authorization_id: int, note: str = "", principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row = db.get(SecurityAuthorization, authorization_id)
    if not row: raise HTTPException(404, "Authorization record not found")
    if row.approval_status != "APPROVED": raise HTTPException(409, "Only approved authorizations can be revoked")
    return serialize_security_authorization(db, transition_security_authorization(db, row, principal.external_subject or principal.user_id, "REVOKED", "REVOKED", note))

@router.get("/security-assessments/history")
def security_assessment_history(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
                                principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    query = db.query(SecurityAssessment)
    if principal.role != "admin": query = query.filter(SecurityAssessment.user_id == principal.user_id)
    rows = query.order_by(SecurityAssessment.created_at.desc()).offset(offset).limit(limit).all()
    return {"items": [serialize_assessment(db, row, include_findings=False) for row in rows], "offset": offset, "limit": limit}

@router.post("/security-assessments/{assessment_id}/execute")
def execute_security_assessment(assessment_id: int, payload: dict | None = None, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(SecurityAssessment, assessment_id)
    if not row: raise HTTPException(404, "Security assessment not found")
    if not can_access(db, row, principal, principal.role == "admin"): raise HTTPException(403, "Assessment access denied")
    if row.assessment_mode != "ACTIVE" or not row.authorization_id: raise HTTPException(403, "Only explicitly authorized ACTIVE assessments can execute")
    authorization = db.get(SecurityAuthorization, row.authorization_id)
    if not authorization: raise HTTPException(403, "Authorization record not found")
    expire_security_authorization(db, authorization)
    categories = (payload or {}).get("allowed_categories") or json.loads(authorization.allowed_categories_json or "[]")
    approved_categories = {str(x).upper() for x in json.loads(authorization.allowed_categories_json or "[]")}
    if not authorization_scope_allows(authorization, row.target_url, None) or ("FULL_SCAN" not in approved_categories and "*" not in approved_categories and any(not authorization_scope_allows(authorization, row.target_url, category) for category in categories)):
        row.status = "STOPPED"; row.stopped_reason = "Authorization expired, revoked, or outside approved scope"; db.commit(); raise HTTPException(403, row.stopped_reason)
    try:
        result = create_scan(ScanRequest(url=row.target_url, authorization_id=authorization.id, allowed_categories=categories), principal, db)
        scan_row = db.get(Scan, result["id"])
        attach_scan_to_assessment(db, row, scan_row)
        db.add(AssessmentEvent(assessment_id=row.id, actor=principal.external_subject or principal.user_id, event_type="ACTIVE_EXECUTION", details_json=json.dumps({"authorization_id": authorization.id, "categories": categories})))
        db.commit(); db.refresh(row)
    except AuthorizationStopped as exc:
        db.rollback(); row = db.get(SecurityAssessment, assessment_id); row.status = "STOPPED"; row.stopped_reason = "Authorization revoked or expired during execution"; db.commit()
        raise HTTPException(403, "Active assessment stopped because its authorization is no longer valid") from exc
    except HTTPException: raise
    except Exception as exc:
        db.rollback(); row = db.get(SecurityAssessment, assessment_id); row.status = "STOPPED"; row.stopped_reason = type(exc).__name__; db.commit(); raise HTTPException(502, "Authorized assessment execution failed") from exc
    return serialize_assessment(db, row)

@router.get("/security-assessments/{assessment_id}")
def get_security_assessment(assessment_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(SecurityAssessment, assessment_id)
    if not row: raise HTTPException(404, "Security assessment not found")
    if not can_access(db, row, principal, principal.role == "admin"): raise HTTPException(403, "Assessment access denied")
    return serialize_assessment(db, row)

@router.get("/security-assessments/{assessment_id}/reports")
def list_security_assessment_reports(assessment_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    assessment = db.get(SecurityAssessment, assessment_id)
    if not assessment: raise HTTPException(404, "Security assessment not found")
    if not can_access(db, assessment, principal, principal.role == "admin"): raise HTTPException(403, "Assessment access denied")
    return {"items": security_report_history(db, assessment_id)}

@router.get("/security-assessments/{assessment_id}/report")
def export_security_assessment_report(assessment_id: int, format: str = Query("json"), principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    selected = format.lower().strip()
    if selected not in SECURITY_REPORT_FORMATS: raise HTTPException(400, "format must be json, csv, or pdf")
    assessment = db.get(SecurityAssessment, assessment_id)
    if not assessment: raise HTTPException(404, "Security assessment not found")
    if not can_access(db, assessment, principal, principal.role == "admin"): raise HTTPException(403, "Assessment export denied")
    actor = principal.external_subject or principal.user_id
    try:
        report = build_security_assessment_report(db, assessment)
        if selected == "json":
            content, media_type = security_report_json_bytes(report), "application/json"
        elif selected == "csv":
            content, media_type = security_report_csv_bytes(report), "text/csv"
        else:
            content, media_type = security_report_pdf_bytes(report), "application/pdf"
        record_security_report_generation(db, assessment, actor, selected, len(report["findings"]))
    except Exception as exc:
        db.rollback()
        try: record_security_report_generation(db, assessment, actor, selected, 0, status="FAILED", error=type(exc).__name__)
        except Exception: db.rollback()
        raise HTTPException(500, "Security assessment report generation failed") from exc
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="security-assessment-{assessment_id}.{selected}"'})

@router.get("/security-assessments/{assessment_id}/findings")
def list_security_findings(assessment_id: int, category: str | None = Query(None), severity: str | None = Query(None),
                           principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    assessment = db.get(SecurityAssessment, assessment_id)
    if not assessment: raise HTTPException(404, "Security assessment not found")
    if not can_access(db, assessment, principal, principal.role == "admin"): raise HTTPException(403, "Assessment access denied")
    query = db.query(SecurityFinding).filter(SecurityFinding.assessment_id == assessment_id)
    if category: query = query.filter(SecurityFinding.category == category.upper())
    if severity: query = query.filter(SecurityFinding.severity == severity.upper())
    return {"assessment_id": assessment_id, "items": [serialize_finding(row) for row in query.order_by(SecurityFinding.id).all()]}

@router.get("/security-findings")
def search_security_findings(
    severity: str | None = Query(None), category: str | None = Query(None),
    status: str | None = Query(None), remediation_status: str | None = Query(None),
    confidence: str | None = Query(None), date_from: str | None = Query(None),
    date_to: str | None = Query(None), assessment_id: int | None = Query(None),
    hostname: str | None = Query(None), search: str | None = Query(None),
    sort: str = Query("newest"), page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db),
):
    query = accessible_query(db, principal, principal.role == "admin")
    if severity: query = query.filter(SecurityFinding.severity == severity.upper())
    if category: query = query.filter(SecurityFinding.category == category.upper())
    if status: query = query.filter(SecurityFinding.status == status.upper())
    if remediation_status: query = query.filter(remediation_status_expression() == remediation_status.upper())
    if confidence: query = query.filter(SecurityFinding.confidence == confidence.upper())
    if assessment_id is not None: query = query.filter(SecurityFinding.assessment_id == assessment_id)
    if hostname: query = query.filter(SecurityFinding.hostname.ilike(f"%{hostname.strip()}%"))
    try:
        if date_from: query = query.filter(SecurityFinding.first_detected >= datetime.fromisoformat(date_from.replace("Z", "+00:00")))
        if date_to: query = query.filter(SecurityFinding.first_detected <= datetime.fromisoformat(date_to.replace("Z", "+00:00")))
    except ValueError as exc:
        raise HTTPException(400, "date_from and date_to must be ISO timestamps") from exc
    if search:
        term = f"%{search.strip()}%"
        clauses = [SecurityFinding.title.ilike(term), SecurityFinding.hostname.ilike(term), SecurityFinding.category.ilike(term)]
        if search.strip().isdigit(): clauses.append(SecurityFinding.id == int(search.strip()))
        query = query.filter(or_(*clauses))
    total = query.count()
    groups = query.with_entities(SecurityFinding.severity, func.count(SecurityFinding.id)).group_by(SecurityFinding.severity).all()
    status_groups = query.with_entities(SecurityFinding.status, func.count(SecurityFinding.id)).group_by(SecurityFinding.status).all()
    remediation_groups = query.with_entities(remediation_status_expression(), func.count(SecurityFinding.id)).group_by(remediation_status_expression()).all()
    severity_order = case(
        (SecurityFinding.severity == "CRITICAL", 5), (SecurityFinding.severity == "HIGH", 4),
        (SecurityFinding.severity == "MEDIUM", 3), (SecurityFinding.severity == "LOW", 2),
        else_=1,
    )
    sort_map = {
        "severity": (severity_order, desc), "oldest": (SecurityFinding.first_detected, asc),
        "newest": (SecurityFinding.first_detected, desc), "confidence": (SecurityFinding.confidence, desc),
        "remediation": (remediation_status_expression(), asc), "alphabetical": (SecurityFinding.title, asc),
    }
    sort_column, direction = sort_map.get(sort, sort_map["newest"])
    rows = query.order_by(direction(sort_column), SecurityFinding.id.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [managed_finding(db, row, include_history=False) for row in rows],
        "page": page, "page_size": page_size, "total": total,
        "pages": (total + page_size - 1) // page_size,
        "counts": {
            "severity": {str(key or "UNKNOWN"): value for key, value in groups},
            "status": {str(key or "UNKNOWN"): value for key, value in status_groups},
            "remediation": {str(key or "OPEN"): value for key, value in remediation_groups},
        },
    }

@router.get("/security-findings/{finding_id}")
def get_security_finding(finding_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(SecurityFinding, finding_id)
    if not row: raise HTTPException(404, "Security finding not found")
    assessment = db.get(SecurityAssessment, row.assessment_id)
    if not assessment or not can_access(db, assessment, principal, principal.role == "admin"):
        raise HTTPException(403, "Finding access denied")
    return managed_finding(db, row)

@router.patch("/security-findings/{finding_id}/remediation")
def change_finding_remediation(finding_id: int, payload: dict,
                               principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    finding = db.get(SecurityFinding, finding_id)
    if not finding: raise HTTPException(404, "Security finding not found")
    assessment = db.get(SecurityAssessment, finding.assessment_id)
    if not assessment or not can_access(db, assessment, principal, principal.role == "admin"):
        raise HTTPException(403, "Finding modification denied")
    try:
        record = update_remediation(db, finding, principal.external_subject or principal.user_id, payload)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return managed_finding(db, finding)

@router.post("/security-findings/{finding_id}/verify")
def verify_finding_remediation(finding_id: int, payload: dict,
                               principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    finding = db.get(SecurityFinding, finding_id)
    if not finding: raise HTTPException(404, "Security finding not found")
    assessment = db.get(SecurityAssessment, finding.assessment_id)
    if not assessment or not can_access(db, assessment, principal, principal.role == "admin"):
        raise HTTPException(403, "Finding verification denied")
    if "verified" not in payload or not isinstance(payload.get("verified"), bool):
        raise HTTPException(400, "verified must be a boolean")
    record = update_remediation(db, finding, principal.external_subject or principal.user_id, payload, verify=True)
    return managed_finding(db, finding)

@router.post("/admin/identity-links")
def link_legacy_identity(payload: dict, principal: Principal = Depends(get_current_principal), x_admin_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    if principal.role != "admin" and not _admin(x_admin_token): raise HTTPException(403, "Administrator role required")
    legacy = str(payload.get("legacy_user_id") or "").strip(); subject = str(payload.get("external_subject") or "").strip()
    if not legacy or not subject: raise HTTPException(400, "legacy_user_id and external_subject are required")
    if db.query(LegacyIdentityLink).filter(LegacyIdentityLink.legacy_user_id == legacy).first(): raise HTTPException(409, "Legacy identity is already linked")
    if not db.query(AppUser).filter(AppUser.external_subject == subject).first(): raise HTTPException(404, "External user must authenticate before linking")
    db.add(LegacyIdentityLink(legacy_user_id=legacy, external_subject=subject, linked_by=principal.external_subject or "admin-token")); db.add(MessageAnalysisEvent(user_id=principal.user_id, event_type="identity_linked", details_json=json.dumps({"legacy_user_id": legacy, "external_subject": subject}))); db.commit(); return {"linked": True, "legacy_user_id": legacy, "external_subject": subject}

@router.get("/intelligence/providers/health")
def intelligence_provider_health():
    return {"phone_reputation": phone_provider_status(), "cache": cache_health(), "database": {"status": "CONNECTED" if health()["database"] == "ok" else "UNAVAILABLE"}, "workers": {"status": "CONFIGURED" if settings.celery_broker_url else "NOT_CONFIGURED"}}

@router.post("/intelligence/phone/analyze")
def intelligence_phone(payload: dict, db: Session = Depends(get_db)):
    value = payload.get("phone")
    if not isinstance(value, str) or not value.strip(): raise HTTPException(400, "phone is required")
    result = phone_analysis(value.strip())
    db.add(IntelligenceVerification(indicator_type="phone", indicator=value.strip(), provider=result.get("reputation", {}).get("provider", "libphonenumber"), status=result.get("status", "UNKNOWN"), result_json=json.dumps(result), checked_at=datetime.now(timezone.utc)))
    db.commit()
    return result

@router.post("/intelligence/email/authentication")
def intelligence_email_authentication(payload: dict, db: Session = Depends(get_db)):
    email = payload.get("email")
    domain = payload.get("domain")
    if isinstance(email, str) and "@" in email: domain = email.rsplit("@", 1)[1]
    if not isinstance(domain, str): raise HTTPException(400, "email or domain is required")
    raw = payload.get("raw_message")
    raw_bytes = raw.encode() if isinstance(raw, str) and raw else None
    try:
        result = email_security_investigation.investigate(domain, payload.get("selector"), raw_bytes)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    # Keep the legacy response shape for existing callers while exposing the
    # complete investigation under the new fields.
    result["legacy_authentication"] = verify_email_authentication(result["target"]["domain"], payload.get("selector"), raw_bytes)
    db.add(IntelligenceVerification(indicator_type="email", indicator=result["target"]["domain"], provider="DNS/email-authentication", status="COMPLETED", result_json=json.dumps(result), checked_at=datetime.now(timezone.utc)))
    db.commit()
    return result


@router.post("/intelligence/email/investigate")
def investigate_email_security(request: Request, payload: dict, db: Session = Depends(get_db)):
    """Investigate an email identity or domain without probing mailboxes."""
    client_key = request.client.host if request.client else "unknown"
    if not email_security_investigation.allow_request(client_key):
        raise HTTPException(429, "Email investigation rate limit reached; retry shortly")
    target = payload.get("target") or payload.get("email") or payload.get("domain")
    selector = payload.get("selector") or payload.get("dkim_selector")
    raw = payload.get("raw_message")
    if raw is not None and not isinstance(raw, str):
        raise HTTPException(400, "raw_message must be text containing the original RFC5322 message")
    raw_bytes = raw.encode("utf-8", errors="surrogatepass") if raw else None
    if raw_bytes and len(raw_bytes) > email_security_investigation.MAX_INVESTIGATION_BYTES:
        raise HTTPException(413, "raw_message exceeds the 10 MB limit")
    providers = [{"domain": item.domain, "provider_name": item.provider_name, "category": item.category, "disposable": item.disposable, "source": item.source} for item in db.query(EmailProviderRegistry).all()]
    try:
        result = email_security_investigation.investigate(target, selector, raw_bytes, providers)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.add(IntelligenceVerification(indicator_type="email", indicator=result["target"]["domain"], provider="email-security-investigation", status="COMPLETED", result_json=json.dumps(result), checked_at=datetime.now(timezone.utc)))
    db.commit()
    return result


@router.post("/intelligence/email/remediation/verify")
def verify_email_remediation(payload: dict):
    """Re-read proposed TXT records; this endpoint never changes DNS."""
    target = payload.get("domain") or payload.get("target")
    try:
        normalized = email_security_investigation.normalize_input(target)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    domain = normalized["domain"]
    requested = payload.get("records") or []
    if not isinstance(requested, list) or len(requested) > 20:
        raise HTTPException(400, "records must be a list containing at most 20 TXT records")
    checks = []
    for item in requested:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str):
            raise HTTPException(400, "each record must contain a DNS name and value")
        record_type = str(item.get("type", "TXT")).upper()
        if record_type != "TXT":
            raise HTTPException(400, "remediation verification currently supports TXT records only")
        name = item["name"].strip().rstrip(".")
        if not (name == domain or name.endswith("." + domain)):
            raise HTTPException(400, "verification is limited to the requested domain and its subdomains")
        observed = email_security_investigation._dns_query(name, record_type)
        checks.append({"name": name, "type": record_type, "expected": item["value"], "observed": observed.get("records", []), "status": "MATCH" if item["value"] in observed.get("records", []) else "NOT_MATCHED", "dns_status": observed.get("status")})
    return {"domain": domain, "status": "VERIFIED" if checks and all(item["status"] == "MATCH" for item in checks) else "NOT_VERIFIED", "checks": checks, "message": "DNS was read for verification only. No record was created, changed, or overwritten."}

@router.get("/intelligence/tasks/{task_id}")
def intelligence_task(task_id: str, db: Session = Depends(get_db)):
    row = db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id == task_id).first()
    if not row: raise HTTPException(404, "Task not found")
    return {"task_id": row.task_id, "task_name": row.task_name, "status": row.status, "result": json.loads(row.result_json) if row.result_json else None, "error": row.error, "started_at": row.started_at, "completed_at": row.completed_at}

@router.get("/brands")
def brands(db: Session = Depends(get_db)):
    return [{"id":b.id,"brand_name":b.brand_name,"official_domain":b.official_domain,"official_website":b.official_website,"logo_url":b.logo_url,"verification_status":b.verification_status,"source":b.source,"source_reliability":b.source_reliability,"verification_date":b.verification_date} for b in db.query(BrandRegistry).order_by(BrandRegistry.brand_name).all()]

@router.post("/admin/brands")
def add_brand(payload: dict, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    required=(payload.get("brand_name"),payload.get("official_domain"),payload.get("source"))
    if not all(isinstance(x,str) and x.strip() for x in required): raise HTTPException(400,"brand_name, official_domain and source are required")
    # A registry write never self-asserts ownership. Verification can only be
    # reached through challenge evidence or a separately reviewed record.
    row=BrandRegistry(brand_name=payload["brand_name"].strip(),official_domain=payload["official_domain"].strip().lower().rstrip("."),official_website=payload.get("official_website"),logo_url=payload.get("logo_url"),verification_status="unknown",source=payload["source"],source_reliability=payload.get("source_reliability","unknown"),verification_date=None)
    db.add(row); db.flush(); db.add(BrandVerificationAudit(brand_id=row.id,actor="admin",action="brand_created",details_json=json.dumps({"source":row.source}))); db.commit(); db.refresh(row); return {"id":row.id,"brand_name":row.brand_name,"official_domain":row.official_domain,"verification_status":row.verification_status,"source":row.source}

@router.post("/admin/brands/{brand_id}/evidence")
def add_brand_evidence(brand_id: int, payload: dict, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    if not db.get(BrandRegistry, brand_id): raise HTTPException(404,"Brand not found")
    if not payload.get("evidence_type") or not payload.get("evidence_value"): raise HTTPException(400,"evidence_type and evidence_value are required")
    item=BrandVerificationEvidence(brand_id=brand_id,evidence_type=payload["evidence_type"],evidence_value=payload["evidence_value"],source=payload.get("source"),status=payload.get("status","unverified")); db.add(item); db.add(BrandVerificationAudit(brand_id=brand_id,actor="admin",action="evidence_added",details_json=json.dumps({"evidence_type":payload["evidence_type"],"status":item.status}))); db.commit(); db.refresh(item); return {"id":item.id,"brand_id":brand_id,"status":item.status,"checked_at":item.checked_at}

@router.post("/admin/brands/{brand_id}/challenges")
def create_brand_challenge(brand_id: int, payload: dict, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    brand=db.get(BrandRegistry,brand_id)
    if not brand: raise HTTPException(404,"Brand not found")
    domain=str(payload.get("domain") or brand.official_domain).strip().lower().rstrip(".")
    try: row,token=create_challenge(db,BrandVerificationChallenge,brand_id,domain,str(payload.get("method","dns_txt")))
    except ValueError as exc: raise HTTPException(400,str(exc))
    return {"challenge_id":row.id,"domain":domain,"method":row.method,"token":token,"dns_txt_name":domain,"dns_txt_value":token,"http_path":row.challenge_path,"expires_at":row.expires_at}

@router.post("/admin/brand-challenges/{challenge_id}/verify")
def verify_brand_challenge_route(challenge_id: int, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    challenge=db.get(BrandVerificationChallenge,challenge_id)
    if not challenge: raise HTTPException(404,"Challenge not found")
    brand=db.get(BrandRegistry,challenge.brand_id)
    return verify_brand_challenge(db,challenge,brand,BrandVerificationEvidence,BrandVerificationAudit)

@router.get("/admin/brands/{brand_id}/audit")
def brand_audit(brand_id: int, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    if not db.get(BrandRegistry,brand_id): raise HTTPException(404,"Brand not found")
    return [{"id":x.id,"actor":x.actor,"action":x.action,"details":json.loads(x.details_json or "{}"),"created_at":x.created_at} for x in db.query(BrandVerificationAudit).filter(BrandVerificationAudit.brand_id==brand_id).order_by(BrandVerificationAudit.created_at.desc()).all()]

@router.post("/admin/brands/import")
def import_brands(payload: dict, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    records=payload.get("records")
    if not isinstance(records,list): raise HTTPException(400,"records must be a list")
    created=[]
    for item in records:
        if not isinstance(item,dict) or not item.get("brand_name") or not item.get("official_domain") or not item.get("source"): continue
        row=BrandRegistry(brand_name=str(item["brand_name"]).strip(),official_domain=str(item["official_domain"]).lower().strip().rstrip("."),official_website=item.get("official_website"),logo_url=item.get("logo_url"),verification_status="unknown",source=item["source"],source_reliability=item.get("source_reliability","unknown")); db.add(row); db.flush(); db.add(BrandVerificationAudit(brand_id=row.id,actor="admin",action="brand_imported",details_json=json.dumps({"source":row.source}))); created.append(row.id)
    db.commit(); return {"created":created,"count":len(created),"note":"Imported records remain UNKNOWN until authoritative evidence is verified."}

@router.post("/admin/brands/{brand_id}/logos")
async def upload_brand_logo(brand_id: int, file: UploadFile = File(...), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    if not db.get(BrandRegistry,brand_id): raise HTTPException(404,"Brand not found")
    allowed={"image/png","image/jpeg","image/webp","image/svg+xml","application/svg+xml"}
    if file.content_type not in allowed: raise HTTPException(400,"Unsupported image content type")
    data=await file.read(MAX_IMAGE_BYTES+1)
    info=fingerprint(data)
    if len(data)>MAX_IMAGE_BYTES or info.get("status")!="available": raise HTTPException(400,info.get("reason","invalid_image"))
    row=BrandLogoAsset(brand_id=brand_id,original_source=file.filename,content_type=file.content_type,width=info["width"],height=info["height"],phash=info["phash"],image_bytes=data,approval_status="pending",source="admin upload")
    db.add(row); db.flush(); db.add(BrandVerificationAudit(brand_id=brand_id,actor="admin",action="logo_uploaded",details_json=json.dumps({"logo_id":row.id}))); db.commit(); db.refresh(row)
    return {"id":row.id,"brand_id":brand_id,"approval_status":row.approval_status,"width":row.width,"height":row.height,"phash":row.phash}

@router.post("/admin/logos/{logo_id}/approve")
def approve_brand_logo(logo_id: int, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row=db.get(BrandLogoAsset,logo_id)
    if not row: raise HTTPException(404,"Logo not found")
    row.approval_status="approved"; row.approved_at=datetime.now(timezone.utc); db.add(BrandVerificationAudit(brand_id=row.brand_id,actor="admin",action="logo_approved",details_json=json.dumps({"logo_id":row.id}))); db.commit(); return {"id":row.id,"approval_status":row.approval_status,"approved_at":row.approved_at}

@router.post("/admin/brands/{brand_id}/image-references")
async def upload_image_reference(brand_id: int, asset_type: str, file: UploadFile = File(...), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    if asset_type not in {"logo","favicon"}: raise HTTPException(400,"asset_type must be logo or favicon")
    if not db.get(BrandRegistry,brand_id): raise HTTPException(404,"Brand not found")
    if file.content_type not in {"image/png","image/jpeg","image/webp","image/svg+xml","application/svg+xml","image/x-icon"}: raise HTTPException(400,"Unsupported image content type")
    data=await file.read(MAX_IMAGE_BYTES+1); info=fingerprint(data)
    if len(data)>MAX_IMAGE_BYTES or info.get("status")!="available": raise HTTPException(400,info.get("reason","invalid_image"))
    row=BrandImageReference(brand_id=brand_id,asset_type=asset_type,original_source=file.filename,content_type=file.content_type,width=info.get("width"),height=info.get("height"),sha256=info["sha256"],phash=info["phash"],dhash=info.get("dhash"),ahash=info.get("ahash"),image_bytes=data,approval_status="pending",source="admin image reference upload")
    db.add(row); db.flush(); db.add(BrandVerificationAudit(brand_id=brand_id,actor="admin",action="image_reference_uploaded",details_json=json.dumps({"asset_id":row.id,"asset_type":asset_type}))); db.commit(); db.refresh(row)
    return {"id":row.id,"asset_type":asset_type,"approval_status":row.approval_status,"sha256":row.sha256,"width":row.width,"height":row.height}

@router.post("/admin/image-references/{asset_id}/approve")
def approve_image_reference(asset_id: int, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row=db.get(BrandImageReference,asset_id)
    if not row: raise HTTPException(404,"Image reference not found")
    row.approval_status="approved"; row.approved_at=datetime.now(timezone.utc); db.add(BrandVerificationAudit(brand_id=row.brand_id,actor="admin",action="image_reference_approved",details_json=json.dumps({"asset_id":row.id}))); db.commit(); return {"id":row.id,"asset_type":row.asset_type,"approval_status":row.approval_status}

@router.get("/providers/google-safe-browsing/status")
def google_safe_browsing_status():
    return google_safe_browsing_configuration()

@router.post("/providers/google-safe-browsing/verify")
def google_safe_browsing_verify(force: bool = False):
    return verify_google_safe_browsing(force=force)

@router.get("/providers/google-safe-browsing/latest")
def google_safe_browsing_latest(db: Session = Depends(get_db)):
    row = db.query(ProviderVerdict).filter(ProviderVerdict.provider == "Google Safe Browsing").order_by(ProviderVerdict.checked_at.desc()).first()
    if not row:
        return {"status": "no_scan", "verdict": "unknown", "message": "No Google Safe Browsing scan result is stored yet."}
    return {"provider": row.provider, "status": row.status, "verdict": row.verdict, "evidence": json.loads(row.evidence_json or "{}"), "checked_at": row.checked_at}

@router.get("/providers/virustotal/status")
def virustotal_status():
    return virustotal_configuration()

@router.get("/providers/virustotal/latest")
def virustotal_latest(db: Session = Depends(get_db)):
    row = db.query(ProviderVerdict).filter(ProviderVerdict.provider == "VirusTotal").order_by(ProviderVerdict.checked_at.desc()).first()
    if not row:
        return {"status": "no_scan", "verdict": "unknown", "message": "No VirusTotal scan result is stored yet."}
    return {"provider": row.provider, "status": row.status, "verdict": row.verdict, "evidence": json.loads(row.evidence_json or "{}"), "checked_at": row.checked_at}

@router.post("/providers/virustotal/submit")
def virustotal_submit(payload: dict):
    url = payload.get("url")
    confirmed = payload.get("confirm_public_submission") is True
    if not isinstance(url, str) or not url.strip(): raise HTTPException(400, "url is required")
    return submit_virustotal_url(url, confirmed)

@router.get("/providers/virustotal/analyses/{analysis_id}")
def virustotal_analysis(analysis_id: str):
    if not analysis_id.strip(): raise HTTPException(400, "analysis_id is required")
    return poll_virustotal_analysis(analysis_id)

@router.get("/providers/external/status")
def external_status():
    return external_intelligence_status()

@router.get("/providers/ca-reputation/status")
def ca_reputation_status():
    return ca_reputation_configuration()

@router.get("/providers/external/latest")
def external_latest(db: Session = Depends(get_db)):
    providers = []
    for name in ("AlienVault OTX", "OPSWAT MetaDefender Cloud"):
        row = db.query(ProviderVerdict).filter(ProviderVerdict.provider == name).order_by(ProviderVerdict.checked_at.desc()).first()
        providers.append({"provider": name, "status": row.status if row else "no_scan", "verdict": row.verdict if row else "unknown", "evidence": json.loads(row.evidence_json or "{}") if row else {}, "checked_at": row.checked_at if row else None})
    return {"providers": providers}

@router.get("/providers/urlhaus/status")
def urlhaus_status():
    return urlhaus_connectivity_status()

@router.get("/providers/urlhaus/latest")
def urlhaus_latest(db: Session = Depends(get_db)):
    row = db.query(ProviderVerdict).filter(ProviderVerdict.provider == "URLhaus").order_by(ProviderVerdict.checked_at.desc()).first()
    if not row:
        return {"status": "no_scan", "verdict": "unknown", "message": "No URLhaus scan result is stored yet."}
    return {"provider": row.provider, "status": row.status, "verdict": row.verdict, "evidence": json.loads(row.evidence_json or "{}"), "checked_at": row.checked_at}

@router.post("/scans")
def create_scan(request: Request, payload: ScanRequest, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    mode = (getattr(payload, "scan_mode", "PUBLIC_PASSIVE") or "PUBLIC_PASSIVE").upper()
    client_ip = request.client.host if request.client else "127.0.0.1"
    _enforce_rate_limits(db, client_ip, principal, mode)
    authorization, guard = _scan_authorization(db, payload, principal)
    try: result = scan(payload.url, db, authorization_guard=guard)
    except AuthorizationStopped as exc:
        raise HTTPException(403, "Active scan stopped because its authorization is no longer valid") from exc
    except ValueError as exc: raise HTTPException(400, str(exc))
    registered = db.query(BrandRegistry).filter(BrandRegistry.official_domain == result["domain"].lower().rstrip("."), BrandRegistry.verification_status == "verified").first()
    if registered:
        result.setdefault("domain_intelligence", {}).setdefault("domain", {})["ownership"] = {"status":"verified", "confidence":"high", "brand":registered.brand_name, "official_domain":registered.official_domain, "source":registered.source, "verification_date":registered.verification_date, "message":"Exact domain match to an administrator-verified brand registry record."}
    identity=result.setdefault("domain_intelligence",{}).setdefault("identity",{})
    comparisons=[]; favicon_comparisons=[]
    for candidate in identity.get("logo_assets",[]):
        if candidate.get("status")!="available" or not candidate.get("phash"): continue
        for ref in db.query(BrandLogoAsset).filter(BrandLogoAsset.approval_status=="approved").all():
            brand=db.get(BrandRegistry,ref.brand_id); match=compare(candidate["phash"],ref.phash)
            if match.get("status")=="compared" and (match.get("exact_match") or match.get("similarity_percent",0) >= 78): comparisons.append({**match,"brand":brand.brand_name if brand else "Unknown","brand_id":brand.id if brand else None,"official_domain":brand.official_domain if brand else None,"reference_logo_id":ref.id,"candidate_url":candidate.get("url")})
    for candidate in identity.get("favicon_candidates",[]):
        if candidate.get("status")!="available": continue
        for ref in db.query(BrandImageReference).filter(BrandImageReference.asset_type=="favicon",BrandImageReference.approval_status=="approved").all():
            brand=db.get(BrandRegistry,ref.brand_id); match=compare_fingerprints(candidate,{"status":"available","sha256":ref.sha256,"phash":ref.phash,"dhash":ref.dhash,"ahash":ref.ahash})
            if match.get("status")=="compared" and (match.get("exact_match") or match.get("similarity_percent",0) >= 78): favicon_comparisons.append({**match,"brand":brand.brand_name if brand else "Unknown","brand_id":brand.id if brand else None,"official_domain":brand.official_domain if brand else None,"reference_asset_id":ref.id,"candidate_url":candidate.get("url")})
    identity["logo_comparisons"]=comparisons or {"status":"COMPARISON_UNAVAILABLE_NO_VERIFIED_REFERENCE","reason":"No approved reference logo matched or no approved reference exists"}
    identity["favicon_comparisons"]=favicon_comparisons or {"status":"COMPARISON_UNAVAILABLE_NO_VERIFIED_REFERENCE","reason":"No approved reference favicon matched or no approved reference exists"}
    identity["findings"]=[]
    for finding_type, matches in (("logo",comparisons),("favicon",favicon_comparisons if isinstance(favicon_comparisons,list) else [])):
        for match in matches:
            finding={"finding_type":f"{finding_type}_reference_match","brand":match.get("brand"),"brand_id":match.get("brand_id"),"reference_asset_id":match.get("reference_asset_id") or match.get("reference_logo_id"),"candidate_url":match.get("candidate_url"),"similarity":match.get("similarity_percent"),"exact_match":match.get("exact_match",False),"confidence":match.get("confidence"),"source":"approved_brand_reference","checked_at":datetime.now(timezone.utc).isoformat(),"risk_contribution":0,"explanation":"Image similarity is supporting identity evidence and is not proof of ownership or fraud."}
            identity["findings"].append(finding)
    result["risk"] = calculate(result.get("phishing",{}), result.get("network",{}), result.get("threat_intelligence",{}), result.get("domain_intelligence",{}), result.get("certificate",{}))
    row = Scan(
        url=payload.url,
        normalized_url=result["normalized_url"],
        domain=result["domain"],
        risk_score=result["risk"]["score"],
        risk_level=result["risk"]["level"],
        result_json=json.dumps(result),
        scan_mode=mode,
        tenant_id=getattr(payload, "tenant_id", "default") or "default",
        created_by=principal.user_id,
        authorization_state="APPROVED" if authorization else "NOT_REQUIRED"
    )
    db.add(row); db.commit(); db.refresh(row)
    intel=result.get("domain_intelligence",{}); db.add(DomainIntelligence(scan_id=row.id,domain=row.domain,rdap_json=json.dumps(intel.get("rdap",{})),infrastructure_json=json.dumps(intel.get("infrastructure",{})),identity_json=json.dumps(intel.get("identity",{}))))
    certificate=result.get("certificate",{}); cert_items=certificate.get("certificates",[])
    for item in cert_items:
        def parse_date(value):
            try: return datetime.fromisoformat(value.replace("Z","+00:00")) if value else None
            except (ValueError,AttributeError): return None
        der=bytes.fromhex(item["der"]) if item.get("der") else None
        db.add(CertificateRecord(scan_id=row.id,fingerprint_sha256=item.get("fingerprint_sha256",""),role=item.get("role","unknown"),subject=item.get("subject"),issuer=item.get("issuer"),serial_number=item.get("serial_number"),not_before=parse_date(item.get("not_before")),not_after=parse_date(item.get("not_after")),der=der,parsed_json=json.dumps({k:v for k,v in item.items() if k != "der"})))
    db.flush()
    for index,item in enumerate(cert_items[:-1]):
        issuer=cert_items[index+1]
        db.add(CertificateChainLink(scan_id=row.id,child_fingerprint=item.get("fingerprint_sha256",""),issuer_fingerprint=issuer.get("fingerprint_sha256"),relation="presented_issuer",position=index,evidence_json=json.dumps({"child_subject":item.get("subject"),"issuer_subject":issuer.get("subject")})))
    validation=certificate.get("validation",{})
    db.add(CertificateValidationResult(scan_id=row.id,status=validation.get("status",certificate.get("status","UNKNOWN")),trust_anchor=(validation.get("trust_anchor") or {}).get("fingerprint_sha256"),errors_json=json.dumps(validation.get("errors",[])),evidence_json=json.dumps(validation),checked_at=datetime.now(timezone.utc)))
    cert_risk=certificate.get("risk",{})
    db.add(CertificateRiskAssessment(scan_id=row.id,score=int(cert_risk.get("score",0) or 0),level=cert_risk.get("level","Informational"),confidence=cert_risk.get("confidence"),validation_status=cert_risk.get("validation_status"),tls_grade=cert_risk.get("tls_grade"),revocation_status=cert_risk.get("revocation_status"),ca_trust_status=cert_risk.get("ca_trust_status"),ct_anomaly_score=int(cert_risk.get("ct_anomaly_score",0) or 0),findings_json=json.dumps(cert_risk.get("findings",[])),evidence_json=json.dumps(cert_risk),checked_at=datetime.now(timezone.utc)))
    ct=certificate.get("ct_intelligence",{})
    for item in ct.get("records",[]):
        db.add(CertificateTransparencyEntry(scan_id=row.id,certificate_id=str(item.get("certificate_id")) if item.get("certificate_id") is not None else None,fingerprint_sha256=item.get("fingerprint_sha256"),issuer=item.get("issuer"),subject=item.get("subject"),san_json=json.dumps(item.get("san_domains",[])),serial_number=item.get("serial_number"),not_before=parse_date(item.get("not_before")),not_after=parse_date(item.get("not_after")),observation_timestamp=parse_date(item.get("observation_timestamp")),ct_log=item.get("ct_log"),source=item.get("source","crt.sh"),status=item.get("status","OBSERVED")))
    for item in ct.get("anomalies",[]):
        db.add(CertificateTransparencyAnomaly(scan_id=row.id,finding_type=item.get("finding_type","unknown"),fingerprint=item.get("fingerprint"),domain=item.get("domain"),issuer=item.get("issuer"),source=item.get("source"),observation_timestamp=parse_date(item.get("observation_timestamp")),confidence=item.get("confidence"),evidence_json=json.dumps(item.get("evidence",{})),explanation=item.get("explanation")))
    for item in certificate.get("revocation",{}).get("certificates",[]):
        aggregate=item.get("aggregate",{}); sources=aggregate.get("sources",{}); ca_trust=item.get("ca_trust",{})
        db.add(CertificateRevocationResult(scan_id=row.id,certificate_fingerprint=item.get("fingerprint_sha256",""),role=item.get("role","unknown"),status=aggregate.get("status","UNKNOWN"),ocsp_status=(sources.get("ocsp") or {}).get("status"),crl_status=(sources.get("crl") or {}).get("status"),distrust_status=ca_trust.get("status"),ca_reputation=ca_trust.get("ca_reputation"),evidence_json=json.dumps(item),checked_at=datetime.now(timezone.utc)))
    candidate_rows=[]
    for asset_type, values in (("logo",identity.get("logo_assets",[])),("favicon",identity.get("favicon_candidates",[]))):
        for item in values:
            candidate_row=WebsiteImageCandidate(scan_id=row.id,asset_type=asset_type,source_url=item.get("url","")[:2048],extraction_method=item.get("source"),status=item.get("status"),format=item.get("detected_format") or item.get("format"),width=item.get("width"),height=item.get("height"),sha256=item.get("sha256"),phash=item.get("phash"),dhash=item.get("dhash"))
            db.add(candidate_row); candidate_rows.append(candidate_row)
    db.flush()
    for finding in identity.get("findings",[]):
        candidate=next((x for x in candidate_rows if x.source_url==finding.get("candidate_url") and x.asset_type==finding.get("finding_type","").split("_",1)[0]),None)
        db.add(ImageComparison(scan_id=row.id,candidate_id=candidate.id if candidate else None,reference_id=finding.get("reference_asset_id"),brand_id=finding.get("brand_id"),asset_type="favicon" if "favicon" in finding.get("finding_type","") else "logo",similarity=finding.get("similarity"),exact_match=str(finding.get("exact_match",False)),confidence=finding.get("confidence"),method="approved reference image comparison",evidence_json=json.dumps(finding),checked_at=datetime.now(timezone.utc)))
    for provider in result.get("threat_intelligence",{}).get("providers",[]): db.add(ProviderVerdict(scan_id=row.id,provider=provider.get("provider","unknown"),status=provider.get("status","unknown"),verdict=provider.get("verdict"),evidence_json=json.dumps(provider)))
    for finding in result.get("threat_intelligence",{}).get("findings",[]):
        source=finding.get("provider") or "unknown"
        existing=db.query(ThreatIndicator).filter(ThreatIndicator.indicator==row.domain, ThreatIndicator.indicator_type=="domain", ThreatIndicator.source==source).first()
        if existing:
            existing.last_seen=row.created_at; existing.category=finding.get("provider"); existing.verification_status=finding.get("state","unverified"); existing.confidence=max(existing.confidence or 0, 1 if finding.get("state")=="confirmed" else .5); existing.source_reference=finding.get("reference")
        else:
            db.add(ThreatIndicator(indicator=row.domain,indicator_type="domain",category=finding.get("provider"),confidence=1 if finding.get("state")=="confirmed" else .5,verification_status=finding.get("state","unverified"),source=source,source_reference=finding.get("reference")))
    for hop in result.get("network",{}).get("http",{}).get("redirects",[]):
        db.add(RedirectHop(scan_id=row.id, sequence=hop.get("sequence", 0), source_url=hop.get("source_url", ""), destination_url=hop.get("destination_url", ""), source_domain=hop.get("source_domain"), destination_domain=hop.get("destination_domain"), status_code=hop.get("status_code"), redirect_type=hop.get("redirect_type"), https=str(hop.get("https")), https_downgrade=str(hop.get("https_downgrade")), destination_ips_json=json.dumps(hop.get("destination_ips", [])), reputation_json=json.dumps(result.get("network",{}).get("redirect_analysis",{}).get("destinations",{}).get(hop.get("destination_domain"), {})), analysis_status=hop.get("analysis_status", "complete")))
    extract_and_persist_provenance(db, row.id, result, scan_job_id=None)
    db.commit()
    return {"id": row.id, **result, "scan_mode": row.scan_mode, "created_at": row.created_at}

@router.post("/scan-jobs", status_code=202)
def create_realtime_scan_job(request: Request, payload: ScanRequest, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    """Queue a non-blocking threat scan and return a pollable job id."""
    mode = (getattr(payload, "scan_mode", "PUBLIC_PASSIVE") or "PUBLIC_PASSIVE").upper()
    client_ip = request.client.host if request.client else "127.0.0.1"
    _enforce_rate_limits(db, client_ip, principal, mode)
    authorization, _ = _scan_authorization(db, payload, principal)
    task_id = create_job(db, payload.url)
    submit_scan_job(task_id, payload.url, authorization.id if authorization else None, principal.user_id)
    return {"task_id": task_id, "status": "QUEUED", "scan_mode": mode}

@router.post("/scan-jobs/{task_id}/cancel")
def cancel_scan_job(task_id: str, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id == task_id).first()
    if not row:
        raise HTTPException(404, "Scan job not found")
    if row.status in ["COMPLETED", "FAILED"]:
        return {"task_id": task_id, "status": row.status, "message": "Job already finalized"}
    row.status = "CANCELLED"
    row.completed_at = datetime.now(timezone.utc)
    db.commit()
    return {"task_id": task_id, "status": "CANCELLED"}

@router.get("/scan-jobs/{task_id}/events")
def get_scan_job_events(task_id: str, db: Session = Depends(get_db)):
    row = db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id == task_id).first()
    if not row:
        raise HTTPException(404, "Scan job not found")
    events = [
        {"stage": "URL_VALIDATION", "status": "COMPLETED", "occurred_at": row.started_at},
        {"stage": "DNS_RESOLUTION", "status": "COMPLETED" if row.status in ["COMPLETED", "RUNNING"] else "PENDING"},
        {"stage": "TLS_CERTIFICATE", "status": "COMPLETED" if row.status in ["COMPLETED", "RUNNING"] else "PENDING"},
        {"stage": "THREAT_INTELLIGENCE", "status": "COMPLETED" if row.status == "COMPLETED" else "RUNNING" if row.status == "RUNNING" else "PENDING"},
        {"stage": "RISK_CALCULATION", "status": "COMPLETED" if row.status == "COMPLETED" else "PENDING"},
        {"stage": "EVIDENCE_PERSISTENCE", "status": "COMPLETED" if row.status == "COMPLETED" else "PENDING"}
    ]
    return {"task_id": task_id, "job_status": row.status, "events": events}

@router.get("/abuse-events")
def list_abuse_events(limit: int = 50, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    rows = db.query(AbuseEvent).order_by(AbuseEvent.created_at.desc()).limit(limit).all()
    return [{
        "id": r.id,
        "event_type": r.event_type,
        "client_ip": r.client_ip,
        "user_id": r.user_id,
        "tenant_id": r.tenant_id,
        "details": json.loads(r.details_json or "{}"),
        "created_at": r.created_at
    } for r in rows]

@router.get("/quotas/status")
def get_quota_status(request: Request, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = datetime.now(timezone.utc)
    minute_bucket = now.strftime("%Y-%m-%d-%H-%M")
    day_bucket = now.strftime("%Y-%m-%d")
    client_key = f"ip:{client_ip}" if not principal.authenticated else f"user:{principal.user_id}"
    min_record = db.query(RateLimitRecord).filter(RateLimitRecord.client_key == client_key, RateLimitRecord.window_bucket == minute_bucket).first()
    day_record = db.query(RateLimitRecord).filter(RateLimitRecord.client_key == f"anon:{client_ip}", RateLimitRecord.window_bucket == day_bucket).first()
    return {
        "client_ip": client_ip,
        "authenticated": principal.authenticated,
        "user_id": principal.user_id,
        "minute_limit": 5,
        "minute_used": min_record.request_count if min_record else 0,
        "minute_remaining": max(0, 5 - (min_record.request_count if min_record else 0)),
        "daily_limit": 50,
        "daily_used": day_record.request_count if day_record else 0,
        "daily_remaining": max(0, 50 - (day_record.request_count if day_record else 0))
    }

@router.get("/scan-jobs/{task_id}")
def get_realtime_scan_job(task_id: str, db: Session = Depends(get_db)):
    row = db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id == task_id, BackgroundTaskRun.task_name == "real_time_scan").first()
    if not row:
        raise HTTPException(404, "Scan job not found")
    response = {"task_id": row.task_id, "status": row.status, "error": row.error, "started_at": row.started_at, "completed_at": row.completed_at}
    if row.result_json:
        data = json.loads(row.result_json)
        response.update(data)
        scan_id = data.get("scan_id") or (data.get("result", {}).get("id"))
        if scan_id:
            provenance_rows = db.query(FindingEvidenceProvenance).filter(FindingEvidenceProvenance.scan_id == scan_id).order_by(FindingEvidenceProvenance.id).all()
            if provenance_rows:
                serialized = [serialize_provenance(p) for p in provenance_rows]
                response.setdefault("result", {})["evidence_provenance"] = serialized
                response["evidence_provenance"] = serialized
    return response

@router.get("/scans")
def history(limit: int = Query(1000, ge=1, le=1000), principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    query = db.query(Scan)
    if principal.role != "admin":
        if principal.authenticated:
            query = query.filter((Scan.created_by == principal.user_id) | (Scan.scan_mode == "PUBLIC_PASSIVE"))
        else:
            query = query.filter(Scan.scan_mode == "PUBLIC_PASSIVE")
    return [{"id": x.id, "url": x.url, "domain": x.domain, "risk_score": x.risk_score, "risk_level": x.risk_level, "scan_mode": x.scan_mode, "created_at": x.created_at} for x in query.order_by(Scan.created_at.desc()).limit(limit).all()]

@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    if not row: raise HTTPException(404, "Scan not found")
    if principal.role != "admin" and row.scan_mode != "PUBLIC_PASSIVE" and row.created_by != principal.user_id:
        raise HTTPException(403, "Access to scan is restricted to its owner or administrator")
    result_data = json.loads(row.result_json) if row.result_json else {}
    provenance_rows = db.query(FindingEvidenceProvenance).filter(FindingEvidenceProvenance.scan_id == row.id).order_by(FindingEvidenceProvenance.id).all()
    if provenance_rows:
        result_data["evidence_provenance"] = [serialize_provenance(p) for p in provenance_rows]
    return {"id": row.id, **result_data, "created_at": row.created_at}

@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    if not row:
        raise HTTPException(404, "Scan not found")
    if principal.role != "admin" and row.scan_mode != "PUBLIC_PASSIVE" and row.created_by != principal.user_id and principal.authenticated:
        raise HTTPException(403, "Access to delete scan is restricted to its owner or administrator")

    db.query(FindingEvidenceProvenance).filter(FindingEvidenceProvenance.scan_id == scan_id).delete(synchronize_session=False)
    db.query(RedirectHop).filter(RedirectHop.scan_id == scan_id).delete(synchronize_session=False)
    db.query(ProviderVerdict).filter(ProviderVerdict.scan_id == scan_id).delete(synchronize_session=False)
    db.query(DomainIntelligence).filter(DomainIntelligence.scan_id == scan_id).delete(synchronize_session=False)
    db.query(CertificateRecord).filter(CertificateRecord.scan_id == scan_id).delete(synchronize_session=False)

    if principal.authenticated:
        record_audit_event(
            db=db,
            user_id=principal.user_id,
            action="SCAN_DELETED",
            resource_type="scan",
            resource_id=str(scan_id),
            details={"url": row.url, "domain": row.domain},
            tenant_id=principal.tenant_id
        )

    db.delete(row)
    db.commit()
    return {"deleted": True, "scan_id": scan_id}

@router.get("/evidence-provenance")
def list_evidence_provenance(
    scan_id: int | None = None,
    scan_job_id: str | None = None,
    finding_id: str | None = None,
    source_provider: str | None = None,
    is_current: bool | None = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = db.query(FindingEvidenceProvenance)
    if scan_id is not None:
        query = query.filter(FindingEvidenceProvenance.scan_id == scan_id)
    if scan_job_id:
        query = query.filter(FindingEvidenceProvenance.scan_job_id == scan_job_id.strip())
    if finding_id:
        query = query.filter(FindingEvidenceProvenance.finding_id == finding_id.strip())
    if source_provider:
        query = query.filter(FindingEvidenceProvenance.source_provider.ilike(f"%{source_provider.strip()}%"))
    if is_current is not None:
        query = query.filter(FindingEvidenceProvenance.is_current == is_current)
    rows = query.order_by(FindingEvidenceProvenance.id.desc()).limit(limit).all()
    return {"count": len(rows), "items": [serialize_provenance(r) for r in rows]}

@router.get("/evidence-provenance/{provenance_id}")
def get_single_evidence_provenance(provenance_id: int, db: Session = Depends(get_db)):
    row = db.get(FindingEvidenceProvenance, provenance_id)
    if not row:
        raise HTTPException(404, "Evidence provenance record not found")
    return serialize_provenance(row)

@router.post("/evidence-provenance/{provenance_id}/verify")
def verify_single_evidence_provenance(provenance_id: int, db: Session = Depends(get_db)):
    row = db.get(FindingEvidenceProvenance, provenance_id)
    if not row:
        raise HTTPException(404, "Evidence provenance record not found")
    res = verify_content_hash(row.content_hash, row.evidence_payload_json)
    return {"id": row.id, "finding_id": row.finding_id, **res}

@router.post("/evidence-provenance/{provenance_id}/link-revision")
def link_provenance_to_revision(provenance_id: int, payload: LinkRevisionRequest, db: Session = Depends(get_db)):
    row = db.get(FindingEvidenceProvenance, provenance_id)
    if not row:
        raise HTTPException(404, "Evidence provenance record not found")
    if payload.report_id is not None:
        row.report_id = payload.report_id
    if payload.revision_id is not None:
        row.revision_id = payload.revision_id
    db.commit()
    return serialize_provenance(row)

@router.post("/evidence-provenance/verify-hash")
def verify_arbitrary_evidence_hash(payload: VerifyHashRequest):
    content_hash, canonical_json = canonicalize_evidence(payload.payload)
    matches = (content_hash.lower() == payload.expected_hash.strip().lower())
    return {
        "verified": matches,
        "matches": matches,
        "hash_algorithm": "SHA-256",
        "stored_hash": payload.expected_hash,
        "computed_hash": content_hash,
        "canonical_payload": canonical_json,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }

@router.get("/scans/{scan_id}/evidence-chain")
def scan_evidence_chain(scan_id: int, db: Session = Depends(get_db)):
    """Return the persisted evidence-to-provenance chain for one website scan.

    Empty stages are intentional: a local scan is not silently represented as
    a report revision or blockchain anchor until those records actually exist.
    """
    from backend.app.models.models import IndicatorObservation, SecurityAssessment, SecurityFinding, SecurityEvidence, ReportCommitment, ProvenanceEvent, AppendOnlyLedgerEvent, BlockchainTransaction
    row = db.get(Scan, scan_id)
    if not row:
        raise HTTPException(404, "Scan not found")
    result = json.loads(row.result_json or "{}")
    providers = db.query(ProviderVerdict).filter(ProviderVerdict.scan_id == scan_id).order_by(ProviderVerdict.checked_at.asc()).all()
    observations = db.query(IndicatorObservation).filter(IndicatorObservation.source_analysis_id == str(scan_id)).order_by(IndicatorObservation.first_observed.asc()).all()
    assessment = db.query(SecurityAssessment).filter(SecurityAssessment.scan_id == scan_id).order_by(SecurityAssessment.id.desc()).first()
    findings = []
    security_evidence = []
    if assessment:
        finding_rows = db.query(SecurityFinding).filter(SecurityFinding.assessment_id == assessment.id).order_by(SecurityFinding.id.asc()).all()
        finding_ids = [item.id for item in finding_rows]
        evidence_rows = db.query(SecurityEvidence).filter(SecurityEvidence.assessment_id == assessment.id).order_by(SecurityEvidence.id.asc()).all()
        findings = [{"id": item.id, "title": item.title, "status": item.status, "severity": item.severity, "confidence": item.confidence, "evidence": json.loads(item.evidence_json or "{}"), "detected_at": item.last_detected} for item in finding_rows]
        security_evidence = [{"id": item.id, "finding_id": item.finding_id, "source": item.source, "evidence_type": item.evidence_type, "details": json.loads(item.details_json or "{}"), "observed_at": item.observed_at} for item in evidence_rows if not finding_ids or item.finding_id in finding_ids]

    revisions = []
    for revision in db.query(ReportRevision).order_by(ReportRevision.created_at.asc()).all():
        try:
            payload = json.loads(revision.canonical_payload or "{}")
        except (TypeError, ValueError):
            payload = {}
        if str(payload.get("scan_id") or payload.get("source_scan_id") or "") != str(scan_id):
            continue
        commitment = db.query(ReportCommitment).filter(ReportCommitment.revision_id == revision.id).first()
        ledger = db.query(AppendOnlyLedgerEvent).filter(AppendOnlyLedgerEvent.revision_id == revision.id).order_by(AppendOnlyLedgerEvent.sequence_number.asc()).all()
        blockchain = db.query(BlockchainTransaction).filter(BlockchainTransaction.revision_id == revision.id).order_by(BlockchainTransaction.id.asc()).all()
        revisions.append({"id": revision.id, "report_id": revision.report_id, "revision_number": revision.revision_number, "hash": revision.canonical_report_hash, "created_at": revision.created_at, "commitment": {"id": commitment.id, "value": commitment.commitment, "scope": commitment.commitment_scope} if commitment else None, "ledger": [{"id": event.id, "sequence": event.sequence_number, "hash": event.event_hash, "type": event.event_type, "occurred_at": event.occurred_at} for event in ledger], "blockchain": [{"id": tx.id, "hash": tx.tx_hash, "status": tx.status, "confirmations": tx.confirmations, "block_number": tx.block_number} for tx in blockchain]})

    def stage(name, status, items, explanation):
        return {"stage": name, "status": status, "items": items, "explanation": explanation}

    provider_items = [{"id": item.id, "provider": item.provider, "status": item.status, "verdict": item.verdict, "evidence": json.loads(item.evidence_json or "{}"), "checked_at": item.checked_at, "confidence": (json.loads(item.evidence_json or "{}").get("confidence"))} for item in providers]
    indicator_items = [{"id": item.id, "indicator_id": item.indicator_id, "normalized_value": item.normalized_value, "source_analysis_type": item.source_analysis_type, "provider": item.source_provider, "status": item.verification_status, "confidence": item.confidence, "observed_at": item.last_observed} for item in observations]
    ledger_items = [event for revision in revisions for event in revision["ledger"]]
    commitment_items = [revision["commitment"] | {"revision_id": revision["id"], "created_at": revision["created_at"]} for revision in revisions if revision.get("commitment")]
    blockchain_items = [item | {"revision_id": revision["id"]} for revision in revisions for item in revision["blockchain"]]
    return {"scan_id": row.id, "target": row.url, "observed_at": row.created_at, "stages": [
        stage("OBSERVATION", "RECORDED", [{"id": row.id, "type": "WEBSITE_SCAN", "target": row.url, "status": row.status, "observed_at": row.created_at}], "The scanner observation persisted for this target."),
        stage("PROVIDER_RESULT", "RECORDED" if provider_items else "UNKNOWN", provider_items, "Provider state, verdict, evidence and check time come from persisted provider records."),
        stage("NORMALIZED_INDICATOR", "RECORDED" if indicator_items else "UNKNOWN", indicator_items, "Only persisted indicator observations linked to this scan are shown."),
        stage("FINDING", "RECORDED" if findings else "UNKNOWN", findings + security_evidence, "Findings and security evidence are shown only when a persisted assessment is linked to this scan."),
        stage("REPORT_REVISION", "RECORDED" if revisions else "NOT_CREATED", revisions, "A report revision is not inferred from a scan; it must explicitly reference the scan."),
        stage("CANONICAL_COMMITMENT", "RECORDED" if commitment_items else "NOT_CREATED", commitment_items, "Commitments are local canonical hashes until a verified external anchor exists."),
        stage("APPEND_ONLY_LEDGER_EVENT", "RECORDED" if ledger_items else "NOT_CREATED", ledger_items, "Ledger events are the local tamper-evident provenance layer."),
        stage("BLOCKCHAIN_ANCHOR", "RECORDED" if blockchain_items else "NOT_ANCHORED", blockchain_items, "Blockchain status is reported only from persisted transaction metadata."),
    ], "risk": result.get("risk", {}), "freshness": {"observed_at": row.created_at, "provider_records": len(provider_items), "policy": "Freshness is measured from each source timestamp; unavailable data is not treated as clean."}}

@router.get("/scans/{scan_id}/certificate")
def certificate_details(scan_id: int, db: Session = Depends(get_db)):
    row=db.get(Scan,scan_id)
    if not row: raise HTTPException(404,"Scan not found")
    result=json.loads(row.result_json); return {"scan_id":scan_id,"domain":row.domain,"certificate":result.get("certificate",{}),"validation":result.get("certificate",{}).get("validation",{}),"ct_records":result.get("certificate",{}).get("ct_records",[]),"checked_at":result.get("certificate",{}).get("checked_at")}

@router.get("/scans/{scan_id}/certificate/chain")
def certificate_chain_details(scan_id: int, db: Session = Depends(get_db)):
    if not db.get(Scan,scan_id): raise HTTPException(404,"Scan not found")
    result=json.loads(db.get(Scan,scan_id).result_json); cert=result.get("certificate",{}); validation=cert.get("validation",{}); return {"scan_id":scan_id,"certificates":[{k:v for k,v in item.items() if k != "der"} for item in cert.get("certificates",[])],"trust_anchor":validation.get("trust_anchor"),"errors":cert.get("errors",[]),"status":validation.get("status",cert.get("status","UNKNOWN")),"validation":validation,"alternative_paths":validation.get("alternative_paths",cert.get("alternative_paths",[]))}

@router.get("/scans/{scan_id}/certificate/validation")
def certificate_validation(scan_id: int, db: Session = Depends(get_db)):
    row=db.get(CertificateValidationResult,db.query(CertificateValidationResult).filter(CertificateValidationResult.scan_id==scan_id).order_by(CertificateValidationResult.checked_at.desc()).first().id if db.query(CertificateValidationResult).filter(CertificateValidationResult.scan_id==scan_id).first() else -1)
    if not row: raise HTTPException(404,"Certificate validation not found")
    return {"scan_id":scan_id,"status":row.status,"trust_anchor":row.trust_anchor,"errors":json.loads(row.errors_json or "[]"),"evidence":json.loads(row.evidence_json or "{}"),"checked_at":row.checked_at}

@router.get("/scans/{scan_id}/certificate/revocation")
def certificate_revocation(scan_id: int, db: Session = Depends(get_db)):
    if not db.get(Scan, scan_id): raise HTTPException(404, "Scan not found")
    rows=db.query(CertificateRevocationResult).filter(CertificateRevocationResult.scan_id==scan_id).order_by(CertificateRevocationResult.role,CertificateRevocationResult.id).all()
    statuses=[row.status for row in rows]
    overall="REVOKED" if "REVOKED" in statuses else "UNKNOWN" if not rows or any(item in {"UNKNOWN","UNAVAILABLE","INVALID_RESPONSE"} for item in statuses) else "GOOD"
    return {"scan_id":scan_id,"status":overall,"certificates":[{"fingerprint_sha256":row.certificate_fingerprint,"role":row.role,"status":row.status,"ocsp_status":row.ocsp_status,"crl_status":row.crl_status,"distrust_status":row.distrust_status,"ca_reputation":row.ca_reputation,"evidence":json.loads(row.evidence_json or "{}"),"checked_at":row.checked_at} for row in rows]}

@router.get("/scans/{scan_id}/certificate/transparency")
def certificate_transparency(scan_id: int, db: Session = Depends(get_db)):
    if not db.get(Scan,scan_id): raise HTTPException(404,"Scan not found")
    result=json.loads(db.get(Scan,scan_id).result_json); ct=result.get("certificate",{}).get("ct_intelligence",{})
    entries=db.query(CertificateTransparencyEntry).filter(CertificateTransparencyEntry.scan_id==scan_id).order_by(CertificateTransparencyEntry.not_before,CertificateTransparencyEntry.observation_timestamp).all()
    anomalies=db.query(CertificateTransparencyAnomaly).filter(CertificateTransparencyAnomaly.scan_id==scan_id).order_by(CertificateTransparencyAnomaly.observation_timestamp).all()
    return {"scan_id":scan_id,"status":ct.get("status","UNAVAILABLE"),"source":ct.get("source","crt.sh"),"query":ct.get("query"),"checked_at":ct.get("checked_at"),"errors":ct.get("errors",[]),"entries":[{"certificate_id":row.certificate_id,"fingerprint_sha256":row.fingerprint_sha256,"issuer":row.issuer,"subject":row.subject,"san_domains":json.loads(row.san_json or "[]"),"serial_number":row.serial_number,"not_before":row.not_before,"not_after":row.not_after,"observation_timestamp":row.observation_timestamp,"ct_log":row.ct_log,"source":row.source,"status":row.status} for row in entries],"anomalies":[{"finding_type":row.finding_type,"fingerprint":row.fingerprint,"domain":row.domain,"issuer":row.issuer,"source":row.source,"observation_timestamp":row.observation_timestamp,"confidence":row.confidence,"evidence":json.loads(row.evidence_json or "{}"),"explanation":row.explanation} for row in anomalies]}

@router.get("/scans/{scan_id}/certificate/risk")
def certificate_risk(scan_id: int, db: Session = Depends(get_db)):
    row=db.query(CertificateRiskAssessment).filter(CertificateRiskAssessment.scan_id==scan_id).order_by(CertificateRiskAssessment.checked_at.desc()).first()
    if not row: raise HTTPException(404,"Certificate risk assessment not found")
    return {"scan_id":scan_id,"score":row.score,"level":row.level,"confidence":row.confidence,"validation_status":row.validation_status,"tls_grade":row.tls_grade,"revocation_status":row.revocation_status,"ca_trust_status":row.ca_trust_status,"ct_anomaly_score":row.ct_anomaly_score,"findings":json.loads(row.findings_json or "[]"),"evidence":json.loads(row.evidence_json or "{}"),"checked_at":row.checked_at}

@router.post("/scans/{scan_id}/certificate/revocation/refresh")
def refresh_certificate_revocation(scan_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not db.get(Scan,scan_id): raise HTTPException(404,"Scan not found")
    active=db.query(CertificateRevocationJob).filter(CertificateRevocationJob.scan_id==scan_id,CertificateRevocationJob.status.in_(["PENDING","RUNNING"])).first()
    if active: return {"job_id":active.id,"status":active.status}
    job=CertificateRevocationJob(scan_id=scan_id,status="PENDING",requested_at=datetime.now(timezone.utc)); db.add(job); db.commit(); db.refresh(job)
    background_tasks.add_task(_refresh_revocation_job,job.id,scan_id)
    return {"job_id":job.id,"status":"PENDING"}

@router.get("/certificate/revocation/jobs/{job_id}")
def certificate_revocation_job(job_id: int, db: Session = Depends(get_db)):
    job=db.get(CertificateRevocationJob,job_id)
    if not job: raise HTTPException(404,"Revocation job not found")
    return {"job_id":job.id,"scan_id":job.scan_id,"status":job.status,"requested_at":job.requested_at,"started_at":job.started_at,"completed_at":job.completed_at,"error":job.error}

@router.get("/domains/{domain}/certificate/history")
def certificate_history(domain: str, db: Session = Depends(get_db)):
    return [{"scan_id":scan.id,"status":validation.status,"checked_at":validation.checked_at} for scan in db.query(Scan).filter(Scan.domain==domain.lower().rstrip(".")).all() for validation in db.query(CertificateValidationResult).filter(CertificateValidationResult.scan_id==scan.id).all()]

@router.get("/scans/{scan_id}/infrastructure-graph")
def infrastructure_graph(scan_id: int, db: Session = Depends(get_db)):
    row=db.get(Scan, scan_id)
    if not row: raise HTTPException(404,"Scan not found")
    result=json.loads(row.result_json); intel=result.get("domain_intelligence",{}); current_ips=set((intel.get("infrastructure") or {}).get("ips",[])); current_ns=set((intel.get("rdap") or {}).get("nameservers",[])); related=[]
    for item in db.query(DomainIntelligence).filter(DomainIntelligence.scan_id != scan_id).order_by(DomainIntelligence.created_at.desc()).limit(100).all():
        try: other=json.loads(item.infrastructure_json or "{}"); other_intel=json.loads(item.rdap_json or "{}"); other_ips=set(other.get("ips",[])); other_ns=set(other_intel.get("nameservers",[]))
        except (ValueError,TypeError): continue
        if current_ips & other_ips: related.append({"domain":item.domain,"relationship":"shared_ip","evidence":f"Shared IP: {', '.join(sorted(current_ips & other_ips))}"})
        elif current_ns & other_ns: related.append({"domain":item.domain,"relationship":"shared_nameserver","evidence":f"Shared nameserver: {', '.join(sorted(current_ns & other_ns))}"})
    return build_graph(row.domain,intel,result.get("threat_intelligence",{}).get("findings",[]),related)

@router.get("/scans/{scan_id}/redirects")
def redirect_chain(scan_id: int, db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    if not row: raise HTTPException(404, "Scan not found")
    result = json.loads(row.result_json)
    analysis = result.get("network", {}).get("redirect_analysis", {})
    hops = db.query(RedirectHop).filter(RedirectHop.scan_id == scan_id).order_by(RedirectHop.sequence).all()
    return {"scan_id": scan_id, "original_url": row.normalized_url, "hops": [json.loads(json.dumps({"sequence":h.sequence,"source_url":h.source_url,"destination_url":h.destination_url,"source_domain":h.source_domain,"destination_domain":h.destination_domain,"status_code":h.status_code,"redirect_type":h.redirect_type,"https":h.https,"https_downgrade":h.https_downgrade,"destination_ips":json.loads(h.destination_ips_json or "[]"),"reputation":json.loads(h.reputation_json or "{}"),"analysis_status":h.analysis_status,"checked_at":h.checked_at}, default=str)) for h in hops], "risk": analysis.get("risk", {}), "comparison": analysis.get("comparison", {}), "destinations": analysis.get("destinations", {})}

@router.get("/scans/{scan_id}/redirects/{sequence}")
def redirect_hop(scan_id: int, sequence: int, db: Session = Depends(get_db)):
    row = db.query(RedirectHop).filter(RedirectHop.scan_id == scan_id, RedirectHop.sequence == sequence).first()
    if not row: raise HTTPException(404, "Redirect hop not found")
    return {"scan_id": scan_id, "sequence": row.sequence, "source_url": row.source_url, "destination_url": row.destination_url, "source_domain": row.source_domain, "destination_domain": row.destination_domain, "status_code": row.status_code, "redirect_type": row.redirect_type, "https": row.https, "https_downgrade": row.https_downgrade, "destination_ips": json.loads(row.destination_ips_json or "[]"), "reputation": json.loads(row.reputation_json or "{}"), "analysis_status": row.analysis_status, "checked_at": row.checked_at}

@router.post("/scans/{scan_id}/redirects/{sequence}/retry")
def retry_redirect_hop(scan_id: int, sequence: int, db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    hop = db.query(RedirectHop).filter(RedirectHop.scan_id == scan_id, RedirectHop.sequence == sequence).first()
    if not row or not hop: raise HTTPException(404, "Redirect hop not found")
    result=json.loads(row.result_json); destination=hop.destination_url; domain=hop.destination_domain
    threats=check_threats(destination); intel=collect_domain_intelligence(destination, domain)
    destination_result={"status":"complete", "verdict":"malicious" if any(p.get("verdict") in {"malicious","phishing"} for p in threats.get("providers",[])) else "suspicious" if any(p.get("verdict")=="suspicious" for p in threats.get("providers",[])) else "unknown", "threat_intelligence":threats, "provider_results":_destination_providers(threats,intel), "brand_matches":intel.get("domain",{}).get("brand_matches",[]), "domain_intelligence":intel}
    analysis=result.setdefault("network",{}).setdefault("redirect_analysis",{}); destinations=analysis.setdefault("destinations",{}); destinations[domain]=destination_result
    analysis["risk"]=score_redirect_chain(result.get("normalized_url",row.normalized_url), result.get("network",{}).get("http",{}).get("redirects",[]), destinations)
    hop.reputation_json=json.dumps(destination_result); hop.analysis_status="complete"; row.result_json=json.dumps(result); row.risk_score=result.get("risk",{}).get("score",row.risk_score); db.commit()
    return {"scan_id":scan_id, "sequence":sequence, **destination_result}

@router.post("/reports")
def report(payload: ReportRequest, db: Session = Depends(get_db)):
    row = CommunityReport(**payload.model_dump()); db.add(row); db.commit(); db.refresh(row); return row

@router.get("/reports")
def reports(db: Session = Depends(get_db)):
    return db.query(CommunityReport).order_by(CommunityReport.created_at.desc()).limit(50).all()

@router.post("/message-analysis")
def message_analysis(payload: dict, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    text = payload.get("text", "")
    if not isinstance(text, str) or not 1 <= len(text) <= 20000: raise HTTPException(400, "text must contain 1-20000 characters")
    brands=[{"brand_name": row.brand_name, "official_domain": row.official_domain, "verification_status": row.verification_status} for row in db.query(BrandRegistry).all()]
    email_providers=[{"domain": row.domain, "provider_name": row.provider_name, "category": row.category, "disposable": row.disposable, "source": row.source, "list_version": row.list_version} for row in db.query(EmailProviderRegistry).all()]
    result=analyze_message(text, brands=brands, email_providers=email_providers)
    owner = principal.user_id; digest = hashlib.sha256(text.encode()).hexdigest()
    previous = db.query(MessageAnalysisMetadata).join(MessageAnalysisRecord, MessageAnalysisMetadata.message_analysis_id == MessageAnalysisRecord.id).filter(MessageAnalysisMetadata.user_id == owner, MessageAnalysisRecord.input_sha256 == digest).order_by(MessageAnalysisMetadata.created_at.desc()).first()
    record=MessageAnalysisRecord(input_sha256=digest, source_type="TEXT", result_json=json.dumps(result)); db.add(record); db.flush()
    ml = result.get("ml") or {}
    db.add(MessageContent(message_analysis_id=record.id, content_bytes=text.encode(), sha256=digest, content_type="text/plain"))
    db.add(MessageAnalysisMetadata(message_analysis_id=record.id, user_id=owner, input_type="TEXT", sender=None, subject=None, risk_score=result.get("score"), classification=result.get("classification"), ml_prediction=ml.get("prediction"), ml_confidence=ml.get("malicious_probability"), llm_status=(result.get("llm") or {}).get("status") or ("CONNECTED" if (result.get("llm") or {}).get("available") else "UNAVAILABLE"), model_version=ml.get("model") or "current", analysis_status="COMPLETED", duplicate_of_id=previous.message_analysis_id if previous else None))
    db.add(MessageReview(message_analysis_id=record.id, status="PENDING_REVIEW", created_by=owner, updated_by=owner))
    db.add(MessageAnalysisEvent(message_analysis_id=record.id, user_id=owner, event_type="created", details_json=json.dumps({"input_type":"TEXT", "duplicate": bool(previous)})))
    intel=result.get("indicator_intelligence", {})
    for indicator_type in ("urls", "emails", "phones"):
        for item in intel.get(indicator_type, []):
            for provider in item.get("provider_results", []) or [{"provider": item.get("provider", "local"), "status": item.get("status", "UNKNOWN"), "verdict": item.get("verdict", "unknown")}]:
                db.add(MessageIndicatorResult(message_analysis_id=record.id, indicator_type=indicator_type[:-1], indicator=item.get("indicator", ""), provider=provider.get("provider", "unknown"), status=provider.get("status", "UNKNOWN"), verdict=provider.get("verdict", "unknown"), result_json=json.dumps(provider)))
            if indicator_type in ("emails", "phones"):
                db.add(ContactRiskAssessment(message_analysis_id=record.id, indicator_type=indicator_type[:-1], indicator=item.get("indicator", ""), score=int(item.get("risk_score") or 0), classification=item.get("classification", "UNKNOWN"), confidence=item.get("confidence", "low"), evidence_json=json.dumps(item), checked_at=datetime.now(timezone.utc)))
    for finding in intel.get("domain_spoofing", []): db.add(MessageDomainSpoofingFinding(message_analysis_id=record.id, observed_domain=finding.get("observed_domain", ""), official_domain=finding.get("official_domain"), brand=finding.get("brand"), similarity=finding.get("similarity"), edit_distance=finding.get("edit_distance"), technique=finding.get("technique", "unknown"), confidence=finding.get("confidence", "unknown"), verification_status=finding.get("verification_status", "unknown"), evidence_json=json.dumps(finding)))
    db.commit(); result["analysis_id"] = record.id
    return result

@router.post("/message-analysis/email")
async def email_message_analysis(file: UploadFile = File(...), principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    filename = file.filename or "uploaded.eml"
    if not filename.lower().endswith(".eml"):
        raise HTTPException(400, "Only .eml files are supported")
    raw = await file.read(MAX_EMAIL_BYTES + 1)
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(413, "Email file exceeds the 10 MB limit")
    try:
        result = analyze_email(raw, filename, file.content_type or "")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    dkim_results = verify_dkim_signatures(raw)
    result["dkim_verification"] = dkim_results
    for item in result.get("authentication", []):
        if item.get("mechanism") == "DKIM": item["independent_verification"] = dkim_results
    sender = result.get("sender", {})
    brands=[{"brand_name": item.brand_name, "official_domain": item.official_domain, "verification_status": item.verification_status} for item in db.query(BrandRegistry).all()]
    email_providers=[{"domain": item.domain, "provider_name": item.provider_name, "category": item.category, "disposable": item.disposable, "source": item.source, "list_version": item.list_version} for item in db.query(EmailProviderRegistry).all()]
    result["indicator_intelligence"] = analyze_indicators(result.get("indicators", {}), sender=sender, brands=brands, email_providers=email_providers)
    owner = principal.user_id; digest = hashlib.sha256(raw).hexdigest()
    previous = db.query(MessageAnalysisMetadata).join(EmailAnalysis, MessageAnalysisMetadata.email_analysis_id == EmailAnalysis.id).filter(MessageAnalysisMetadata.user_id == owner, EmailAnalysis.id.in_(db.query(EmailRawMessage.analysis_id).filter(EmailRawMessage.sha256 == digest))).order_by(MessageAnalysisMetadata.created_at.desc()).first()
    row = EmailAnalysis(filename=filename, content_type=file.content_type or "", size_bytes=len(raw), message_id=sender.get("message_id"), sender=sender.get("from"), subject=sender.get("subject"), analysis_status=result.get("status", "COMPLETED"), result_json=json.dumps(result))
    db.add(row); db.flush(); db.add(EmailRawMessage(analysis_id=row.id, raw_bytes=raw, sha256=hashlib.sha256(raw).hexdigest()))
    ml = result.get("ml") or {}
    db.add(MessageAnalysisMetadata(email_analysis_id=row.id, user_id=owner, input_type="EML", sender=sender.get("from"), subject=sender.get("subject"), risk_score=result.get("score"), classification=result.get("classification"), ml_prediction=ml.get("prediction"), ml_confidence=ml.get("malicious_probability"), llm_status=(result.get("llm") or {}).get("status") or "UNAVAILABLE", model_version=ml.get("model") or "current", analysis_status=result.get("status", "COMPLETED"), duplicate_of_id=previous.email_analysis_id if previous else None))
    db.add(MessageReview(email_analysis_id=row.id, status="PENDING_REVIEW", created_by=owner, updated_by=owner))
    db.add(MessageAnalysisEvent(email_analysis_id=row.id, user_id=owner, event_type="created", details_json=json.dumps({"input_type":"EML", "duplicate": bool(previous)})))
    for item in result.get("headers", []): db.add(EmailHeader(analysis_id=row.id, header_name=item["name"], header_value=item["value"], normalized_value=item.get("normalized"), position=item.get("position", 0)))
    for item in result.get("authentication", []): db.add(EmailAuthenticationResult(analysis_id=row.id, mechanism=item["mechanism"], status=item["status"], domain=item.get("domain"), selector=item.get("selector"), source=item.get("source"), evidence_json=json.dumps(item.get("evidence", {})), checked_at=datetime.now(timezone.utc)))
    for item in result.get("anomalies", []): db.add(EmailHeaderAnomaly(analysis_id=row.id, anomaly_type=item["type"], severity=item["severity"], evidence=item["evidence"], created_at=datetime.now(timezone.utc)))
    intel=result.get("indicator_intelligence", {})
    for indicator_type in ("urls", "emails", "phones"):
        for item in intel.get(indicator_type, []):
            for provider in item.get("provider_results", []) or [{"provider": item.get("provider", "local"), "status": item.get("status", "UNKNOWN"), "verdict": item.get("verdict", "unknown")}]:
                db.add(MessageIndicatorResult(email_analysis_id=row.id, indicator_type=indicator_type[:-1], indicator=item.get("indicator", ""), provider=provider.get("provider", "unknown"), status=provider.get("status", "UNKNOWN"), verdict=provider.get("verdict", "unknown"), result_json=json.dumps(provider)))
            if indicator_type in ("emails", "phones"):
                db.add(ContactRiskAssessment(email_analysis_id=row.id, indicator_type=indicator_type[:-1], indicator=item.get("indicator", ""), score=int(item.get("risk_score") or 0), classification=item.get("classification", "UNKNOWN"), confidence=item.get("confidence", "low"), evidence_json=json.dumps(item), checked_at=datetime.now(timezone.utc)))
    for finding in intel.get("domain_spoofing", []): db.add(MessageDomainSpoofingFinding(email_analysis_id=row.id, observed_domain=finding.get("observed_domain", ""), official_domain=finding.get("official_domain"), brand=finding.get("brand"), similarity=finding.get("similarity"), edit_distance=finding.get("edit_distance"), technique=finding.get("technique", "unknown"), confidence=finding.get("confidence", "unknown"), verification_status=finding.get("verification_status", "unknown"), evidence_json=json.dumps(finding)))
    db.add(EmailVerificationRun(analysis_id=row.id, verification_type="DKIM", result_json=json.dumps({"signatures": dkim_results}), source="independent cryptographic verification"))
    db.commit(); result["analysis_id"] = row.id
    return result

@router.post("/message-analysis/email/{analysis_id}/smtp-context")
def ingest_smtp_context(analysis_id: int, payload: dict, x_smtp_context_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not settings.smtp_context_shared_secret or not x_smtp_context_token or not secrets.compare_digest(x_smtp_context_token, settings.smtp_context_shared_secret):
        raise HTTPException(403, "Authenticated SMTP context is required")
    row = db.get(EmailAnalysis, analysis_id)
    raw_row = db.query(EmailRawMessage).filter(EmailRawMessage.analysis_id == analysis_id).first()
    if not row or not raw_row: raise HTTPException(404, "Email analysis not found")
    required = [payload.get(key) for key in ("smtp_client_ip", "envelope_mail_from", "helo_hostname", "receiving_server", "message_id", "trusted_source", "received_at")]
    if not all(isinstance(value, str) and value.strip() for value in required): raise HTTPException(400, "All trusted SMTP context fields are required")
    result = json.loads(row.result_json); expected_message_id = result.get("sender", {}).get("message_id", "")
    if payload["message_id"] != expected_message_id: raise HTTPException(400, "SMTP context does not match the uploaded Message-ID")
    try: received_at = datetime.fromisoformat(payload["received_at"].replace("Z", "+00:00"))
    except ValueError: raise HTTPException(400, "received_at must be an ISO timestamp")
    if received_at.tzinfo is None: received_at = received_at.replace(tzinfo=timezone.utc)
    age_seconds = (datetime.now(timezone.utc) - received_at).total_seconds()
    if age_seconds < -300 or age_seconds > settings.smtp_context_max_age_seconds: raise HTTPException(400, "SMTP context timestamp is outside the accepted age window")
    context = {**payload, "received_at": received_at.isoformat()}
    spf_result = evaluate_spf_context(context, result.get("sender", {}).get("from_domain"), [])
    dmarc_domain = result.get("sender", {}).get("from_domain")
    dmarc_records = []
    if dmarc_domain:
        from backend.app.engines.email_analysis import _dns_txt
        _, dmarc_records, _ = _dns_txt(f"_dmarc.{dmarc_domain}")
    dkim_results = result.get("dkim_verification", [])
    dmarc_result = evaluate_dmarc_alignment(dmarc_domain, spf_result, dkim_results, dmarc_records)
    verification = {"smtp_context": context, "spf": spf_result, "dkim": dkim_results, "dmarc": dmarc_result, "checked_at": datetime.now(timezone.utc).isoformat()}
    result["trusted_authentication"] = verification; row.result_json = json.dumps(result)
    db.add(EmailSmtpContext(analysis_id=analysis_id, smtp_client_ip=context["smtp_client_ip"], envelope_mail_from=context["envelope_mail_from"], helo_hostname=context["helo_hostname"], receiving_server=context["receiving_server"], message_id=context["message_id"], trusted_source=context["trusted_source"], received_at=received_at))
    for mechanism, value in (("SPF", spf_result), ("DKIM", {"signatures": dkim_results}), ("DMARC", dmarc_result)):
        db.add(EmailVerificationRun(analysis_id=analysis_id, verification_type=mechanism, result_json=json.dumps(value), source=context["trusted_source"]))
    db.commit(); result["analysis_id"] = analysis_id
    return result

@router.get("/message-analysis/email/{analysis_id}")
def email_message_analysis_result(analysis_id: int, principal: Principal = Depends(get_current_principal), x_admin_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    row = db.get(EmailAnalysis, analysis_id)
    meta = db.query(MessageAnalysisMetadata).filter(MessageAnalysisMetadata.email_analysis_id == analysis_id).first()
    if not row or not meta or not _can_view(meta, principal.user_id, principal.role == "admin" or _admin(x_admin_token), principal.legacy_ids): raise HTTPException(404, "Email analysis not found")
    result = json.loads(row.result_json); result["analysis_id"] = row.id; result["created_at"] = row.created_at; result["metadata"] = _metadata_summary(meta)
    return result

@router.delete("/message-analysis/email/{analysis_id}")
def delete_email_analysis(analysis_id: int, principal: Principal = Depends(get_current_principal), x_admin_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    row=db.get(EmailAnalysis, analysis_id); meta=db.query(MessageAnalysisMetadata).filter(MessageAnalysisMetadata.email_analysis_id == analysis_id).first()
    if not row or not meta or not _can_view(meta, principal.user_id, principal.role == "admin" or _admin(x_admin_token), principal.legacy_ids): raise HTTPException(404, "Email analysis not found")
    review = db.query(MessageReview).filter(MessageReview.email_analysis_id == analysis_id).first()
    if review:
        db.query(MessageReviewFeedback).filter(MessageReviewFeedback.review_id == review.id).delete(synchronize_session=False); db.query(MessageReviewAudit).filter(MessageReviewAudit.review_id == review.id).delete(synchronize_session=False); db.delete(review)
    db.query(MessageAnalysisEvent).filter(MessageAnalysisEvent.email_analysis_id == analysis_id).delete(synchronize_session=False); db.query(MessageIndicatorResult).filter(MessageIndicatorResult.email_analysis_id == analysis_id).delete(synchronize_session=False); db.query(MessageDomainSpoofingFinding).filter(MessageDomainSpoofingFinding.email_analysis_id == analysis_id).delete(synchronize_session=False); db.query(ContactRiskAssessment).filter(ContactRiskAssessment.email_analysis_id == analysis_id).delete(synchronize_session=False); db.query(EmailHeader).filter(EmailHeader.analysis_id == analysis_id).delete(synchronize_session=False); db.query(EmailAuthenticationResult).filter(EmailAuthenticationResult.analysis_id == analysis_id).delete(synchronize_session=False); db.query(EmailHeaderAnomaly).filter(EmailHeaderAnomaly.analysis_id == analysis_id).delete(synchronize_session=False); db.query(EmailRawMessage).filter(EmailRawMessage.analysis_id == analysis_id).delete(synchronize_session=False); db.query(EmailVerificationRun).filter(EmailVerificationRun.analysis_id == analysis_id).delete(synchronize_session=False); db.query(EmailSmtpContext).filter(EmailSmtpContext.analysis_id == analysis_id).delete(synchronize_session=False)
    if principal.authenticated:
        record_audit_event(db, principal.user_id, "MESSAGE_ANALYSIS_DELETED", "email_analysis", str(analysis_id), {"kind": "EML"}, principal.tenant_id)
    db.delete(meta); db.delete(row); db.commit(); return {"deleted": True, "analysis_id": analysis_id}

@router.get("/message-analysis/history")
def message_analysis_history(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100), search: str | None = Query(default=None), risk: str | None = Query(default=None), input_type: str | None = Query(default=None), provider: str | None = Query(default=None), principal: Principal = Depends(get_current_principal), x_admin_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    owner_ids = [principal.user_id, *principal.legacy_ids]; query = db.query(MessageAnalysisMetadata)
    if not (principal.role == "admin" or _admin(x_admin_token)): query = query.filter(MessageAnalysisMetadata.user_id.in_(owner_ids))
    if search: query = query.filter(or_(MessageAnalysisMetadata.sender.ilike(f"%{search}%"), MessageAnalysisMetadata.subject.ilike(f"%{search}%")))
    if risk: query = query.filter(MessageAnalysisMetadata.classification.ilike(f"%{risk}%"))
    if input_type: query = query.filter(MessageAnalysisMetadata.input_type == input_type.upper())
    if provider:
        ids = [x[0] for x in db.query(MessageIndicatorResult.message_analysis_id).filter(MessageIndicatorResult.provider.ilike(f"%{provider}%")).distinct().all() if x[0] is not None]
        if ids: query = query.filter(MessageAnalysisMetadata.message_analysis_id.in_(ids))
        else: query = query.filter(MessageAnalysisMetadata.id == -1)
    total = query.count(); items = query.order_by(MessageAnalysisMetadata.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [_metadata_summary(item) for item in items], "page": page, "page_size": page_size, "total": total, "pages": (total + page_size - 1) // page_size}

@router.get("/message-analysis/text/{analysis_id}")
def message_analysis_detail(analysis_id: int, principal: Principal = Depends(get_current_principal), x_admin_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    row = db.get(MessageAnalysisRecord, analysis_id); meta = db.query(MessageAnalysisMetadata).filter(MessageAnalysisMetadata.message_analysis_id == analysis_id).first()
    if not row or not meta or not _can_view(meta, principal.user_id, principal.role == "admin" or _admin(x_admin_token), principal.legacy_ids): raise HTTPException(404, "Message analysis not found")
    result = json.loads(row.result_json); result["analysis_id"] = row.id; result["metadata"] = _metadata_summary(meta); result["history_events"] = [{"event_type": event.event_type, "created_at": event.created_at, "details": json.loads(event.details_json or "{}")} for event in db.query(MessageAnalysisEvent).filter(MessageAnalysisEvent.message_analysis_id == analysis_id).order_by(MessageAnalysisEvent.created_at).all()]; return result

@router.post("/message-analysis/text/{analysis_id}/reanalyze")
def reanalyze_message(analysis_id: int, principal: Principal = Depends(get_current_principal), x_admin_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    old = db.get(MessageAnalysisRecord, analysis_id); meta = db.query(MessageAnalysisMetadata).filter(MessageAnalysisMetadata.message_analysis_id == analysis_id).first(); content = db.query(MessageContent).filter(MessageContent.message_analysis_id == analysis_id).first()
    if not old or not meta or not content or not _can_view(meta, principal.user_id, principal.role == "admin" or _admin(x_admin_token), principal.legacy_ids): raise HTTPException(404, "Message analysis not found")
    text = content.content_bytes.decode(errors="replace"); brands=[{"brand_name": row.brand_name, "official_domain": row.official_domain, "verification_status": row.verification_status} for row in db.query(BrandRegistry).all()]; providers=[{"domain": row.domain, "provider_name": row.provider_name, "category": row.category, "disposable": row.disposable} for row in db.query(EmailProviderRegistry).all()]
    result = analyze_message(text, brands=brands, email_providers=providers); digest = hashlib.sha256(text.encode()).hexdigest(); record = MessageAnalysisRecord(input_sha256=digest, source_type="TEXT", result_json=json.dumps(result)); db.add(record); db.flush(); ml=result.get("ml") or {}; owner=meta.user_id
    db.add(MessageContent(message_analysis_id=record.id, content_bytes=content.content_bytes, sha256=digest, content_type="text/plain")); db.add(MessageAnalysisMetadata(message_analysis_id=record.id, user_id=owner, input_type="TEXT", risk_score=result.get("score"), classification=result.get("classification"), ml_prediction=ml.get("prediction"), ml_confidence=ml.get("malicious_probability"), llm_status=(result.get("llm") or {}).get("status") or "UNAVAILABLE", model_version=ml.get("model") or "current", analysis_status="COMPLETED", duplicate_of_id=analysis_id)); db.add(MessageAnalysisEvent(message_analysis_id=record.id, user_id=owner, event_type="reanalyzed", details_json=json.dumps({"previous_analysis_id": analysis_id}))); db.commit(); result["analysis_id"] = record.id; result["reanalysis_of"] = analysis_id; return result

@router.delete("/message-analysis/text/{analysis_id}")
def delete_message_analysis(analysis_id: int, principal: Principal = Depends(get_current_principal), x_admin_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    row=db.get(MessageAnalysisRecord, analysis_id); meta=db.query(MessageAnalysisMetadata).filter(MessageAnalysisMetadata.message_analysis_id == analysis_id).first()
    if not row or not meta or not _can_view(meta, principal.user_id, principal.role == "admin" or _admin(x_admin_token), principal.legacy_ids): raise HTTPException(404, "Message analysis not found")
    review = db.query(MessageReview).filter(MessageReview.message_analysis_id == analysis_id).first()
    if review:
        db.query(MessageReviewFeedback).filter(MessageReviewFeedback.review_id == review.id).delete(synchronize_session=False); db.query(MessageReviewAudit).filter(MessageReviewAudit.review_id == review.id).delete(synchronize_session=False); db.delete(review)
    db.query(MessageAnalysisEvent).filter(MessageAnalysisEvent.message_analysis_id == analysis_id).delete(synchronize_session=False); db.query(MessageContent).filter(MessageContent.message_analysis_id == analysis_id).delete(synchronize_session=False); db.query(ContactRiskAssessment).filter(ContactRiskAssessment.message_analysis_id == analysis_id).delete(synchronize_session=False); db.query(MessageIndicatorResult).filter(MessageIndicatorResult.message_analysis_id == analysis_id).delete(synchronize_session=False); db.query(MessageDomainSpoofingFinding).filter(MessageDomainSpoofingFinding.message_analysis_id == analysis_id).delete(synchronize_session=False)
    if principal.authenticated:
        record_audit_event(db, principal.user_id, "MESSAGE_ANALYSIS_DELETED", "message_analysis", str(analysis_id), {"kind": "TEXT"}, principal.tenant_id)
    db.delete(meta); db.delete(row); db.commit(); return {"deleted": True, "analysis_id": analysis_id}

REVIEW_STATUSES = {"PENDING_REVIEW", "UNDER_REVIEW", "ESCALATED", "CONFIRMED_MALICIOUS", "CONFIRMED_BENIGN", "INCONCLUSIVE", "CLOSED"}
REVIEW_LABELS = {"MALICIOUS", "BENIGN", "INCONCLUSIVE"}

def _message_row(kind: str, analysis_id: int, db: Session):
    normalized = kind.lower()
    if normalized == "text":
        row = db.get(MessageAnalysisRecord, analysis_id)
        meta = db.query(MessageAnalysisMetadata).filter(MessageAnalysisMetadata.message_analysis_id == analysis_id).first()
    elif normalized == "email":
        row = db.get(EmailAnalysis, analysis_id)
        meta = db.query(MessageAnalysisMetadata).filter(MessageAnalysisMetadata.email_analysis_id == analysis_id).first()
    else:
        raise HTTPException(400, "analysis_type must be text or email")
    if not row or not meta:
        raise HTTPException(404, "Message analysis not found")
    return row, meta, normalized

def _review_summary(review: MessageReview) -> dict:
    return {"review_id": review.id, "analysis_id": review.message_analysis_id or review.email_analysis_id, "analysis_type": "TEXT" if review.message_analysis_id else "EML", "status": review.status, "assigned_reviewer": review.assigned_reviewer, "decision_reason": review.decision_reason, "created_by": review.created_by, "updated_by": review.updated_by, "created_at": review.created_at, "updated_at": review.updated_at}

@router.get("/message-analysis/reports/{analysis_type}/{analysis_id}")
def export_message_report(analysis_type: str, analysis_id: int, format: str = Query("json"), principal: Principal = Depends(get_current_principal), x_admin_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    row, meta, normalized = _message_row(analysis_type, analysis_id, db)
    if not _can_view(meta, principal.user_id, principal.role == "admin" or _admin(x_admin_token), principal.legacy_ids):
        raise HTTPException(404, "Message analysis not found")
    report = build_message_report(normalized, row, meta)
    selected = format.lower()
    if selected == "json":
        return report
    if selected == "csv":
        return Response(content=report_csv_bytes(report), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="message-analysis-{analysis_id}.csv"'})
    if selected == "pdf":
        return Response(content=report_pdf_bytes(report), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="message-analysis-{analysis_id}.pdf"'})
    raise HTTPException(400, "format must be json, csv, or pdf")

@router.get("/admin/message-reviews")
def list_message_reviews(status: str | None = Query(None), page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100), principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    query = db.query(MessageReview)
    if status:
        if status not in REVIEW_STATUSES: raise HTTPException(400, "Unknown review status")
        query = query.filter(MessageReview.status == status)
    total = query.count(); reviews = query.order_by(MessageReview.updated_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    items=[]
    for review in reviews:
        analysis_id = review.message_analysis_id or review.email_analysis_id
        meta = db.query(MessageAnalysisMetadata).filter((MessageAnalysisMetadata.message_analysis_id == analysis_id) if review.message_analysis_id else (MessageAnalysisMetadata.email_analysis_id == analysis_id)).first()
        item = _review_summary(review); item["risk_score"] = meta.risk_score if meta else None; item["classification"] = meta.classification if meta else None; item["sender"] = meta.sender if meta else None; item["subject"] = meta.subject if meta else None; items.append(item)
    return {"items": items, "page": page, "page_size": page_size, "total": total, "pages": (total + page_size - 1) // page_size}

@router.get("/admin/message-reviews/{review_id}")
def get_message_review(review_id: int, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    review = db.get(MessageReview, review_id)
    if not review: raise HTTPException(404, "Review not found")
    analysis_id = review.message_analysis_id or review.email_analysis_id; kind = "text" if review.message_analysis_id else "email"; row, meta, _ = _message_row(kind, analysis_id, db)
    return {"review": _review_summary(review), "report": build_message_report(kind, row, meta), "audit": [{"reviewer_id": x.reviewer_id, "action": x.action, "previous_status": x.previous_status, "new_status": x.new_status, "reason": x.reason, "note": x.note, "created_at": x.created_at} for x in db.query(MessageReviewAudit).filter(MessageReviewAudit.review_id == review_id).order_by(MessageReviewAudit.created_at).all()], "feedback": [{"reviewer_id": x.reviewer_id, "label": x.label, "certainty": x.certainty, "evidence": x.evidence, "approval_status": x.approval_status, "created_at": x.created_at} for x in db.query(MessageReviewFeedback).filter(MessageReviewFeedback.review_id == review_id).order_by(MessageReviewFeedback.created_at).all()]}

@router.post("/admin/message-reviews/open/{analysis_type}/{analysis_id}")
def create_message_review(analysis_type: str, analysis_id: int, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row, meta, normalized = _message_row(analysis_type, analysis_id, db)
    review = db.query(MessageReview).filter((MessageReview.message_analysis_id == analysis_id) if normalized == "text" else (MessageReview.email_analysis_id == analysis_id)).first()
    if review: return _review_summary(review)
    actor = principal.external_subject or principal.user_id; review = MessageReview(message_analysis_id=analysis_id if normalized == "text" else None, email_analysis_id=analysis_id if normalized == "email" else None, created_by=actor, updated_by=actor); db.add(review); db.flush(); db.add(MessageReviewAudit(review_id=review.id, reviewer_id=actor, action="created", new_status=review.status, note="Review opened")); db.commit(); db.refresh(review); return _review_summary(review)

@router.post("/admin/message-reviews/{review_id}/status")
def update_message_review_status(review_id: int, payload: dict, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    review = db.get(MessageReview, review_id)
    if not review: raise HTTPException(404, "Review not found")
    status = str(payload.get("status") or "").upper()
    if status not in REVIEW_STATUSES: raise HTTPException(400, "Invalid review status")
    if review.status in {"CONFIRMED_MALICIOUS", "CONFIRMED_BENIGN", "CLOSED"} and status != "CLOSED": raise HTTPException(409, "Finalized review cannot be reopened")
    actor = principal.external_subject or principal.user_id; previous = review.status; review.status = status; review.decision_reason = str(payload.get("reason") or "")[:4000] or None; review.updated_by = actor; review.updated_at = datetime.now(timezone.utc); db.add(MessageReviewAudit(review_id=review.id, reviewer_id=actor, action="status_changed", previous_status=previous, new_status=status, reason=review.decision_reason, note=str(payload.get("note") or "")[:4000] or None)); db.commit(); return _review_summary(review)

@router.post("/admin/message-reviews/{review_id}/assign")
def assign_message_review(review_id: int, payload: dict, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    review = db.get(MessageReview, review_id)
    if not review: raise HTTPException(404, "Review not found")
    assigned = str(payload.get("reviewer_id") or "").strip()
    if not assigned or len(assigned) > 512: raise HTTPException(400, "reviewer_id is required")
    actor = principal.external_subject or principal.user_id; review.assigned_reviewer = assigned; review.updated_by = actor; review.updated_at = datetime.now(timezone.utc); db.add(MessageReviewAudit(review_id=review.id, reviewer_id=actor, action="assigned", note=f"Assigned to {assigned}")); db.commit(); return _review_summary(review)

@router.post("/admin/message-reviews/{review_id}/feedback")
def add_message_review_feedback(review_id: int, payload: dict, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    review = db.get(MessageReview, review_id)
    if not review: raise HTTPException(404, "Review not found")
    label = str(payload.get("label") or "").upper()
    if label not in REVIEW_LABELS: raise HTTPException(400, "label must be MALICIOUS, BENIGN, or INCONCLUSIVE")
    actor = principal.external_subject or principal.user_id; evidence = str(payload.get("evidence") or "")[:8000]; db.add(MessageReviewFeedback(review_id=review.id, reviewer_id=actor, label=label, certainty=str(payload.get("certainty") or "")[:30] or None, evidence=evidence or None, approval_status="PENDING_VALIDATION")); db.add(MessageReviewAudit(review_id=review.id, reviewer_id=actor, action="feedback_submitted", note="Feedback queued for dataset validation")); db.commit(); return {"review_id": review.id, "label": label, "approval_status": "PENDING_VALIDATION"}

@router.post("/admin/message-reviews/feedback/{feedback_id}/approve")
def approve_message_review_feedback(feedback_id: int, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    feedback=db.get(MessageReviewFeedback,feedback_id)
    if not feedback: raise HTTPException(404,"Feedback not found")
    if feedback.approval_status != "PENDING_VALIDATION": raise HTTPException(409,"Feedback is already finalized")
    feedback.approval_status="APPROVED"; actor=principal.external_subject or principal.user_id; db.add(MessageReviewAudit(review_id=feedback.review_id,reviewer_id=actor,action="feedback_approved",note="Feedback approved for future training")); db.commit(); return {"feedback_id":feedback.id,"approval_status":feedback.approval_status}

@router.get("/ml/status")
def model_status():
    return ml_status()

@router.get("/ml/registry")
def ml_registry(principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    datasets=db.query(MLDatasetVersion).order_by(MLDatasetVersion.created_at.desc()).limit(100).all()
    models=db.query(MLModelVersion).order_by(MLModelVersion.created_at.desc()).limit(100).all()
    deployments=db.query(MLDeploymentHistory).order_by(MLDeploymentHistory.created_at.desc()).limit(100).all()
    runs=db.query(MLTrainingRun).order_by(MLTrainingRun.created_at.desc()).limit(100).all()
    return {"production": ml_status(), "datasets":[{"id":x.id,"dataset_id":x.dataset_id,"version":x.version,"source":x.source,"checksum":x.checksum,"record_count":x.record_count,"class_distribution":json.loads(x.class_distribution_json or "{}"),"quality":json.loads(x.quality_json or "{}"),"preprocessing_version":x.preprocessing_version,"validation_status":x.validation_status,"approval_status":x.approval_status,"created_at":x.created_at} for x in datasets], "models":[{"id":x.id,"model_id":x.model_id,"version":x.version,"name":x.name,"algorithm":x.algorithm,"dataset_version_id":x.dataset_version_id,"artifact_location":x.artifact_location,"artifact_checksum":x.artifact_checksum,"metrics":json.loads(x.metrics_json or "{}"),"status":x.status,"approval_by":x.approval_by,"approved_at":x.approved_at,"created_at":x.created_at} for x in models], "deployments":[{"id":x.id,"model_version_id":x.model_version_id,"previous_model_version_id":x.previous_model_version_id,"action":x.action,"actor":x.actor,"created_at":x.created_at,"reason":x.reason} for x in deployments], "training_runs":[{"id":x.id,"dataset_version_id":x.dataset_version_id,"model_version_id":x.model_version_id,"status":x.status,"metrics":json.loads(x.metrics_json or "{}"),"error":x.error,"created_at":x.created_at} for x in runs]}

@router.post("/ml/retraining")
def start_ml_retraining(payload: dict, background_tasks: BackgroundTasks, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    dataset_id=int(payload.get("dataset_version_id") or 0); dataset=db.get(MLDatasetVersion,dataset_id)
    if not dataset: raise HTTPException(404,"Dataset version not found")
    if dataset.approval_status != "APPROVED" or dataset.validation_status != "VALID": raise HTTPException(409,"Only approved and valid datasets may be trained")
    active=db.query(MLTrainingRun).filter(MLTrainingRun.status.in_(["PENDING","RUNNING"])).first()
    if active: raise HTTPException(409,"A retraining job is already active")
    actor=principal.external_subject or principal.user_id; run=MLTrainingRun(dataset_version_id=dataset.id,status="PENDING",created_by=actor); db.add(run); db.flush(); task_id="ml-retrain-"+secrets.token_hex(12); db.add(BackgroundTaskRun(task_id=task_id,task_name="retrain_model",status="PENDING")); db.commit(); db.refresh(run)
    if worker_tasks.celery_app: worker_tasks.retrain_model.delay(task_id,run.id)
    else: submit_local_retraining(task_id,run.id)
    return {"task_id":task_id,"training_run_id":run.id,"status":"PENDING","dataset_version_id":dataset.id}

@router.get("/ml/training/{training_run_id}")
def ml_training_status(training_run_id: int, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    run=db.get(MLTrainingRun,training_run_id)
    if not run: raise HTTPException(404,"Training run not found")
    return {"id":run.id,"dataset_version_id":run.dataset_version_id,"model_version_id":run.model_version_id,"status":run.status,"metrics":json.loads(run.metrics_json or "{}"),"error":run.error,"started_at":run.started_at,"completed_at":run.completed_at}

@router.post("/ml/datasets/register")
def register_ml_dataset(payload: dict, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    try: quality=validate_dataset(str(payload.get("path") or ""), int(payload.get("max_rows") or 500000))
    except (ValueError, FileNotFoundError) as exc: raise HTTPException(400, str(exc)) from exc
    dataset_id=str(payload.get("dataset_id") or Path(quality["path"]).stem)[:160]; version=str(payload.get("version") or "v1")[:80]; actor=principal.external_subject or principal.user_id
    if db.query(MLDatasetVersion).filter(MLDatasetVersion.dataset_id == dataset_id, MLDatasetVersion.version == version).first(): raise HTTPException(409, "Dataset version already registered")
    row=MLDatasetVersion(dataset_id=dataset_id,version=version,source=quality["path"][:2000],checksum=quality["checksum"],record_count=quality["record_count"],class_distribution_json=json.dumps(quality["class_distribution"]),quality_json=json.dumps(quality["quality"]),preprocessing_version=str(payload.get("preprocessing_version") or "message-text-v1"),validation_status=quality["validation_status"],approval_status="PENDING",created_by=actor); db.add(row); db.commit(); db.refresh(row); return {"id":row.id,"dataset_id":dataset_id,"version":version,"validation_status":row.validation_status,"approval_status":row.approval_status,"quality":quality}

@router.post("/ml/datasets/{dataset_id}/approve")
def approve_ml_dataset(dataset_id: int, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row=db.get(MLDatasetVersion,dataset_id)
    if not row: raise HTTPException(404,"Dataset version not found")
    if row.validation_status != "VALID": raise HTTPException(409,"Dataset must pass validation before approval")
    row.approval_status="APPROVED"; db.commit(); return {"id":row.id,"approval_status":row.approval_status}

@router.post("/ml/models/register")
def register_ml_model(payload: dict, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    try: info=artifact_metadata(str(payload.get("artifact_location") or ""))
    except (ValueError, FileNotFoundError) as exc: raise HTTPException(400,str(exc)) from exc
    dataset_id=payload.get("dataset_version_id"); dataset=db.get(MLDatasetVersion,int(dataset_id)) if dataset_id else None
    if dataset_id and not dataset: raise HTTPException(404,"Dataset version not found")
    if dataset and dataset.approval_status != "APPROVED": raise HTTPException(409,"Dataset version must be approved")
    model_id=str(payload.get("model_id") or "tfidf-logistic-message-classifier")[:160]; version=str(payload.get("version") or info.get("model_version") or "candidate-1")[:80]; actor=principal.external_subject or principal.user_id
    if db.query(MLModelVersion).filter(MLModelVersion.model_id == model_id, MLModelVersion.version == version).first(): raise HTTPException(409,"Model version already registered")
    row=MLModelVersion(model_id=model_id,version=version,name=str(payload.get("name") or info.get("name") or model_id)[:255],algorithm=str(payload.get("algorithm") or "TF-IDF + Logistic Regression")[:120],dataset_version_id=dataset.id if dataset else None,artifact_location=info["path"],artifact_checksum=info["checksum"],feature_config_json=json.dumps(info.get("feature_config",{})),hyperparameters_json=json.dumps(info.get("hyperparameters",{})),metrics_json=json.dumps(info.get("metrics",{})),status="CANDIDATE",created_by=actor); db.add(row); db.commit(); db.refresh(row); return {"id":row.id,"model_id":model_id,"version":version,"artifact_checksum":row.artifact_checksum,"status":row.status,"inspection":info}

@router.post("/ml/models/{model_id}/approve")
def approve_ml_model(model_id: int, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row=db.get(MLModelVersion,model_id)
    if not row: raise HTTPException(404,"Model version not found")
    try: info=artifact_metadata(row.artifact_location)
    except (ValueError, FileNotFoundError) as exc: raise HTTPException(400,str(exc)) from exc
    if info["checksum"] != row.artifact_checksum: raise HTTPException(409,"Artifact checksum changed")
    row.status="APPROVED"; row.approval_by=principal.external_subject or principal.user_id; row.approved_at=datetime.now(timezone.utc); db.commit(); return {"id":row.id,"status":row.status,"approved_at":row.approved_at}

@router.post("/ml/models/{model_id}/deploy")
def deploy_ml_model(model_id: int, payload: dict | None = None, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row=db.get(MLModelVersion,model_id)
    if not row: raise HTTPException(404,"Model version not found")
    if row.status != "APPROVED": raise HTTPException(409,"Only approved models may be deployed")
    try: info=artifact_metadata(row.artifact_location)
    except (ValueError, FileNotFoundError) as exc: raise HTTPException(400,str(exc)) from exc
    if info["checksum"] != row.artifact_checksum: raise HTTPException(409,"Artifact checksum changed")
    current=db.query(MLModelVersion).filter(MLModelVersion.status == "PRODUCTION").first(); previous=current.id if current else None
    if current and current.id != row.id: current.status="ARCHIVED"
    row.status="PRODUCTION"; MODEL_ROOT.mkdir(parents=True,exist_ok=True); POINTER.write_text(json.dumps({"model_version_id":row.id,"artifact_location":row.artifact_location,"checksum":row.artifact_checksum}),encoding="utf-8"); actor=principal.external_subject or principal.user_id; db.add(MLDeploymentHistory(model_version_id=row.id,previous_model_version_id=previous,action="DEPLOY",actor=actor,artifact_checksum=row.artifact_checksum,reason=str((payload or {}).get("reason") or "Approved deployment"))); db.commit(); return {"deployed":True,"model_version_id":row.id,"previous_model_version_id":previous}

@router.post("/ml/models/{model_id}/rollback")
def rollback_ml_model(model_id: int, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    target=db.get(MLModelVersion,model_id)
    if not target: raise HTTPException(404,"Model version not found")
    try: info=artifact_metadata(target.artifact_location)
    except (ValueError, FileNotFoundError) as exc: raise HTTPException(400,str(exc)) from exc
    if info["checksum"] != target.artifact_checksum: raise HTTPException(409,"Artifact checksum changed")
    current=db.query(MLModelVersion).filter(MLModelVersion.status == "PRODUCTION").first()
    if current and current.id != target.id: current.status="ARCHIVED"
    target.status="PRODUCTION"; MODEL_ROOT.mkdir(parents=True,exist_ok=True); POINTER.write_text(json.dumps({"model_version_id":target.id,"artifact_location":target.artifact_location,"checksum":target.artifact_checksum}),encoding="utf-8"); actor=principal.external_subject or principal.user_id; db.add(MLDeploymentHistory(model_version_id=target.id,previous_model_version_id=current.id if current else None,action="ROLLBACK",actor=actor,artifact_checksum=target.artifact_checksum,reason="Controlled rollback")); db.commit(); return {"rolled_back":True,"model_version_id":target.id}

@router.get("/llm/status")
def llm_status():
    return configuration_status()

@router.post("/llm/verify")
def llm_verify():
    return verify_llm_connection()

@router.get("/correlation")
def correlation(db: Session = Depends(get_db)):
    return correlate(db.query(Scan).all(), db.query(CommunityReport).all())

@router.post("/correlation/infrastructure")
def infrastructure_correlation(db: Session = Depends(get_db)):
    """Run Phase 4.2 shared-indicator correlation over persisted evidence."""
    return run_infrastructure_correlation(db)

@router.post("/correlation/messages")
def message_correlation(db: Session = Depends(get_db)):
    """Correlate persisted text and uploaded-email analyses by explainable similarity."""
    return correlate_messages(db)

@router.get("/correlation/messages")
def message_correlation_history(analysis_type: str | None = Query(None), analysis_id: str | None = Query(None), db: Session = Depends(get_db)):
    if bool(analysis_type) != bool(analysis_id):
        raise HTTPException(400, "analysis_type and analysis_id must be supplied together")
    return {"items": message_similarity_history(db, analysis_type, analysis_id)}

@router.post("/correlation/campaigns/discover")
def discover_campaigns(principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    return group_incidents(db)

@router.get("/correlation/campaigns")
def get_campaigns(db: Session = Depends(get_db)):
    return {"items": list_campaigns(db)}

@router.post("/correlation/campaigns/{campaign_id}/status")
def change_campaign_status(campaign_id: int, payload: dict, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    try:
        row = set_campaign_status(db, campaign_id, str(payload.get("status") or ""), principal.external_subject or principal.user_id, payload)
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    return {"id": row.id, "status": row.status, "confidence": row.confidence}

@router.post("/correlation/campaigns/{campaign_id}/incidents/{incident_id}/reject")
def reject_campaign_relationship(campaign_id: int, incident_id: int, payload: dict | None = None, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    try:
        row = reject_campaign_incident(db, campaign_id, incident_id, principal.external_subject or principal.user_id, str((payload or {}).get("reason") or "")[:2000])
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    return {"campaign_id": row.campaign_id, "incident_id": row.incident_id, "association_status": row.association_status}

@router.post("/correlation/campaigns/{campaign_id}/merge")
def merge_campaign(campaign_id: int, payload: dict, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    try:
        row = merge_campaigns(db, campaign_id, int(payload.get("source_campaign_id")), principal.external_subject or principal.user_id, str(payload.get("reason") or "")[:2000])
    except (ValueError, TypeError) as exc: raise HTTPException(400, str(exc)) from exc
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    return {"id": row.id, "status": row.status, "confidence": row.confidence}

@router.post("/correlation/campaigns/{campaign_id}/split")
def split_campaign_route(campaign_id: int, payload: dict, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    try:
        row = split_campaign(db, campaign_id, payload.get("incident_ids") or [], principal.external_subject or principal.user_id, str(payload.get("reason") or "")[:2000])
    except (ValueError, TypeError) as exc: raise HTTPException(400, str(exc)) from exc
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    return {"id": row.id, "campaign_key": row.campaign_key, "status": row.status}

@router.get("/correlation/campaigns/{campaign_id}/graph")
def campaign_graph(campaign_id: int, max_nodes: int = Query(500, ge=10, le=2000), principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: return get_campaign_graph(db, campaign_id, max_nodes)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc

@router.get("/correlation/incidents/{incident_id}/graph")
def incident_graph(incident_id: int, max_nodes: int = Query(300, ge=10, le=1000), principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: return get_incident_graph(db, incident_id, max_nodes)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc

@router.get("/correlation/campaigns/{campaign_id}/timeline")
def campaign_timeline_route(campaign_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: return campaign_timeline(db, campaign_id)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc

@router.get("/correlation/incidents/{incident_id}/timeline")
def incident_timeline_route(incident_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: return incident_timeline(db, incident_id)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc

@router.post("/correlation/campaigns/{campaign_id}/summaries")
def generate_campaign_summary_route(campaign_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: return generate_campaign_summary(db, campaign_id)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc

@router.get("/correlation/campaigns/{campaign_id}/summaries")
def campaign_summary_history_route(campaign_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    if not db.get(ThreatCampaign, campaign_id): raise HTTPException(404, "campaign not found")
    return {"items": summary_history(db, campaign_id)}

@router.get("/reports/{report_id}/commitment")
def report_commitment(report_id: int, db: Session = Depends(get_db)):
    row=db.get(CommunityReport, report_id)
    if not row: raise HTTPException(404, "Report not found")
    return commitment({"id":row.id,"url":row.url,"reason":row.reason,"details":row.details,"status":row.status,"created_at":row.created_at})

# Phase 6.1 decentralized threat-intelligence report architecture. These
# endpoints create and verify local commitments only; they do not submit to a
# blockchain and never expose private keys or confidential report data publicly.
@router.post("/threat-intelligence/reports")
def create_threat_intelligence_report(payload: dict, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try:
        row = create_threat_report(db, principal.user_id, payload)
    except ValueError as exc:
        db.rollback(); raise HTTPException(400, str(exc)) from exc
    return serialize_threat_report(db, row)

@router.get("/threat-intelligence/reports")
def list_threat_intelligence_reports(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    rows = db.query(ThreatIntelligenceReport).filter(ThreatIntelligenceReport.owner_user_id.in_((principal.user_id, *principal.legacy_ids))).order_by(ThreatIntelligenceReport.updated_at.desc()).offset(offset).limit(limit).all()
    return {"items": [serialize_threat_report(db, row, include_revisions=False) for row in rows], "offset": offset, "limit": limit}

@router.get("/threat-intelligence/reports/{report_id}")
def get_threat_intelligence_report(report_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try:
        row = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    return serialize_threat_report(db, row)

@router.post("/threat-intelligence/reports/{report_id}/revisions")
def create_threat_intelligence_revision(report_id: int, payload: dict, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try:
        report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
        revision = add_threat_revision(db, report, principal, payload)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    except ValueError as exc: db.rollback(); raise HTTPException(400, str(exc)) from exc
    return {"report": serialize_threat_report(db, report), "revision_id": revision.id}

@router.get("/threat-intelligence/reports/{report_id}/revisions/{revision_id}")
def get_threat_intelligence_revision(report_id: int, revision_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    revision = db.query(ReportRevision).filter_by(id=revision_id, report_id=report.id).first()
    if not revision: raise HTTPException(404, "revision not found")
    return {"report": {"id": report.id, "report_key": report.report_key, "title": report.title}, "revision": serialize_threat_revision(db, revision), "canonical_payload": revision.canonical_payload}

@router.post("/threat-intelligence/reports/{report_id}/revisions/{revision_id}/commitment/verify")
def verify_threat_intelligence_commitment(report_id: int, revision_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try:
        report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
        return verify_local_commitment(db, report, revision_id, principal.user_id)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc

@router.get("/threat-intelligence/reports/{report_id}/provenance")
def get_threat_intelligence_provenance(report_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    return {"items": threat_provenance(db, report.id)}

@router.get("/threat-intelligence/reports/{report_id}/validation")
def get_threat_intelligence_validation_history(report_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    return {"items": threat_validation_history(db, report.id)}

@router.get("/threat-intelligence/reports/{report_id}/blockchain")
def get_threat_intelligence_blockchain_metadata(report_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    return {"items": threat_blockchain_metadata(db, report.id), "on_chain_status": "NOT_SUBMITTED"}

@router.get("/threat-intelligence/ledger/verify")
def verify_threat_intelligence_ledger(principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    return ledger_checkpoint(db)

@router.post("/threat-intelligence/reports/{report_id}/revisions/{revision_id}/blockchain/verify-receipt")
def verify_threat_intelligence_blockchain_receipt(report_id: int, revision_id: int, payload: dict, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    try: report = get_owned_threat_report(db, report_id, principal, True)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    revision = db.query(ReportRevision).filter_by(id=revision_id, report_id=report.id).first()
    if not revision: raise HTTPException(404, "revision not found")
    try: return EVMBlockchainAdapter().verify_existing_transaction(db, report, revision, payload.get("transaction_hash"))
    except (ValueError, httpx.HTTPError) as exc:
        db.rollback(); raise HTTPException(502, "blockchain receipt verification failed") from exc

@router.get("/threat-intelligence/blockchain/status")
def threat_intelligence_blockchain_status(principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only)):
    return blockchain_configuration_status()

@router.post("/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence")
async def add_threat_intelligence_evidence(
    report_id: int,
    revision_id: int,
    file: UploadFile = File(...),
    reference_type: str = Query("SUPPORTING", min_length=1, max_length=80),
    description: str = Query("", max_length=4000),
    access_classification: str = Query("PRIVATE"),
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    try:
        report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    revision = db.query(ReportRevision).filter_by(id=revision_id, report_id=report.id).first()
    if not revision:
        raise HTTPException(404, "revision not found")
    data = await file.read(int(settings.evidence_max_bytes) + 1)
    try:
        obj, ref, manifest, ledger = upload_evidence(
            db,
            report,
            revision,
            principal.user_id,
            data,
            file.filename,
            file.content_type,
            reference_type,
            description,
            access_classification,
        )
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    return {
        "evidence": serialize_evidence(db, obj, principal, principal.role == "admin"),
        "reference": {"id": ref.id, "reference_type": ref.reference_type, "description": ref.description},
        "manifest": {"id": manifest.id, "version": manifest.version, "manifest_hash": manifest.manifest_hash},
        "ledger_event_id": ledger.id,
    }

@router.get("/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence")
def list_threat_intelligence_evidence(report_id: int, revision_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try:
        report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    revision = db.query(ReportRevision).filter_by(id=revision_id, report_id=report.id).first()
    if not revision:
        raise HTTPException(404, "revision not found")
    rows = db.query(EvidenceObject).filter_by(revision_id=revision.id).order_by(EvidenceObject.id.asc()).all()
    return {"items": [serialize_evidence(db, row, principal, principal.role == "admin") for row in rows], "manifests": manifest_details(db, report, revision.id, principal.user_id)}

@router.get("/threat-intelligence/evidence/{evidence_id}")
def get_threat_intelligence_evidence(evidence_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(EvidenceObject, evidence_id)
    if not row:
        raise HTTPException(404, "evidence not found")
    if not can_access_evidence(row, principal, principal.role == "admin"):
        raise HTTPException(403, "evidence access denied")
    return serialize_evidence(db, row, principal, principal.role == "admin")

@router.get("/threat-intelligence/evidence/{evidence_id}/content")
def download_threat_intelligence_evidence(evidence_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(EvidenceObject, evidence_id)
    if not row:
        raise HTTPException(404, "evidence not found")
    if not can_access_evidence(row, principal, principal.role == "admin"):
        raise HTTPException(403, "evidence access denied")
    integrity, content = read_verified_evidence(db, row, principal.user_id)
    if integrity["status"] != "VERIFIED":
        code = 404 if integrity["status"] == "MISSING" else 409
        raise HTTPException(code, integrity["status"])
    return Response(content=content, media_type=row.content_type or "application/octet-stream", headers={"Content-Disposition": "attachment; filename=evidence"})

@router.post("/threat-intelligence/evidence/{evidence_id}/verify")
def verify_threat_intelligence_evidence(evidence_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(EvidenceObject, evidence_id)
    if not row:
        raise HTTPException(404, "evidence not found")
    if not can_access_evidence(row, principal, principal.role == "admin"):
        return {"status": "ACCESS_DENIED", "evidence_id": evidence_id}
    return verify_evidence(db, row, principal.user_id)

@router.post("/threat-intelligence/evidence/{evidence_id}/ipfs")
def pin_threat_intelligence_evidence(evidence_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    row = db.get(EvidenceObject, evidence_id)
    if not row:
        raise HTTPException(404, "evidence not found")
    if not can_access_evidence(row, principal, principal.role == "admin"):
        raise HTTPException(403, "evidence access denied")
    return pin_to_ipfs(db, row, principal.user_id)

@router.post("/admin/threat-intelligence/evidence/retention/cleanup")
def cleanup_threat_intelligence_evidence(principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    return cleanup_expired(db, principal.user_id)

@router.get("/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence/manifests")
def list_threat_intelligence_manifests(report_id: int, revision_id: int, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try:
        report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
        return {"items": manifest_details(db, report, revision_id, principal.user_id)}
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc

@router.post("/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence/manifests/verify")
def verify_threat_intelligence_manifest(report_id: int, revision_id: int, version: int | None = None, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try:
        report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
        return verify_manifest(db, report, revision_id, version)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc

@router.post("/threat-intelligence/wallet/challenges")
def create_wallet_ownership_challenge(payload: dict, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: return ownership_challenge(db, principal, payload.get("address"), str(payload.get("action") or "WALLET_OWNERSHIP"))
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc

@router.post("/threat-intelligence/wallet/challenges/{challenge_id}/verify")
def verify_wallet_ownership_challenge(challenge_id: str, payload: dict, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: return verify_ownership(db, principal, challenge_id, payload.get("address"), payload.get("signature"), payload.get("chain_id"))
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    except (ValueError, TypeError) as exc: db.rollback(); raise HTTPException(400, str(exc)) from exc

@router.post("/threat-intelligence/reports/{report_id}/revisions/{revision_id}/signature/challenge")
def create_report_signature_challenge(report_id: int, revision_id: int, payload: dict, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: report = get_owned_threat_report(db, report_id, principal, principal.role == "admin")
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    revision=db.query(ReportRevision).filter_by(id=revision_id,report_id=report.id).first()
    if not revision: raise HTTPException(404,"revision not found")
    try: return signature_challenge(db, principal, report, revision, payload.get("address"))
    except (ValueError, PermissionError) as exc: raise HTTPException(403, str(exc)) from exc

@router.post("/threat-intelligence/signatures/{challenge_id}/verify")
def verify_report_signature(challenge_id: str, payload: dict, principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    try: return verify_signature(db, principal, challenge_id, payload.get("signature"))
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    except (ValueError, PermissionError) as exc: db.rollback(); raise HTTPException(400, str(exc)) from exc

@router.post("/threat-intelligence/reports/{report_id}/revisions/{revision_id}/blockchain/submit")
def submit_threat_intelligence_blockchain_revision(report_id: int, revision_id: int, payload: dict | None = None, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    try: report = get_owned_threat_report(db, report_id, principal, True)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    revision = db.query(ReportRevision).filter_by(id=revision_id, report_id=report.id).first()
    if not revision: raise HTTPException(404, "revision not found")
    try:
        adapter = EVMBlockchainAdapter()
        return adapter.submit_revision(db, report, revision, (payload or {}).get("metadata") or "")
    except Exception as exc:
        db.rollback(); raise HTTPException(503, "EVM blockchain submission unavailable") from exc

@router.get("/threat-intelligence/blockchain/transactions/{transaction_id}")
def refresh_threat_intelligence_transaction(transaction_id: int, principal: Principal = Depends(get_current_principal), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    try:
        adapter = EVMBlockchainAdapter()
        return adapter.refresh_transaction(db, transaction_id)
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    except Exception as exc:
        db.rollback(); raise HTTPException(503, "EVM transaction status unavailable") from exc

@router.post("/reports/{report_id}/moderate")
def moderate_report(report_id: int, status: str, db: Session = Depends(get_db), _: None = Depends(admin_only)):
    if status not in {"pending","verified","rejected"}: raise HTTPException(400, "Invalid report status")
    row=db.get(CommunityReport, report_id)
    if not row: raise HTTPException(404, "Report not found")
    row.status=status; db.commit(); return {"id":row.id,"status":row.status}
