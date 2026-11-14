"""Phase 6.6: Centralized evidence provenance for findings.

Provides deterministic canonical hashing, persistence, and verification for every finding.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from backend.app.models.models import FindingEvidenceProvenance, Scan


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json_serializable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(k): _json_serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_serializable(v) for v in value]
    return value


def canonicalize_evidence(payload: Any) -> tuple[str, str]:
    """Return deterministic SHA-256 content hash and canonical JSON string."""
    serializable = _json_serializable(payload if payload is not None else {})
    canonical_json = json.dumps(
        serializable,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    content_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return content_hash, canonical_json


def verify_content_hash(stored_hash: str, payload_json: str) -> dict[str, Any]:
    """Verify that stored content hash matches the canonical hash of the payload."""
    try:
        data = json.loads(payload_json or "{}")
    except Exception:
        data = payload_json
    computed_hash, _ = canonicalize_evidence(data)
    matches = (computed_hash.lower() == str(stored_hash or "").strip().lower())
    return {
        "verified": matches,
        "matches": matches,
        "hash_algorithm": "SHA-256",
        "stored_hash": stored_hash,
        "computed_hash": computed_hash,
        "verified_at": _now().isoformat(),
    }


def serialize_provenance(item: FindingEvidenceProvenance) -> dict[str, Any]:
    evidence_payload = {}
    try:
        evidence_payload = json.loads(item.evidence_payload_json or "{}")
    except Exception:
        pass

    return {
        "id": item.id,
        "finding_id": item.finding_id,
        "source_provider": item.source_provider,
        "source_type": item.source_type,
        "observed_at": item.observed_at.isoformat() if item.observed_at else None,
        "checked_at": item.checked_at.isoformat() if item.checked_at else None,
        "confidence": item.confidence,
        "provider_status": item.provider_status,
        "evidence_reference": item.evidence_reference,
        "content_hash": item.content_hash,
        "scan_job_id": item.scan_job_id,
        "scan_id": item.scan_id,
        "report_id": item.report_id,
        "revision_id": item.revision_id,
        "title": item.title or item.finding_id,
        "explanation": item.explanation or item.why_it_exists,
        "why_it_exists": item.why_it_exists or item.explanation,
        "severity": item.severity or "INFO",
        "is_current": bool(item.is_current),
        "evidence": evidence_payload,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def record_finding_provenance(
    db,
    *,
    finding_id: str,
    source_provider: str,
    source_type: str,
    observed_at: datetime | None = None,
    checked_at: datetime | None = None,
    confidence: str = "UNKNOWN",
    provider_status: str = "UNKNOWN",
    evidence_reference: str | None = None,
    evidence_payload: Any = None,
    scan_job_id: str | None = None,
    scan_id: int | None = None,
    report_id: int | None = None,
    revision_id: int | None = None,
    title: str = "",
    why_it_exists: str = "",
    explanation: str = "",
    severity: str = "INFO",
    is_current: bool = True,
) -> FindingEvidenceProvenance:
    observed = observed_at or _now()
    checked = checked_at or _now()
    content_hash, canonical_json = canonicalize_evidence(evidence_payload)

    row = FindingEvidenceProvenance(
        finding_id=finding_id[:120],
        source_provider=source_provider[:120],
        source_type=source_type[:80],
        observed_at=observed,
        checked_at=checked,
        confidence=confidence[:30].upper(),
        provider_status=provider_status[:40].upper(),
        evidence_reference=(evidence_reference or "")[:1024],
        content_hash=content_hash,
        scan_job_id=(scan_job_id or "")[:120] if scan_job_id else None,
        scan_id=scan_id,
        report_id=report_id,
        revision_id=revision_id,
        title=(title or finding_id)[:255],
        explanation=explanation or why_it_exists,
        why_it_exists=why_it_exists or explanation,
        severity=severity[:30].upper(),
        is_current=is_current,
        evidence_payload_json=canonical_json,
        created_at=_now(),
    )
    db.add(row)
    db.flush()
    return row


def extract_and_persist_provenance(
    db,
    scan_id: int | None,
    result: dict[str, Any],
    scan_job_id: str | None = None,
    report_id: int | None = None,
    revision_id: int | None = None,
) -> list[dict[str, Any]]:
    """Extract all findings from scan result, persist provenance records, and return serialized list."""
    now = _now()
    persisted_rows: list[FindingEvidenceProvenance] = []
    job_ref = scan_job_id or (f"scan-{scan_id}" if scan_id else "scan-ad-hoc")
    idx = 0

    # 1. External Threat Intelligence findings
    threat_intel = result.get("threat_intelligence") or {}
    threat_findings = threat_intel.get("findings") or []
    for item in threat_findings:
        idx += 1
        provider = item.get("provider") or "External Threat Provider"
        threat_type = item.get("threat_type") or item.get("state") or "Malicious indicator"
        fid = f"fnd-threat-{scan_id or 'adhoc'}-{idx}"
        ref = item.get("reference") or str(item.get("evidence", {}).get("indicator") or item.get("evidence", {}).get("url") or "")
        why = f"{provider} identified active threat: {threat_type}"
        row = record_finding_provenance(
            db,
            finding_id=fid,
            source_provider=provider,
            source_type="external_threat_api",
            observed_at=now,
            checked_at=now,
            confidence="HIGH" if item.get("state") == "confirmed" else "MEDIUM",
            provider_status="QUERIED",
            evidence_reference=ref or f"{provider}:{threat_type}",
            evidence_payload=item.get("evidence") or item,
            scan_job_id=job_ref,
            scan_id=scan_id,
            report_id=report_id,
            revision_id=revision_id,
            title=f"{provider}: {threat_type}",
            why_it_exists=why,
            severity="CRITICAL" if "malware" in str(threat_type).lower() or "phish" in str(threat_type).lower() else "HIGH",
            is_current=True,
        )
        persisted_rows.append(row)

    # 2. External Threat Intelligence providers (unavailable / not configured / queried visibility)
    for provider_item in threat_intel.get("providers") or []:
        status_val = str(provider_item.get("status") or "unknown").lower()
        if status_val in {"unavailable", "not_configured", "rate_limited", "provider_error"}:
            idx += 1
            p_name = provider_item.get("provider") or "Unknown Provider"
            fid = f"fnd-provider-status-{scan_id or 'adhoc'}-{idx}"
            why = f"Provider {p_name} is {status_val.upper()}: {provider_item.get('reason') or 'No connection established'}. Unavailable providers are never assumed clean."
            row = record_finding_provenance(
                db,
                finding_id=fid,
                source_provider=p_name,
                source_type="threat_provider_probe",
                observed_at=now,
                checked_at=now,
                confidence="LOW",
                provider_status=status_val.upper(),
                evidence_reference=provider_item.get("source") or provider_item.get("reason"),
                evidence_payload=provider_item,
                scan_job_id=job_ref,
                scan_id=scan_id,
                report_id=report_id,
                revision_id=revision_id,
                title=f"{p_name}: {status_val.upper()}",
                why_it_exists=why,
                severity="INFO",
                is_current=True,
            )
            persisted_rows.append(row)

    # 3. Phishing Heuristics & Signals
    phishing = result.get("phishing") or {}
    for item in phishing.get("evidence") or []:
        idx += 1
        msg = item.get("message") or "Phishing signal detected"
        sev = str(item.get("severity") or "MEDIUM").upper()
        fid = f"fnd-phish-{scan_id or 'adhoc'}-{idx}"
        why = f"Heuristic analysis detected structural deception signal: {msg}"
        row = record_finding_provenance(
            db,
            finding_id=fid,
            source_provider="Phishing Heuristic Engine",
            source_type="heuristic_engine",
            observed_at=now,
            checked_at=now,
            confidence="HIGH" if sev == "HIGH" else "MEDIUM",
            provider_status="AVAILABLE",
            evidence_reference=result.get("domain") or result.get("url"),
            evidence_payload=item,
            scan_job_id=job_ref,
            scan_id=scan_id,
            report_id=report_id,
            revision_id=revision_id,
            title=f"Phishing Signal: {msg}",
            why_it_exists=why,
            severity=sev,
            is_current=True,
        )
        persisted_rows.append(row)

    # 4. Certificate & Cryptographic Risk
    cert_data = result.get("certificate") or {}
    cert_risk = cert_data.get("risk") or {}
    for item in cert_risk.get("findings") or []:
        idx += 1
        ftype = item.get("finding_type") or "Certificate Anomaly"
        fid = f"fnd-cert-{scan_id or 'adhoc'}-{idx}"
        why = item.get("explanation") or f"Cryptographic check flagged {ftype}"
        conf = str(item.get("confidence") or "HIGH").upper()
        row = record_finding_provenance(
            db,
            finding_id=fid,
            source_provider="Certificate Validator",
            source_type="cryptographic_validation",
            observed_at=now,
            checked_at=now,
            confidence=conf,
            provider_status="AVAILABLE",
            evidence_reference=str(item.get("fingerprint") or item.get("source") or cert_data.get("sha256") or ""),
            evidence_payload=item,
            scan_job_id=job_ref,
            scan_id=scan_id,
            report_id=report_id,
            revision_id=revision_id,
            title=f"Certificate: {ftype.replace('_', ' ').capitalize()}",
            why_it_exists=why,
            severity="HIGH" if item.get("points", 0) >= 30 else "MEDIUM",
            is_current=True,
        )
        persisted_rows.append(row)

    # 5. Typosquatting / Brand Matches
    domain_intel = result.get("domain_intelligence") or {}
    domain_data = domain_intel.get("domain") or {}
    for match in domain_data.get("brand_matches") or []:
        idx += 1
        brand = match.get("brand") or "Protected Brand"
        sim = match.get("similarity_percent") or 0
        fid = f"fnd-typo-{scan_id or 'adhoc'}-{idx}"
        why = f"Domain lexically resembles {brand} ({sim}% match) via {match.get('manipulation') or 'character permutation'}."
        row = record_finding_provenance(
            db,
            finding_id=fid,
            source_provider="Typosquatting & Brand Engine",
            source_type="lexical_distance",
            observed_at=now,
            checked_at=now,
            confidence="HIGH" if sim >= 80 else "MEDIUM",
            provider_status="AVAILABLE",
            evidence_reference=match.get("official_domain"),
            evidence_payload=match,
            scan_job_id=job_ref,
            scan_id=scan_id,
            report_id=report_id,
            revision_id=revision_id,
            title=f"Brand Mimicry: {brand} ({sim}%)",
            why_it_exists=why,
            severity=str(match.get("risk") or "MEDIUM").upper(),
            is_current=True,
        )
        persisted_rows.append(row)

    # 6. Network & TLS findings
    network = result.get("network") or {}
    for finding in network.get("findings") or []:
        idx += 1
        issue = finding.get("issue") or finding.get("description") or "Transport observation"
        fid = f"fnd-net-{scan_id or 'adhoc'}-{idx}"
        why = finding.get("description") or f"Observed in network handshake: {issue}"
        row = record_finding_provenance(
            db,
            finding_id=fid,
            source_provider="Network Handshake Inspector",
            source_type="active_transport_probe",
            observed_at=now,
            checked_at=now,
            confidence="HIGH",
            provider_status="AVAILABLE",
            evidence_reference=result.get("domain") or result.get("url"),
            evidence_payload=finding,
            scan_job_id=job_ref,
            scan_id=scan_id,
            report_id=report_id,
            revision_id=revision_id,
            title=f"Network: {issue[:60]}",
            why_it_exists=why,
            severity=str(finding.get("severity") or "INFO").upper(),
            is_current=True,
        )
        persisted_rows.append(row)

    serialized = [serialize_provenance(r) for r in persisted_rows]
    result["evidence_provenance"] = serialized
    return serialized
