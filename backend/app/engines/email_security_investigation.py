"""Evidence-backed email/domain security investigation.

This module deliberately separates DNS policy inspection from message
authentication.  DNS can tell us what a domain publishes; it cannot prove
that a particular mailbox exists or that a particular message was authorized.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from email.parser import BytesParser
from email import policy
from typing import Any

import dns.exception
import dns.flags
import dns.resolver

from backend.app.core.config import settings
from backend.app.engines.domain_intelligence import analyze_domain, registered_domain
from backend.app.engines.email_analysis import verify_dkim_signatures
from backend.app.engines.rdap import fetch_rdap
from backend.app.engines.threats import check as check_threats

MAX_INVESTIGATION_BYTES = 10 * 1024 * 1024
_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_rate_windows: dict[str, deque[float]] = defaultdict(deque)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _error(code: str, message: str) -> ValueError:
    return ValueError(f"{code}: {message}")


def _ascii_domain(value: str) -> str:
    try:
        return value.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise _error("invalid_domain", "internationalised domain could not be converted to IDNA") from exc


def _validate_domain(value: str) -> str:
    domain = value.strip().rstrip(".")
    if not domain or len(domain) > 253 or any(ch.isspace() for ch in domain):
        raise _error("invalid_domain", "provide a valid fully-qualified domain")
    if "/" in domain or ":" in domain or "@" in domain:
        raise _error("invalid_domain", "a domain must not contain a URL, port, or mailbox separator")
    ascii_domain = _ascii_domain(domain)
    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        pass
    else:
        raise _error("invalid_domain", "IP addresses are not accepted as email domains")
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise _error("invalid_domain", "provide a valid fully-qualified domain")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label, re.I) for label in labels):
        raise _error("invalid_domain", "domain labels contain invalid characters")
    return ascii_domain


def normalize_input(value: str) -> dict[str, Any]:
    """Normalize an email address or domain without claiming mailbox existence."""
    if not isinstance(value, str) or not value.strip():
        raise _error("invalid_input", "email address or domain is required")
    raw = value.strip()
    if len(raw) > 320 or any(ch in raw for ch in "\r\n"):
        raise _error("invalid_input", "input is too long or contains header injection characters")
    if "@" in raw:
        if raw.count("@") != 1:
            raise _error("invalid_email", "email address must contain one @ separator")
        local, domain = raw.rsplit("@", 1)
        if not local or len(local.encode("utf-8")) > 64 or any(ch.isspace() for ch in local):
            raise _error("invalid_email", "email local part is malformed")
        if any(ch in local for ch in '()<>[],;:\\"'):
            raise _error("invalid_email", "email local part contains unsupported characters")
        normalized_domain = _validate_domain(domain)
        return {
            "input_type": "email",
            "input": raw,
            "email": f"{local}@{normalized_domain}",
            "local_part": local,
            "domain": normalized_domain,
            "domain_unicode": normalized_domain.encode("ascii").decode("idna"),
        }
    normalized_domain = _validate_domain(raw)
    return {
        "input_type": "domain",
        "input": raw,
        "email": None,
        "local_part": None,
        "domain": normalized_domain,
        "domain_unicode": normalized_domain.encode("ascii").decode("idna"),
    }


def allow_request(client_key: str, limit: int = 30, window_seconds: int = 60) -> bool:
    """Best-effort per-process rate limiting for DNS/provider-heavy requests."""
    now = time.monotonic()
    window = _rate_windows[client_key]
    while window and window[0] <= now - window_seconds:
        window.popleft()
    if len(window) >= limit:
        return False
    window.append(now)
    return True


def _dns_query(name: str, record_type: str) -> dict[str, Any]:
    key = (record_type.upper(), name.lower().rstrip("."))
    now = time.monotonic()
    cached = _cache.get(key)
    if cached and cached[0] > now:
        return {**cached[1], "cached": True}
    result: dict[str, Any] = {
        "name": name.rstrip("."),
        "type": record_type.upper(),
        "status": "UNKNOWN",
        "records": [],
        "checked_at": _now(),
        "dnssec": "NOT_VALIDATED",
        "cached": False,
    }
    try:
        answers = dns.resolver.resolve(name, record_type, lifetime=settings.dns_timeout_seconds)
        response = getattr(answers, "response", None)
        if response is not None and response.flags & dns.flags.AD:
            result["dnssec"] = "VALIDATED"
        if record_type.upper() == "TXT":
            records = [
                b"".join(part if isinstance(part, bytes) else str(part).encode() for part in item.strings).decode(errors="replace")
                for item in answers
            ]
        else:
            records = [item.to_text() for item in answers]
        result.update(status="FOUND" if records else "NO_ANSWER", records=records)
    except dns.resolver.NXDOMAIN:
        result["status"] = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result["status"] = "NO_ANSWER"
    except dns.resolver.NoNameservers:
        result.update(status="SERVFAIL", error="Resolver returned no authoritative answer")
    except dns.exception.Timeout:
        result.update(status="TIMEOUT", error="DNS resolver timed out")
    except Exception as exc:
        result.update(status="UNAVAILABLE", error=type(exc).__name__)
    _cache[key] = (now + max(1, settings.dns_cache_ttl_seconds), result)
    return result


def _txt(name: str) -> dict[str, Any]:
    return _dns_query(name, "TXT")


def _spf_mechanism(term: str) -> tuple[str, str | None, bool]:
    value = term.lower()
    value = value[1:] if value[:1] in "+-?~" else value
    if value.startswith("include:"):
        return "include", value[8:], True
    if value.startswith("redirect="):
        return "redirect", value[9:], True
    if re.match(r"^(a|mx|exists:|ptr)(?::[^\s/]+)?(?:/[0-9]+)?$", value):
        return value.split(":", 1)[0].split("/", 1)[0], None, True
    if re.match(r"^ip[46]:[^\s]+(?:/[0-9]+)?$", value):
        return value.split(":", 1)[0], None, False
    if value in {"all", "?all", "~all", "-all", "+all"}:
        return "all", value, False
    if value.startswith("exp="):
        return "exp", value[4:], False
    return "invalid", term, False


def _spf_record(domain: str, *, depth: int = 0, path: tuple[str, ...] = (), counter: list[int] | None = None) -> dict[str, Any]:
    counter = counter or [0]
    lookup = _txt(domain)
    records = [record for record in lookup["records"] if re.match(r"^v=spf1(?:\s|$)", record, re.I)]
    result: dict[str, Any] = {
        "domain": domain,
        "dns_status": lookup["status"],
        "record": records[0] if len(records) == 1 else None,
        "records": records,
        "presence": "PRESENT" if records else "MISSING",
        "status": "UNKNOWN",
        "syntax_valid": False,
        "mechanisms": [],
        "lookup_count": counter[0],
        "lookup_limit": 10,
        "includes": [],
        "warnings": [],
        "evidence": {"source": "DNS TXT", "record_name": domain, "cached": lookup.get("cached", False)},
    }
    if lookup["status"] in {"TIMEOUT", "SERVFAIL", "UNAVAILABLE"}:
        result["error"] = "SPF record discovery is unavailable; this is not the same as a missing record"
        return result
    if len(records) > 1:
        result.update(status="FAIL", error="Multiple SPF records were published", warnings=["multiple_spf_records"])
        return result
    if not records:
        result["status"] = "WARNING" if lookup["status"] in {"NXDOMAIN", "NO_ANSWER"} else "UNKNOWN"
        result["warnings"] = ["spf_record_missing"]
        return result
    terms = records[0].split()
    mechanisms = terms[1:]
    result["mechanisms"] = mechanisms
    result["syntax_valid"] = True
    all_terms = []
    for term in mechanisms:
        kind, target, dns_lookup = _spf_mechanism(term)
        all_terms.append(kind)
        if kind == "invalid":
            result["syntax_valid"] = False
            result["warnings"].append(f"invalid_mechanism:{term}")
        if kind == "all" and term.lower() in {"+all", "all"}:
            result["warnings"].append("permissive_all")
        if kind == "all" and term.lower() in {"?all", "~all"}:
            result["warnings"].append("soft_or_neutral_all")
        if dns_lookup and target:
            counter[0] += 1
            child: dict[str, Any] = {"mechanism": kind, "target": target}
            if counter[0] > 10:
                child.update(status="LIMIT_EXCEEDED", error="RFC SPF DNS lookup limit exceeded")
                result["warnings"].append("dns_lookup_limit_exceeded")
            elif depth >= 10 or target in path or target == domain:
                child.update(status="RECURSION_ERROR", error="SPF include/redirect recursion or cycle detected")
                result["warnings"].append("recursive_include")
            else:
                child_record = _spf_record(target, depth=depth + 1, path=path + (domain,), counter=counter)
                child.update(status=child_record["status"], dns_status=child_record["dns_status"], record=child_record.get("record"), presence=child_record.get("presence"), warnings=child_record.get("warnings", []))
                if child_record["status"] in {"UNKNOWN", "FAIL"} or child_record.get("presence") == "MISSING":
                    result["warnings"].append(f"unresolved_{kind}:{target}")
            result["includes"].append(child)
    result["lookup_count"] = counter[0]
    result["dns_lookup_mechanism_count"] = sum(1 for term in mechanisms if _spf_mechanism(term)[2])
    if not any(kind == "all" for kind in all_terms):
        result["warnings"].append("missing_all_mechanism")
    result["warnings"] = list(dict.fromkeys(result["warnings"]))
    if not result["syntax_valid"]:
        result["status"] = "FAIL"
    elif result["warnings"]:
        result["status"] = "WARNING"
    else:
        result["status"] = "PASS"
    return result


def analyze_spf(domain: str) -> dict[str, Any]:
    return _spf_record(domain, path=())


_DMARC_TAGS = {"v", "p", "sp", "rua", "ruf", "adkim", "aspf", "pct", "fo", "rf", "ri"}


def _parse_dmarc_record(record: str) -> tuple[dict[str, str], list[str]]:
    tags: dict[str, str] = {}
    warnings: list[str] = []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            warnings.append(f"malformed_tag:{part}")
            continue
        key, value = (piece.strip().lower() for piece in part.split("=", 1))
        if key in tags:
            warnings.append(f"duplicate_tag:{key}")
        tags[key] = value
        if key not in _DMARC_TAGS:
            warnings.append(f"unknown_tag:{key}")
    return tags, warnings


def analyze_dmarc(domain: str) -> dict[str, Any]:
    name = f"_dmarc.{domain}"
    lookup = _txt(name)
    records = [record for record in lookup["records"] if re.match(r"^v=dmarc1(?:\s*;|\s*$)", record, re.I)]
    result: dict[str, Any] = {
        "domain": domain,
        "record_name": name,
        "dns_status": lookup["status"],
        "records": records,
        "record": records[0] if len(records) == 1 else None,
        "presence": "PRESENT" if records else "MISSING",
        "status": "UNKNOWN",
        "syntax_valid": False,
        "policy": None,
        "subdomain_policy": None,
        "rua": [],
        "ruf": [],
        "adkim": "r",
        "aspf": "r",
        "pct": 100,
        "warnings": [],
        "evidence": {"source": "DNS TXT", "record_name": name, "cached": lookup.get("cached", False)},
    }
    if lookup["status"] in {"TIMEOUT", "SERVFAIL", "UNAVAILABLE"}:
        result["error"] = "DMARC record discovery is unavailable; this is not the same as a missing record"
        return result
    if len(records) > 1:
        result.update(status="FAIL", error="Multiple DMARC records were published", warnings=["multiple_dmarc_records"])
        return result
    if not records:
        result["status"] = "WARNING" if lookup["status"] in {"NXDOMAIN", "NO_ANSWER"} else "UNKNOWN"
        result["warnings"] = ["dmarc_record_missing"]
        return result
    tags, warnings = _parse_dmarc_record(records[0])
    result.update(policy=tags.get("p"), subdomain_policy=tags.get("sp"), rua=tags.get("rua", "").split(",") if tags.get("rua") else [], ruf=tags.get("ruf", "").split(",") if tags.get("ruf") else [], adkim=tags.get("adkim", "r"), aspf=tags.get("aspf", "r"), tags=tags, warnings=warnings)
    if tags.get("v") != "dmarc1":
        warnings.append("invalid_version")
    if tags.get("p") not in {"none", "quarantine", "reject"}:
        warnings.append("invalid_policy")
    if tags.get("sp") and tags["sp"] not in {"none", "quarantine", "reject"}:
        warnings.append("invalid_subdomain_policy")
    if tags.get("adkim", "r") not in {"r", "s"} or tags.get("aspf", "r") not in {"r", "s"}:
        warnings.append("invalid_alignment_mode")
    try:
        pct = int(tags.get("pct", "100"))
        if not 0 <= pct <= 100:
            raise ValueError
        result["pct"] = pct
    except ValueError:
        warnings.append("invalid_percentage")
    for tag in ("rua", "ruf"):
        for uri in result[tag]:
            if not re.match(r"^mailto:[^@\s]+@[^@\s]+\.[^@\s]+$", uri, re.I):
                warnings.append(f"invalid_{tag}_uri")
    if result["policy"] == "none":
        warnings.append("monitoring_only_policy")
        result["policy_explanation"] = "p=none collects evidence but asks receivers not to quarantine or reject messages."
    elif result["policy"] == "quarantine":
        result["policy_explanation"] = "p=quarantine asks receivers to treat DMARC failures as suspicious, commonly sending them to spam."
    elif result["policy"] == "reject":
        result["policy_explanation"] = "p=reject asks receivers to reject messages that fail DMARC alignment."
    result["warnings"] = list(dict.fromkeys(warnings))
    result["syntax_valid"] = not any(item.startswith(("invalid_", "malformed_", "duplicate_")) for item in result["warnings"])
    result["status"] = "FAIL" if not result["syntax_valid"] else "WARNING" if result["warnings"] else "PASS"
    return result


def _selector(value: str) -> str:
    selector = value.strip().rstrip(".")
    if not selector or len(selector) > 63 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", selector):
        raise _error("invalid_selector", "DKIM selector contains invalid DNS label characters")
    return selector.lower()


def _dkim_record(selector: str, domain: str) -> dict[str, Any]:
    name = f"{selector}._domainkey.{domain}"
    lookup = _txt(name)
    records = lookup["records"]
    result: dict[str, Any] = {"selector": selector, "record_name": name, "dns_status": lookup["status"], "records": records, "status": "UNKNOWN", "inspection_status": "UNKNOWN", "public_key_status": "UNKNOWN", "source": "DKIM DNS selector inspection", "checked_at": lookup["checked_at"], "evidence": {"source": "DNS TXT", "record_name": name, "cached": lookup.get("cached", False)}}
    if lookup["status"] in {"TIMEOUT", "SERVFAIL", "UNAVAILABLE"}:
        result["error"] = "DKIM selector lookup is unavailable; this is not a DKIM failure"
        return result
    if not records:
        result["error"] = "DKIM selector public key was not found"
        result["public_key_status"] = "MISSING"
        return result
    if len(records) > 1:
        result.update(public_key_status="INVALID", inspection_status="FAIL", error="Multiple DKIM public-key records were published")
        return result
    record = records[0]
    tags, warnings = {}, []
    for part in record.split(";"):
        if "=" not in part:
            if part.strip(): warnings.append("malformed_tag")
            continue
        key, value = (piece.strip().lower() for piece in part.split("=", 1))
        if key in tags: warnings.append(f"duplicate_tag:{key}")
        tags[key] = value
    key_type = tags.get("k", "rsa")
    public_key = tags.get("p", "")
    if tags.get("v", "dkim1") != "dkim1": warnings.append("invalid_version")
    if key_type not in {"rsa", "ed25519"}: warnings.append("unsupported_key_type")
    if not public_key: warnings.append("empty_public_key")
    else:
        try: base64.b64decode(public_key + "=" * (-len(public_key) % 4), validate=True)
        except (ValueError, binascii.Error): warnings.append("invalid_public_key_encoding")
    result.update(record=record, tags=tags, key_type=key_type, public_key_status="FOUND" if not warnings else "INVALID", warnings=warnings, inspection_status="PASS" if not warnings else "FAIL", status="UNKNOWN", message_verification="NOT_PERFORMED")
    if warnings: result["error"] = "DKIM DNS key is malformed: " + ", ".join(warnings)
    else: result["note"] = "A DNS public key is not a cryptographic message PASS; upload trusted original message bytes to verify a signature."
    return result


def analyze_dkim(domain: str, selector: str | None = None, raw_message: bytes | None = None) -> dict[str, Any]:
    if raw_message:
        if len(raw_message) > MAX_INVESTIGATION_BYTES:
            raise _error("message_too_large", "original message is larger than 10 MB")
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
        headers = [str(value) for name, value in message.raw_items() if name.lower() == "dkim-signature"]
        extracted = []
        for header in headers:
            domain_match = re.search(r"(?:^|;)\s*d=([^;\s]+)", header, re.I)
            selector_match = re.search(r"(?:^|;)\s*s=([^;\s]+)", header, re.I)
            if domain_match and selector_match:
                extracted.append({"domain": _validate_domain(domain_match.group(1)), "selector": _selector(selector_match.group(1))})
        verification = verify_dkim_signatures(raw_message)
        return {"mode": "message_signature", "status": "COMPLETED", "signatures": verification, "selectors": extracted, "source": "independent cryptographic verification", "note": "Verification used the supplied original RFC5322 bytes."}
    if selector:
        return {"mode": "dns_selector", **_dkim_record(_selector(selector), domain)}
    return {"mode": "unavailable", "status": "UNKNOWN", "public_key_status": "NOT_REQUESTED", "error": "No DKIM selector or trusted original message bytes were supplied", "note": "A selector is needed for DNS key inspection; a message is needed for cryptographic verification."}


def _provider_statuses(threat: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"provider": item.get("provider"), "status": item.get("status"), "verdict": item.get("verdict", "unknown"), "source": item.get("provider") or "configured threat provider"} for item in threat.get("providers", [])]


def analyze_domain_threat(domain: str, provider_registry: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    sources: list[str] = []
    score = 0
    try:
        domain_profile = analyze_domain(domain)
    except Exception as exc:
        domain_profile = {"domain": domain, "brand_matches": [], "indicators": [], "error": type(exc).__name__}
    sources.append("local domain similarity engine")
    for match in domain_profile.get("brand_matches", []):
        points = 25 if match.get("risk") == "high" else 15
        score += points
        evidence.append({"signal": "lookalike_or_typosquat", "points": points, "severity": match.get("risk", "medium"), "source": "local domain similarity engine", "details": match})
    for indicator in domain_profile.get("indicators", []):
        points = 20 if indicator.get("severity") == "high" else 10
        score += points
        evidence.append({"signal": indicator.get("type", "domain_indicator"), "points": points, "severity": indicator.get("severity", "medium"), "source": "local domain similarity engine", "details": indicator})
    mx = _dns_query(domain, "MX")
    if mx["status"] == "FOUND": sources.append("DNS MX")
    elif mx["status"] in {"TIMEOUT", "SERVFAIL", "UNAVAILABLE"}: evidence.append({"signal": "mx_lookup_unavailable", "points": 0, "severity": "unknown", "source": "DNS MX", "details": mx})
    registry = next((item for item in (provider_registry or []) if str(item.get("domain", "")).lower().rstrip(".") in {domain, registered_domain(domain)}), None)
    disposable = bool(registry and str(registry.get("disposable", "")).lower() == "true")
    if disposable:
        score += 15
        evidence.append({"signal": "disposable_email_provider", "points": 15, "severity": "medium", "source": registry.get("source", "maintained provider registry"), "details": {"provider": registry.get("provider_name"), "domain": domain}})
    try:
        threat = check_threats("https://" + domain)
    except Exception as exc:
        threat = {"providers": [], "findings": [], "error": type(exc).__name__}
    sources.extend(item.get("provider") for item in threat.get("providers", []) if item.get("provider"))
    for provider in threat.get("providers", []):
        verdict = provider.get("verdict")
        if verdict in {"malicious", "phishing"}:
            score += 60
            evidence.append({"signal": "provider_malicious", "points": 60, "severity": "high", "source": provider.get("provider"), "details": provider})
        elif verdict == "suspicious":
            score += 25
            evidence.append({"signal": "provider_suspicious", "points": 25, "severity": "medium", "source": provider.get("provider"), "details": provider})
    rdap = fetch_rdap(domain)
    sources.append("RDAP")
    registration = (rdap.get("events") or {}).get("registration")
    age_days = None
    if registration:
        try:
            age_days = max(0, (datetime.now(timezone.utc) - datetime.fromisoformat(registration.replace("Z", "+00:00"))).days)
            if age_days < 30:
                score += 15
                evidence.append({"signal": "recent_registration", "points": 15, "severity": "medium", "source": "RDAP", "details": {"registration": registration, "age_days": age_days}})
        except (TypeError, ValueError):
            age_days = None
    score = min(100, score)
    provider_known = any(item.get("verdict") in {"malicious", "phishing", "suspicious", "no_match", "clean"} for item in threat.get("providers", []))
    verdict = "malicious" if any(item["signal"] == "provider_malicious" for item in evidence) else "suspicious" if evidence else "unknown"
    classification = "CRITICAL" if score >= 70 else "HIGH" if score >= 45 else "MEDIUM" if score >= 20 else "LOW" if provider_known else "UNKNOWN"
    return {"domain": domain, "score": score if provider_known or evidence else None, "classification": classification, "verdict": verdict, "confidence": "high" if any(item["signal"] == "provider_malicious" for item in evidence) else "medium" if evidence else "low", "evidence": evidence, "sources": list(dict.fromkeys(sources)), "providers": _provider_statuses(threat), "findings": threat.get("findings", []), "mx": mx, "rdap": rdap, "domain_profile": domain_profile, "disposable": disposable, "age_days": age_days, "note": "Threat evidence is explainable and source-attributed. Unknown provider results are not treated as clean."}


def remediation(domain: str, spf: dict[str, Any], dmarc: dict[str, Any], dkim: dict[str, Any]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    if spf.get("presence") != "PRESENT":
        records.append({"type": "TXT", "name": domain, "value": "v=spf1 -all", "status": "RECOMMENDED", "safe_to_publish": False, "explanation": "Use this only when the domain sends no mail. If it sends mail, inventory authorized senders and replace -all with their mechanisms."})
    elif "multiple_spf_records" in spf.get("warnings", []):
        records.append({"type": "TXT", "name": domain, "value": None, "status": "MANUAL_REVIEW", "safe_to_publish": False, "explanation": "Publish exactly one SPF record after merging the authorized mechanisms; the engine will not guess or overwrite it."})
    elif any(item in spf.get("warnings", []) for item in ("permissive_all", "soft_or_neutral_all")):
        records.append({"type": "TXT", "name": domain, "value": spf.get("record"), "status": "HARDEN_AFTER_SENDER_INVENTORY", "safe_to_publish": False, "explanation": "Replace a permissive or soft final policy with -all only after every legitimate sender is represented."})
    if dmarc.get("presence") != "PRESENT":
        records.append({"type": "TXT", "name": f"_dmarc.{domain}", "value": "v=DMARC1; p=none; pct=100", "status": "RECOMMENDED", "safe_to_publish": False, "explanation": "Start in monitoring mode, collect reports, then move to quarantine and reject after alignment is verified."})
    elif dmarc.get("policy") == "none":
        records.append({"type": "TXT", "name": f"_dmarc.{domain}", "value": "v=DMARC1; p=quarantine; pct=100", "status": "NEXT_HARDENING_STEP", "safe_to_publish": False, "explanation": "Move from monitoring to quarantine only after aggregate reports show legitimate senders align."})
    elif dmarc.get("policy") == "quarantine":
        records.append({"type": "TXT", "name": f"_dmarc.{domain}", "value": "v=DMARC1; p=reject; pct=100", "status": "NEXT_HARDENING_STEP", "safe_to_publish": False, "explanation": "Move to reject only after quarantined traffic has been reviewed and legitimate sources align."})
    if dkim.get("mode") == "unavailable" or dkim.get("public_key_status") == "MISSING":
        records.append({"type": "DKIM", "name": None, "value": None, "status": "ACTION_REQUIRED", "safe_to_publish": False, "explanation": "Select the sending provider and selector, then publish the provider-generated public key. CyberNexus never fabricates DKIM keys."})
    return {"records": records, "ownership_required": True, "explicit_approval_required": True, "overwrite_existing_records": False, "cloudflare": {"status": "DESIGN_ONLY", "message": "DNS changes are not applied by this investigation endpoint. Use an authorized provider integration only after ownership verification and explicit approval."}, "verification": {"endpoint": "/api/intelligence/email/remediation/verify", "method": "POST", "input": "domain"}}


def investigate(target: str, selector: str | None = None, raw_message: bytes | None = None, provider_registry: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    normalized = normalize_input(target)
    domain = normalized["domain"]
    spf = analyze_spf(domain)
    dmarc = analyze_dmarc(domain)
    dkim = analyze_dkim(domain, selector, raw_message)
    threat = analyze_domain_threat(domain, provider_registry)
    identity = {"input_type": normalized["input_type"], "email": normalized["email"], "domain": domain, "mailbox_existence": "NOT_CHECKED", "message": "DNS and threat intelligence cannot prove that a mailbox exists. No SMTP probing was performed."}
    return {"target": normalized, "identity": identity, "spf": spf, "dmarc": dmarc, "dkim": dkim, "domain_threat_intelligence": threat, "remediation": remediation(domain, spf, dmarc, dkim), "checked_at": _now(), "status": "COMPLETED", "limitations": ["SPF DNS discovery is separate from sender-IP verification.", "DKIM DNS key discovery is separate from message signature verification.", "Unavailable or unknown evidence is not treated as safe.", "No mailbox existence claim or invasive SMTP probe was made."]}
