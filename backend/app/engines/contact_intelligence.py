"""Phone validation/reputation and database-backed email classification."""
import re
import random
import time
from dataclasses import dataclass
from typing import Any, Protocol
from datetime import datetime, timezone
from urllib.parse import quote
import httpx
import dns.resolver
from backend.app.core.config import settings
from backend.app.engines.domain_intelligence import analyze_domain, registered_domain
from backend.app.engines.threats import check as check_url
from backend.app.services import cache
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder
except ImportError: phonenumbers = None

_cache = {}  # Backward-compatible test hook; provider caching uses the shared cache service.
_provider_requests: dict[str, list[float]] = {}
def _now(): return datetime.now(timezone.utc).isoformat()

def validate_phone(value):
    base={"indicator":value,"provider":"libphonenumber","checked_at":_now(),"verdict":"unknown","status":"UNKNOWN","risk_score":None,"classification":"UNKNOWN","confidence":"low","evidence":[]}
    if not phonenumbers: return {**base,"status":"UNAVAILABLE","reason":"Phone validation library is unavailable"}
    try:
        region = None if str(value).lstrip().startswith("+") else settings.phone_default_region.strip().upper()
        parsed=phonenumbers.parse(value, region or None); valid=phonenumbers.is_valid_number(parsed); possible=phonenumbers.is_possible_number(parsed); number_type=phonenumbers.number_type(parsed)
        type_name={phonenumbers.PhoneNumberType.MOBILE:"MOBILE",phonenumbers.PhoneNumberType.FIXED_LINE:"LANDLINE",phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE:"FIXED_OR_MOBILE",phonenumbers.PhoneNumberType.VOIP:"VOIP",phonenumbers.PhoneNumberType.PERSONAL_NUMBER:"PERSONAL",phonenumbers.PhoneNumberType.PAGER:"PAGER"}.get(number_type,"UNKNOWN")
        return {**base,"status":"COMPLETED","normalized":phonenumbers.format_number(parsed,phonenumbers.PhoneNumberFormat.E164),"international_format":phonenumbers.format_number(parsed,phonenumbers.PhoneNumberFormat.INTERNATIONAL),"national_format":phonenumbers.format_number(parsed,phonenumbers.PhoneNumberFormat.NATIONAL),"country_code":parsed.country_code,"national_number":str(parsed.national_number),"country":geocoder.description_for_number(parsed,"en"),"carrier":carrier.name_for_number(parsed,"en"),"number_type":type_name,"valid":valid,"possible":possible,"evidence":["Numbering metadata only; validity is not abuse reputation."]}
    except Exception as exc: return {**base,"status":"COMPLETED","valid":False,"possible":False,"reason":type(exc).__name__}

class PhoneProvider(Protocol):
    name: str
    def lookup(self, number: str) -> dict[str, Any]: ...


def _unknown(provider: str, status: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {"provider": provider, "status": status, "verdict": "unknown", "classification": "UNKNOWN",
            "risk_score": None, "reason": reason, "checked_at": _now(), **extra}


@dataclass
class IPQualityScoreProvider:
    name: str = "IPQualityScore Phone Validation"

    def lookup(self, number: str) -> dict[str, Any]:
        key = settings.ipqualityscore_api_key.strip()
        if not key:
            return _unknown(self.name, "NOT_CONFIGURED", "IPQualityScore API credentials are not configured.")
        url = f"{settings.ipqualityscore_base_url.rstrip('/')}/{key}/{quote(number, safe='+')}"
        for attempt in range(settings.phone_reputation_max_retries + 1):
            try:
                response = httpx.get(url, headers={"Accept": "application/json"}, timeout=settings.phone_reputation_timeout_seconds, follow_redirects=False)
                if response.status_code in (429,) or response.status_code >= 500:
                    if attempt < settings.phone_reputation_max_retries:
                        time.sleep(min(2 ** attempt + random.random(), 4)); continue
                if response.status_code in (401, 403): return _unknown(self.name, "INVALID_CREDENTIALS", "IPQualityScore rejected the configured API key.")
                if response.status_code == 429: return _unknown(self.name, "RATE_LIMITED", "IPQualityScore quota or rate limit was reached.")
                if response.status_code >= 500: return _unknown(self.name, "UNAVAILABLE", "IPQualityScore is unavailable.")
                if not 200 <= response.status_code < 300: return _unknown(self.name, "PROVIDER_ERROR", f"IPQualityScore returned HTTP {response.status_code}.")
                payload = response.json()
                if not isinstance(payload, dict): raise ValueError("response is not an object")
                if payload.get("success") is False:
                    return _unknown(self.name, "PROVIDER_ERROR", str(payload.get("message") or "IPQualityScore rejected the lookup."), raw_evidence=payload)
                return self._normalise(payload)
            except httpx.TimeoutException:
                if attempt == settings.phone_reputation_max_retries: return _unknown(self.name, "TIMEOUT", "IPQualityScore timed out; reputation is unknown.")
            except httpx.RequestError as exc:
                if attempt == settings.phone_reputation_max_retries: return _unknown(self.name, "UNAVAILABLE", "IPQualityScore could not be reached.", error=type(exc).__name__)
            except (ValueError, TypeError):
                return _unknown(self.name, "INVALID_RESPONSE", "IPQualityScore returned malformed JSON.")
        return _unknown(self.name, "UNAVAILABLE", "IPQualityScore lookup failed.")

    def _normalise(self, payload: dict[str, Any]) -> dict[str, Any]:
        score = payload.get("fraud_score")
        score = score if isinstance(score, (int, float)) and 0 <= score <= 100 else None
        reported = [k for k in ("recent_abuse", "risky", "spammer", "leaked") if payload.get(k) is True]
        verdict = "malicious" if payload.get("recent_abuse") is True or payload.get("spammer") is True else "suspicious" if payload.get("risky") is True or (score is not None and score >= 75) else "clean" if score is not None and score < 25 and not reported else "unknown"
        return {"provider": self.name, "status": "COMPLETED", "verdict": verdict, "fraud_score": score,
                "confidence": "high" if reported else "medium" if score is not None else "low",
                "reported_signals": reported, "prediction_signals": ["fraud_score"] if score is not None else [],
                "valid": payload.get("valid"), "active": payload.get("active"), "recent_abuse": payload.get("recent_abuse"),
                "risky": payload.get("risky"), "spammer": payload.get("spammer"), "leaked": payload.get("leaked"),
                "voip": payload.get("VOIP"), "prepaid": payload.get("prepaid"), "line_type": payload.get("line_type"),
                "carrier": payload.get("carrier"), "country": payload.get("country"), "evidence": payload, "checked_at": _now()}


@dataclass
class GenericPhoneProvider:
    name: str
    url: str
    key: str

    def lookup(self, number: str) -> dict[str, Any]:
        if not self.url: return _unknown(self.name, "NOT_CONFIGURED", "Phone reputation provider credentials are not configured.")
        try:
            headers = {"Accept": "application/json"}
            if self.key: headers[settings.phone_reputation_auth_header] = self.key
            response = httpx.get(self.url, params={"phone": number}, headers=headers, timeout=settings.phone_reputation_timeout_seconds, follow_redirects=False)
            if response.status_code == 429: return _unknown(self.name, "RATE_LIMITED", "Phone reputation provider rate limit reached.")
            if response.status_code >= 500: return _unknown(self.name, "UNAVAILABLE", "Phone reputation provider is unavailable.")
            if not 200 <= response.status_code < 300: return _unknown(self.name, "PROVIDER_ERROR", f"Provider returned HTTP {response.status_code}.")
            payload = response.json()
            if not isinstance(payload, dict): raise ValueError
            score = payload.get("fraud_score")
            verdict = str(payload.get("verdict") or payload.get("reputation") or "unknown").lower()
            verdict = "malicious" if verdict in {"fraud", "scam", "malicious"} else "suspicious" if verdict in {"spam", "suspicious", "high_risk"} else "clean" if verdict in {"clean", "safe", "low_risk"} else "unknown"
            if score is None and verdict in {"malicious", "suspicious", "clean"}:
                score = {"malicious": 90, "suspicious": 60, "clean": 10}[verdict]
            return {"provider": self.name, "status": "COMPLETED", "verdict": verdict, "fraud_score": score, "confidence": payload.get("confidence"), "evidence": payload, "checked_at": _now()}
        except httpx.TimeoutException: return _unknown(self.name, "TIMEOUT", "Phone reputation provider timed out.")
        except (httpx.RequestError, ValueError, TypeError) as exc: return _unknown(self.name, "INVALID_RESPONSE" if isinstance(exc, (ValueError, TypeError)) else "UNAVAILABLE", "Phone reputation could not be verified.", error=type(exc).__name__)


def phone_provider_status() -> dict[str, Any]:
    configured = bool(settings.ipqualityscore_api_key.strip() or (settings.phone_reputation_api_url.strip() and settings.phone_reputation_api_key.strip()))
    return {"status": "CONFIGURED" if configured else "NOT_CONFIGURED", "provider": "IPQualityScore Phone Validation" if settings.ipqualityscore_api_key.strip() else settings.phone_reputation_provider, "configured": configured}


def phone_reputation(number):
    provider: PhoneProvider = IPQualityScoreProvider() if settings.ipqualityscore_api_key.strip() else GenericPhoneProvider(settings.phone_reputation_provider, settings.phone_reputation_api_url.strip(), settings.phone_reputation_api_key.strip())
    provider_identity = getattr(provider, "url", settings.ipqualityscore_base_url)
    cache_key = f"phone-reputation:{provider.name}:{provider_identity}:{number}"
    now = time.time()
    request_times = [stamp for stamp in _provider_requests.get(provider_identity, []) if now - stamp < 60]
    if len(request_times) >= max(1, settings.phone_reputation_rate_limit_per_minute):
        return _unknown(provider.name, "RATE_LIMITED", "Local phone reputation request limit reached; retry shortly.")
    request_times.append(now)
    _provider_requests[provider_identity] = request_times
    try:
        cached = cache.get(cache_key)
        if cached: return {**cached, "cached": True}
    except RuntimeError as exc: return _unknown(provider.name, "UNAVAILABLE", "Distributed cache is required in production.", error=type(exc).__name__)
    result = provider.lookup(number)
    if result.get("status") == "COMPLETED":
        try: cache.set(cache_key, result, settings.phone_reputation_cache_ttl_seconds)
        except RuntimeError: pass
    return result


def phone_analysis(value):
    validation = validate_phone(value)
    reputation = phone_reputation(validation["normalized"]) if validation.get("normalized") and validation.get("valid") else _unknown("Phone reputation", "UNKNOWN", "Number could not be normalized and validated.")
    score = reputation.get("fraud_score") if reputation.get("status") == "COMPLETED" and isinstance(reputation.get("fraud_score"), (int, float)) else None
    evidence = list(validation.get("evidence", [])); factors = []
    for key, label in (("recent_abuse", "Provider reported recent abuse"), ("spammer", "Provider reported spam activity"), ("risky", "Provider marked the number as risky"), ("leaked", "Provider reported leaked exposure"), ("active", "Provider reports the line is inactive")):
        if reputation.get(key) is True or (key == "active" and reputation.get(key) is False): factors.append(label)
    evidence.extend(factors)
    classification = "UNKNOWN"
    if score is not None or factors:
        effective = max([score or 0, 95 if any(x in reputation.get("reported_signals", []) for x in ("recent_abuse", "spammer")) else 0])
        classification = "CRITICAL" if effective >= 90 else "HIGH" if effective >= 75 else "MEDIUM" if effective >= 40 else "LOW"
    return {**validation, "reputation": reputation, "risk_score": score, "classification": classification, "verdict": reputation.get("verdict", "unknown"), "evidence": evidence, "risk_factors": factors, "last_checked": reputation.get("checked_at", _now())}

def _txt(name):
    try:
        return [b"".join(part if isinstance(part,bytes) else str(part).encode() for part in item.strings).decode(errors="replace") for item in dns.resolver.resolve(name,"TXT",lifetime=4)]
    except Exception: return []

def email_analysis(address, provider_registry=None):
    domain=address.rsplit("@",1)[-1].lower().rstrip("."); registrable=registered_domain(domain); registry=next((item for item in (provider_registry or []) if item.get("domain")==domain or item.get("domain")==registrable),None)
    custom={item.strip().lower() for item in settings.disposable_email_domains.split(",") if item.strip()}; disposable=bool(registry and str(registry.get("disposable")).lower()=="true") or domain in custom or registrable in custom
    provider_name=registry.get("provider_name") if registry else None; category=registry.get("category") if registry else "UNKNOWN"
    try: mx=[str(x.exchange).rstrip(".") for x in dns.resolver.resolve(domain,"MX",lifetime=4)]; mx_status="PRESENT" if mx else "NONE"
    except Exception: mx=[]; mx_status="UNKNOWN"
    spf=[x for x in _txt(domain) if x.lower().startswith("v=spf1")]; dmarc=[x for x in _txt("_dmarc."+domain) if x.lower().startswith("v=dmarc1")]
    try: threat=check_url("https://"+domain)
    except Exception as exc: threat={"providers":[],"findings":[],"error":type(exc).__name__}
    malicious=any(item.get("verdict") in {"malicious","phishing"} for item in threat.get("providers",[])); score=80 if malicious else 15 if disposable else 0; classification="CRITICAL" if score>=80 else "MEDIUM" if disposable else "LOW" if registry and not malicious else "UNKNOWN"; evidence=[]
    if malicious: evidence.append("Configured threat-intelligence provider reported the email domain.")
    if disposable: evidence.append("Domain is listed as disposable; this is not proof of fraud.")
    return {"indicator":address,"domain":domain,"registered_domain":registrable,"provider_name":provider_name,"provider_category":category,"disposable":disposable,"mx":{"status":mx_status,"records":mx},"spf":{"status":"PRESENT" if spf else "UNKNOWN","records":spf},"dmarc":{"status":"PRESENT" if dmarc else "UNKNOWN","records":dmarc},"domain_threat_intelligence":threat,"risk_score":score if classification!="UNKNOWN" else None,"classification":classification,"verdict":"malicious" if malicious else "unknown","confidence":"high" if malicious else "medium" if disposable else "low","evidence":evidence,"checked_at":_now()}
