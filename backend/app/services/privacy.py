"""Privacy-preserving, non-persistent data minimization helpers."""
import hashlib
import json
import re
from typing import Any

_SENSITIVE_KEY = re.compile(r"(email|phone|token|secret|password|authorization|cookie|session|ip|address|message|body|content)", re.I)

def _pseudonym(value: Any) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()
    return f"sha256:{digest[:20]}"

def redact(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {str(name): ("[REDACTED]" if _SENSITIVE_KEY.search(str(name)) else redact(item, str(name))) for name, item in value.items()}
    if isinstance(value, list):
        return [redact(item, key) for item in value]
    if key and _SENSITIVE_KEY.search(key):
        return _pseudonym(value)
    return value

def privacy_summary(value: Any) -> dict[str, Any]:
    redacted = redact(value)
    return {"redacted": redacted, "persistent": False, "algorithm": "SHA-256 pseudonymization", "input_hash": hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()}
