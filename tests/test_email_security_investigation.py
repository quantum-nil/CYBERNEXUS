import pytest

from backend.app.engines import email_security_investigation as investigation


def test_normalizes_email_and_idn_domain():
    result = investigation.normalize_input("Admin@Bücher.example.")
    assert result["input_type"] == "email"
    assert result["domain"] == "xn--bcher-kva.example"
    assert result["email"] == "Admin@xn--bcher-kva.example"


@pytest.mark.parametrize("value", ["not-an-email", "https://example.com", "bad@@example.com", "localhost", "127.0.0.1"])
def test_rejects_malformed_or_non_domain_targets(value):
    with pytest.raises(ValueError):
        investigation.normalize_input(value)


def test_spf_recurses_includes_and_counts_dns_lookups(monkeypatch):
    records = {
        "example.com": {"status": "FOUND", "records": ["v=spf1 include:_spf.example.com -all"], "checked_at": "now"},
        "_spf.example.com": {"status": "FOUND", "records": ["v=spf1 ip4:192.0.2.0/24 -all"], "checked_at": "now"},
    }
    monkeypatch.setattr(investigation, "_txt", lambda name: records.get(name, {"status": "NXDOMAIN", "records": [], "checked_at": "now"}))
    result = investigation.analyze_spf("example.com")
    assert result["status"] == "PASS"
    assert result["lookup_count"] == 1
    assert result["includes"][0]["status"] == "PASS"


def test_dmarc_parses_policy_alignment_reporting_and_percentage(monkeypatch):
    monkeypatch.setattr(investigation, "_txt", lambda name: {"status": "FOUND", "records": ["v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; adkim=s; aspf=r; pct=50"], "checked_at": "now"})
    result = investigation.analyze_dmarc("example.com")
    assert result["status"] == "PASS"
    assert result["policy"] == "quarantine"
    assert result["subdomain_policy"] == "reject"
    assert result["adkim"] == "s"
    assert result["pct"] == 50
    assert result["rua"] == ["mailto:dmarc@example.com"]


@pytest.mark.parametrize(("policy", "expected_status"), [("none", "WARNING"), ("quarantine", "PASS"), ("reject", "PASS")])
def test_dmarc_policy_strength_is_explained(monkeypatch, policy, expected_status):
    monkeypatch.setattr(investigation, "_txt", lambda name: {"status": "FOUND", "records": [f"v=DMARC1; p={policy}; pct=100"], "checked_at": "now"})
    result = investigation.analyze_dmarc("fixture.example")
    assert result["status"] == expected_status
    assert result["policy"] == policy
    assert result["policy_explanation"]


def test_dkim_selector_missing_is_unknown_not_failure(monkeypatch):
    monkeypatch.setattr(investigation, "_txt", lambda name: {"status": "NXDOMAIN", "records": [], "checked_at": "now"})
    result = investigation.analyze_dkim("example.com", "google")
    assert result["status"] == "UNKNOWN"
    assert result["public_key_status"] == "MISSING"
    assert "not found" in result["error"]


def test_invalid_dkim_signature_is_not_confused_with_missing_selector(monkeypatch):
    monkeypatch.setattr(investigation, "verify_dkim_signatures", lambda raw: [{"status": "FAIL", "public_key_status": "FOUND", "error": "signature_mismatch"}])
    raw = b"DKIM-Signature: v=1; d=example.com; s=selector1; a=rsa-sha256; b=invalid\r\nFrom: sender@example.com\r\n\r\nbody"
    result = investigation.analyze_dkim("example.com", raw_message=raw)
    assert result["status"] == "COMPLETED"
    assert result["signatures"][0]["status"] == "FAIL"
    assert result["selectors"] == [{"domain": "example.com", "selector": "selector1"}]


def test_dns_timeout_stays_unknown(monkeypatch):
    monkeypatch.setattr(investigation, "_txt", lambda name: {"status": "TIMEOUT", "records": [], "checked_at": "now"})
    assert investigation.analyze_spf("fixture.example")["status"] == "UNKNOWN"
    assert investigation.analyze_dmarc("fixture.example")["status"] == "UNKNOWN"


def test_remediation_never_fabricates_dkim_key():
    result = investigation.remediation(
        "example.com",
        {"presence": "MISSING", "warnings": []},
        {"presence": "MISSING", "warnings": []},
        {"mode": "unavailable", "public_key_status": "NOT_REQUESTED"},
    )
    dkim = next(item for item in result["records"] if item["type"] == "DKIM")
    assert dkim["value"] is None
    assert result["ownership_required"] is True
    assert result["overwrite_existing_records"] is False
