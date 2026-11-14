import json
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.models.models import AuditLog

client = TestClient(app)

def test_login_and_audit_log_flow():
    # 1. Login as admin
    res = client.post(
        "/api/auth/login",
        json={"email": "admin@cybernexus.io", "role": "admin", "tenant_id": "tenant_default"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["authenticated"] is True
    assert "token" in data
    token = data["token"]
    assert data["user"]["role"] == "admin"
    assert data["user"]["tenant_id"] == "tenant_default"

    # 2. Check me endpoint with Bearer token
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["authenticated"] is True
    assert me_data["role"] == "admin"
    assert me_data["tenant_id"] == "tenant_default"

    # 3. Check audit logs endpoint
    audit_res = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {token}"})
    assert audit_res.status_code == 200
    logs = audit_res.json()
    assert len(logs) > 0
    assert any(log["action"] == "AUTH_LOGIN" for log in logs)

    # 4. Check tenants endpoint
    tenants_res = client.get("/api/tenants")
    assert tenants_res.status_code == 200
    tenants = tenants_res.json()
    assert len(tenants) > 0
    assert any(t["id"] == "tenant_default" for t in tenants)

    # 5. Check logout records audit event
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200
    assert logout_res.json()["logged_out"] is True

def test_scan_and_message_deletion():
    # 1. Create a scan
    scan_res = client.post("/api/scans", json={"url": "https://example-test-delete.com", "scan_mode": "PUBLIC_PASSIVE"})
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["id"]

    # 2. Verify scan can be retrieved
    get_res = client.get(f"/api/scans/{scan_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == scan_id

    # 3. Delete scan
    del_res = client.delete(f"/api/scans/{scan_id}")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True
    assert del_res.json()["scan_id"] == scan_id

    # 4. Confirm it is gone
    get_after = client.get(f"/api/scans/{scan_id}")
    assert get_after.status_code == 404
