"""In-process real-time scan jobs.

The job API keeps the request responsive while reusing the existing scanner.
It is intentionally storage-backed so a browser can poll status safely.
"""
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from uuid import uuid4

from backend.app.db.session import SessionLocal
from backend.app.models.models import BackgroundTaskRun, Scan
from backend.app.services.scanner import scan
from backend.app.models.models import SecurityAuthorization
from backend.app.services.security_authorization import expire_if_needed, scope_allows, AuthorizationStopped
from backend.app.services.evidence_provenance import extract_and_persist_provenance

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan-job")


def create_job(db, url: str) -> str:
    task_id = f"scan-{uuid4().hex}"
    db.add(BackgroundTaskRun(task_id=task_id, task_name="real_time_scan", status="QUEUED"))
    db.commit()
    return task_id


def _update(db, task_id: str, **values):
    row = db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id == task_id).first()
    if row:
        for key, value in values.items():
            setattr(row, key, value)
        db.commit()


def run_job(task_id: str, url: str, authorization_id: int | None = None, requester_user_id: str | None = None):
    db = SessionLocal()
    try:
        _update(db, task_id, status="RUNNING", started_at=datetime.now(timezone.utc))
        guard = None
        if authorization_id is not None:
            authorization = db.get(SecurityAuthorization, authorization_id)
            if not authorization:
                raise AuthorizationStopped("authorization record not found")
            if requester_user_id and authorization.requester_user_id != requester_user_id:
                raise AuthorizationStopped("authorization belongs to another requester")
            expire_if_needed(db, authorization)
            if not scope_allows(authorization, url):
                raise AuthorizationStopped("scan target is outside the approved authorization scope")

            def guard():
                current = db.get(SecurityAuthorization, authorization_id)
                if not current:
                    raise AuthorizationStopped("authorization record not found")
                expire_if_needed(db, current)
                if not scope_allows(current, url):
                    raise AuthorizationStopped("authorization is no longer valid for this target")

        result = scan(url, db=db, authorization_guard=guard)
        risk = result.get("risk", {})
        row = Scan(
            url=url,
            normalized_url=result["normalized_url"],
            domain=result["domain"],
            risk_score=int(risk.get("score", 0) or 0),
            risk_level=risk.get("level", "Low"),
            result_json=json.dumps(result),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        extract_and_persist_provenance(db, row.id, result, scan_job_id=task_id)
        db.commit()
        _update(
            db,
            task_id,
            status="COMPLETED",
            result_json=json.dumps({"scan_id": row.id, "result": result}),
            completed_at=datetime.now(timezone.utc),
        )
    except Exception as exc:
        db.rollback()
        _update(db, task_id, status="FAILED", error=str(exc)[:255], completed_at=datetime.now(timezone.utc))
    finally:
        db.close()


def submit(task_id: str, url: str, authorization_id: int | None = None, requester_user_id: str | None = None):
    _executor.submit(run_job, task_id, url, authorization_id, requester_user_id)
