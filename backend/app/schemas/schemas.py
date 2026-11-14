from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field, HttpUrl

class ScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    # Required when production scan authorization enforcement is enabled.
    authorization_id: int | None = Field(default=None, ge=1)
    allowed_categories: list[str] | None = None
    scan_mode: str = Field(default="PUBLIC_PASSIVE")
    tenant_id: str = Field(default="default")

class ReportRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    reason: str = Field(min_length=3, max_length=255)
    details: str = Field(default="", max_length=2000)

class ReportOut(ReportRequest):
    id: int
    status: str
    created_at: datetime
    class Config: from_attributes = True

class LinkRevisionRequest(BaseModel):
    report_id: int | None = None
    revision_id: int | None = None

class VerifyHashRequest(BaseModel):
    payload: Any = None
    expected_hash: str
