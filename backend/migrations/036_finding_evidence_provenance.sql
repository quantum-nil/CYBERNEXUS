-- Phase 6.6: Centralized evidence provenance for findings.
CREATE TABLE IF NOT EXISTS finding_evidence_provenance (
  id INTEGER PRIMARY KEY,
  finding_id VARCHAR(120) NOT NULL,
  source_provider VARCHAR(120) NOT NULL,
  source_type VARCHAR(80) NOT NULL,
  observed_at TIMESTAMP NOT NULL,
  checked_at TIMESTAMP NOT NULL,
  confidence VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN',
  provider_status VARCHAR(40) NOT NULL DEFAULT 'UNKNOWN',
  evidence_reference VARCHAR(1024),
  content_hash VARCHAR(64) NOT NULL,
  scan_job_id VARCHAR(120),
  scan_id INTEGER,
  report_id INTEGER,
  revision_id INTEGER,
  title VARCHAR(255) DEFAULT '',
  explanation TEXT DEFAULT '',
  why_it_exists TEXT DEFAULT '',
  severity VARCHAR(30) DEFAULT 'INFO',
  is_current BOOLEAN NOT NULL DEFAULT 1,
  evidence_payload_json TEXT DEFAULT '{}',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(scan_id) REFERENCES scans(id),
  FOREIGN KEY(report_id) REFERENCES threat_intelligence_reports(id),
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id)
);
CREATE INDEX IF NOT EXISTS ix_finding_evidence_provenance_finding ON finding_evidence_provenance(finding_id);
CREATE INDEX IF NOT EXISTS ix_finding_evidence_provenance_hash ON finding_evidence_provenance(content_hash);
CREATE INDEX IF NOT EXISTS ix_finding_evidence_provenance_job ON finding_evidence_provenance(scan_job_id);
CREATE INDEX IF NOT EXISTS ix_finding_evidence_provenance_scan ON finding_evidence_provenance(scan_id);
CREATE INDEX IF NOT EXISTS ix_finding_evidence_provenance_report ON finding_evidence_provenance(report_id);
CREATE INDEX IF NOT EXISTS ix_finding_evidence_provenance_rev ON finding_evidence_provenance(revision_id);
