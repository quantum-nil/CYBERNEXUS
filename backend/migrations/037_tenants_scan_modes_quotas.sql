-- Migration 037: Tenants, Scan Modes, Ownership Isolation, and Abuse Quotas
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(64) DEFAULT 'free',
    max_concurrent_jobs INTEGER DEFAULT 10,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tenant_members (
    id INTEGER PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(128) NOT NULL,
    role VARCHAR(32) DEFAULT 'member',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rate_limit_records (
    id INTEGER PRIMARY KEY,
    client_key VARCHAR(128) NOT NULL,
    window_bucket VARCHAR(64) NOT NULL,
    request_count INTEGER DEFAULT 1,
    last_request_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS abuse_events (
    id INTEGER PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    client_ip VARCHAR(64),
    tenant_id VARCHAR(64),
    user_id VARCHAR(128),
    details_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Migration history table for Phase 5
CREATE TABLE IF NOT EXISTS schema_migration_history (
    version VARCHAR(255) PRIMARY KEY,
    checksum VARCHAR(64),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status VARCHAR(32) DEFAULT 'COMPLETED',
    error TEXT
);

-- Add tenant and scan mode columns to scans and scan_jobs if missing
ALTER TABLE scans ADD COLUMN scan_mode VARCHAR(40) DEFAULT 'PUBLIC_PASSIVE';
ALTER TABLE scans ADD COLUMN tenant_id VARCHAR(64) DEFAULT 'default';
ALTER TABLE scans ADD COLUMN created_by VARCHAR(128) DEFAULT 'anonymous';
ALTER TABLE scans ADD COLUMN authorization_state VARCHAR(40) DEFAULT 'NOT_REQUIRED';
