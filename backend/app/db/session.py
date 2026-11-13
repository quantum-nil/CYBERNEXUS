import re
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from pathlib import Path
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.core.config import settings

is_sqlite = settings.database_url.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {"connect_timeout": settings.database_connect_timeout_seconds}
pool_args = {} if is_sqlite else {
    "pool_size": settings.database_pool_size,
    "max_overflow": settings.database_max_overflow,
    "pool_timeout": settings.database_pool_timeout_seconds,
    "pool_pre_ping": True,
}
database_url = settings.database_url
# Render provides PostgreSQL URLs using psycopg2's default dialect. This app
# bundles psycopg v3, so route PostgreSQL connections through its SQLAlchemy driver.
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
engine = create_engine(database_url, connect_args=connect_args, **pool_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def run_migrations():
    migration_dir=Path(__file__).resolve().parents[2] / "migrations"
    with engine.begin() as connection:
        dialect = connection.dialect.name
        connection.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"))
        applied_rows = connection.execute(text("SELECT version FROM schema_migrations")).fetchall()
        applied = {row[0] for row in applied_rows}
        for path in sorted(migration_dir.glob("*.sql")):
            if path.name in applied:
                continue
            for statement in path.read_text(encoding="utf-8").split(";"):
                stmt = statement.strip()
                if not stmt:
                    continue
                if dialect == "postgresql":
                    stmt = re.sub(r'(?i)\bADD\s+COLUMN\s+(?!IF\s+NOT\s+EXISTS\b)', 'ADD COLUMN IF NOT EXISTS ', stmt)
                    if re.match(r'(?i)^\s*INSERT\s+INTO\b', stmt) and "ON CONFLICT" not in stmt.upper():
                        stmt = stmt.rstrip() + " ON CONFLICT DO NOTHING"
                try:
                    # Isolate each statement so a duplicate-column error does
                    # not abort the PostgreSQL transaction for later migrations.
                    with connection.begin_nested():
                        connection.execute(text(stmt))
                except SQLAlchemyError as exc:
                    # Migrations are intentionally idempotent because the
                    # application runs them at startup. SQLite has no
                    # ADD COLUMN IF NOT EXISTS syntax.
                    message = str(exc).lower()
                    if (
                        "duplicate column" not in message
                        and "already exists" not in message
                        and "unique constraint" not in message
                        and "duplicate key" not in message
                    ):
                        raise
            insert_stmt = (
                "INSERT INTO schema_migrations (version) VALUES (:v) ON CONFLICT DO NOTHING"
                if dialect == "postgresql"
                else "INSERT OR IGNORE INTO schema_migrations (version) VALUES (:v)"
            )
            connection.execute(text(insert_stmt), {"v": path.name})
        _install_ledger_guards(connection)

def _install_ledger_guards(connection):
    """Install database-side append-only guards after migrations.

    The application ORM guards are defense in depth. These triggers also stop
    ordinary application-role UPDATE/DELETE statements. A production DBA must
    additionally run the database-specific permission hardening for the app
    role; the database owner/migration role remains trusted.
    """
    dialect = connection.dialect.name
    if dialect == "sqlite":
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS trg_threat_ledger_no_update")
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS trg_threat_ledger_no_delete")
        connection.exec_driver_sql("CREATE TRIGGER trg_threat_ledger_no_update BEFORE UPDATE ON threat_append_only_ledger_events WHEN OLD.event_hash <> 'pending' BEGIN SELECT RAISE(ABORT, 'append-only ledger events cannot be updated'); END")
        connection.exec_driver_sql("CREATE TRIGGER trg_threat_ledger_no_delete BEFORE DELETE ON threat_append_only_ledger_events BEGIN SELECT RAISE(ABORT, 'append-only ledger events cannot be deleted'); END")
    elif dialect == "postgresql":
        connection.exec_driver_sql("CREATE OR REPLACE FUNCTION threat_ledger_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP = 'UPDATE' AND OLD.event_hash = 'pending' THEN RETURN NEW; END IF; RAISE EXCEPTION 'append-only ledger events cannot be changed'; END; $$")
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS trg_threat_ledger_no_update ON threat_append_only_ledger_events")
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS trg_threat_ledger_no_delete ON threat_append_only_ledger_events")
        connection.exec_driver_sql("CREATE TRIGGER trg_threat_ledger_no_update BEFORE UPDATE ON threat_append_only_ledger_events FOR EACH ROW EXECUTE FUNCTION threat_ledger_immutable()")
        connection.exec_driver_sql("CREATE TRIGGER trg_threat_ledger_no_delete BEFORE DELETE ON threat_append_only_ledger_events FOR EACH ROW EXECUTE FUNCTION threat_ledger_immutable()")
