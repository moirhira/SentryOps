"""
SentryOps SQLite persistence layer.

Provides schema creation, row insertion, and query helpers.
Database file: sentryops.db in the project working directory.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Default database path (can be overridden via get_connection)
DEFAULT_DB_PATH = Path("sentryops.db")

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    id               TEXT PRIMARY KEY,
    started_at       TEXT NOT NULL,
    duration         REAL,
    target           TEXT NOT NULL,
    target_type      TEXT NOT NULL,
    scan_types       TEXT,                  -- JSON array: ["host", "application"]
    os               TEXT,
    scanner_version  TEXT NOT NULL,
    status           TEXT DEFAULT 'completed'
);

CREATE TABLE IF NOT EXISTS packages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    version          TEXT NOT NULL,
    ecosystem        TEXT NOT NULL,
    package_manager  TEXT NOT NULL,
    source_type      TEXT NOT NULL          -- "dpkg", "rpm", "requirements.txt", "package.json", "Dockerfile"
);

CREATE TABLE IF NOT EXISTS findings (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id              TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    package_id           INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,

    vulnerability_id     TEXT NOT NULL,     -- e.g. "DEBIAN-CVE-2026-1234" or "GHSA-xxxx"
    installed_version    TEXT NOT NULL,
    fixed_version        TEXT,              -- NULL means no fix available

    severity             TEXT,             -- "CRITICAL", "HIGH", "MEDIUM", "LOW"
    status               TEXT,             -- "affected"

    ecosystem            TEXT NOT NULL,    -- "Debian:13", "PyPI", "npm"

    range_introduced     TEXT,             -- "0" or specific version
    range_fixed          TEXT,             -- NULL if no fix in advisory

    comparator           TEXT,             -- "dpkg" or "semver"
    vulnerability_source TEXT,             -- "dpkg", "requirements.txt", etc.
    summary              TEXT,
    reference_url        TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_started_at   ON scans(started_at);
CREATE INDEX IF NOT EXISTS idx_packages_scan_id   ON packages(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id   ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_id   ON findings(vulnerability_id);
"""


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode and foreign key enforcement."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Create all tables and indexes if they do not exist."""
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)


def generate_scan_id() -> str:
    """Generate a unique scan ID: scan-<date>-<short-uuid>."""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    short = uuid.uuid4().hex[:8]
    return f"scan-{today}-{short}"
