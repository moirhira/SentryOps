"""
scanner.db — SQLite persistence package for SentryOps.
"""

from scanner.db.schema import get_connection, init_db, generate_scan_id
from scanner.db.store import save_scan, list_scans, get_scan, get_findings_for_package

__all__ = [
    "get_connection",
    "init_db",
    "generate_scan_id",
    "save_scan",
    "list_scans",
    "get_scan",
    "get_findings_for_package",
]
