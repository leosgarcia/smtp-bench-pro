"""SQLite schema management."""

from __future__ import annotations

from pathlib import Path
import sqlite3

from smtp_bench_pro.paths import database_path

SCHEMA_VERSION = 4


class SMTPDatabase:
    """Owns SMTP Bench Pro's standalone database."""

    def __init__(self, path: Path | None = None):
        self.path = path or database_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version == 0:
                self._create_v1(connection)
                version = 1
            if version < 2:
                self._migrate_v2(connection)
                version = 2
            if version < 3:
                self._migrate_v3(connection)
                version = 3
            if version < 4:
                self._migrate_v4(connection)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def _create_v1(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS benchmark_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                iterations INTEGER NOT NULL,
                timeout REAL NOT NULL,
                diagnostics_profile TEXT NOT NULL DEFAULT 'safe',
                diagnostics_options_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS smtp_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL REFERENCES benchmark_runs(id) ON DELETE CASCADE,
                hostname TEXT NOT NULL,
                resolved_ip TEXT,
                port INTEGER NOT NULL,
                security_mode TEXT NOT NULL,
                success INTEGER NOT NULL,
                status TEXT NOT NULL,
                error_type TEXT,
                error_message TEXT,
                tcp_connect_ms REAL,
                banner_ms REAL,
                ehlo_ms REAL,
                starttls_ms REAL,
                tls_handshake_ms REAL,
                total_ms REAL,
                banner TEXT,
                ehlo_hostname TEXT,
                capabilities_json TEXT NOT NULL DEFAULT '{}',
                tls_json TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

    def _migrate_v2(self, connection: sqlite3.Connection) -> None:
        existing_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(smtp_results)").fetchall()
        }
        additions = {
            "capabilities_before_tls_json": "TEXT NOT NULL DEFAULT '{}'",
            "capabilities_after_tls_json": "TEXT NOT NULL DEFAULT '{}'",
            "auth_before_tls_json": "TEXT NOT NULL DEFAULT '[]'",
            "auth_after_tls_json": "TEXT NOT NULL DEFAULT '[]'",
            "command_responses_json": "TEXT NOT NULL DEFAULT '{}'",
        }
        for column, definition in additions.items():
            if column not in existing_columns:
                connection.execute(f"ALTER TABLE smtp_results ADD COLUMN {column} {definition}")

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS smtp_diagnostics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL REFERENCES benchmark_runs(id) ON DELETE CASCADE,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL,
                security_mode TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS security_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL REFERENCES benchmark_runs(id) ON DELETE CASCADE,
                finding_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                port INTEGER NOT NULL,
                security_mode TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

    def _migrate_v3(self, connection: sqlite3.Connection) -> None:
        run_columns = {row[1] for row in connection.execute("PRAGMA table_info(benchmark_runs)").fetchall()}
        run_additions = {
            "diagnostics_profile": "TEXT NOT NULL DEFAULT 'safe'",
            "diagnostics_options_json": "TEXT NOT NULL DEFAULT '{}'",
        }
        for column, definition in run_additions.items():
            if column not in run_columns:
                connection.execute(f"ALTER TABLE benchmark_runs ADD COLUMN {column} {definition}")

        result_columns = {row[1] for row in connection.execute("PRAGMA table_info(smtp_results)").fetchall()}
        if "command_diagnostics_json" not in result_columns:
            connection.execute(
                "ALTER TABLE smtp_results ADD COLUMN command_diagnostics_json TEXT NOT NULL DEFAULT '[]'"
            )

    def _migrate_v4(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS mail_dns_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL UNIQUE REFERENCES benchmark_runs(id) ON DELETE CASCADE,
                domain TEXT NOT NULL,
                mx_json TEXT NOT NULL,
                ptr_json TEXT NOT NULL,
                spf_json TEXT NOT NULL,
                dmarc_json TEXT NOT NULL,
                identity_summary_json TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_mail_dns_runs_run_id ON mail_dns_runs(run_id);
            CREATE INDEX IF NOT EXISTS idx_mail_dns_runs_domain ON mail_dns_runs(domain);
            """
        )
