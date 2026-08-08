import sqlite3

from smtp_bench_pro.persistence.database import SMTPDatabase, SCHEMA_VERSION


def test_migrates_v1_database_to_v2(tmp_path) -> None:
    db_path = tmp_path / "smtp-v1.db"
    with sqlite3.connect(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE benchmark_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                iterations INTEGER NOT NULL,
                timeout REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE smtp_results (
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
            PRAGMA user_version = 1;
            """
        )

    SMTPDatabase(db_path).initialize()

    with sqlite3.connect(db_path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        columns = {row[1] for row in connection.execute("PRAGMA table_info(smtp_results)").fetchall()}
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

    assert version == SCHEMA_VERSION
    assert "capabilities_before_tls_json" in columns
    assert "auth_after_tls_json" in columns
    assert "command_diagnostics_json" in columns
    run_columns = {row[1] for row in sqlite3.connect(db_path).execute("PRAGMA table_info(benchmark_runs)").fetchall()}
    assert "diagnostics_profile" in run_columns
    assert "diagnostics_options_json" in run_columns
    assert "smtp_diagnostics" in tables
    assert "security_findings" in tables
