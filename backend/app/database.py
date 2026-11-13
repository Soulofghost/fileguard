import sqlite3
from backend.app.config import DB_PATH

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS baselines (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        directory_path TEXT NOT NULL,
        total_files INTEGER NOT NULL DEFAULT 0,
        total_size_bytes INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_records (
        id TEXT PRIMARY KEY,
        baseline_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        mtime REAL NOT NULL,
        permissions TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (baseline_id) REFERENCES baselines(id) ON DELETE CASCADE
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS integrity_alerts (
        id TEXT PRIMARY KEY,
        baseline_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        change_type TEXT NOT NULL CHECK(change_type IN ('MODIFIED', 'CREATED', 'DELETED', 'PERMISSIONS_ALTERED')),
        severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
        expected_hash TEXT,
        actual_hash TEXT,
        details TEXT,
        acknowledged INTEGER NOT NULL DEFAULT 0,
        detected_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (baseline_id) REFERENCES baselines(id) ON DELETE CASCADE
    );
    """)

    conn.commit()

    # Seed demo baseline if empty
    cursor.execute("SELECT COUNT(*) as c FROM baselines;")
    if cursor.fetchone()["c"] == 0:
        seed_data(cursor, conn)

    conn.close()

def seed_data(cursor, conn):
    baseline_id = "base-linux-etc"
    cursor.execute("""
    INSERT INTO baselines (id, name, directory_path, total_files, total_size_bytes)
    VALUES (?, 'Linux /etc System Configuration Baseline', '/etc', 4, 12480);
    """, (baseline_id,))

    demo_files = [
        ("file-1", baseline_id, "/etc/passwd", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 2840, 1731450000.0, "rw-r--r--"),
        ("file-2", baseline_id, "/etc/shadow", "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", 1420, 1731450100.0, "rw-------"),
        ("file-3", baseline_id, "/etc/ssh/sshd_config", "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a", 4120, 1731450200.0, "rw-r--r--"),
        ("file-4", baseline_id, "/etc/sudoers", "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d", 4100, 1731450300.0, "r--r-----")
    ]

    cursor.executemany("""
    INSERT INTO file_records (id, baseline_id, file_path, sha256_hash, size_bytes, mtime, permissions)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    """, demo_files)

    # Seed initial tamper alert
    cursor.execute("""
    INSERT INTO integrity_alerts (id, baseline_id, file_path, change_type, severity, expected_hash, actual_hash, details, acknowledged)
    VALUES ('alt-sec-01', 'base-linux-etc', '/etc/shadow', 'MODIFIED', 'CRITICAL',
            'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35',
            'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
            'Unauthorized credential modification detected in local user database', 0);
    """)

    conn.commit()
