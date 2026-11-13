import uuid
import datetime
from fastapi import APIRouter, HTTPException, status
from typing import Optional, List

from backend.app.database import get_connection
from backend.app.schemas import CreateBaselineRequest, ScanDirectoryRequest, AcknowledgeAlertRequest
from backend.app.engine.fim_engine import FIMEngine

router = APIRouter(prefix="/api", tags=["fim"])

@router.get("/health")
def healthcheck():
    return {
        "status": "ok",
        "service": "FileGuard",
        "version": "1.0.0",
        "engine": "SHA-256 Recursive Integrity Engine"
    }

@router.get("/stats")
def get_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as c FROM baselines;")
    total_baselines = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM file_records;")
    total_files_monitored = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM integrity_alerts WHERE acknowledged = 0;")
    active_alerts = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM integrity_alerts WHERE severity = 'CRITICAL' AND acknowledged = 0;")
    critical_breaches = cursor.fetchone()["c"]

    conn.close()

    return {
        "totalBaselines": total_baselines,
        "filesMonitored": total_files_monitored,
        "activeAlerts": active_alerts,
        "criticalBreaches": critical_breaches,
        "hashingAlgorithm": "SHA-256",
        "enforcement": "Zero-Trust Cryptographic Baseline"
    }

@router.get("/baselines")
def list_baselines():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM baselines ORDER BY created_at DESC;")
    rows = cursor.fetchall()
    conn.close()

    return {
        "total": len(rows),
        "baselines": [dict(r) for r in rows]
    }

@router.get("/baselines/{baseline_id}")
def get_baseline_detail(baseline_id: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM baselines WHERE id = ?;", (baseline_id,))
    base_row = cursor.fetchone()
    if not base_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Baseline not found")

    cursor.execute("SELECT * FROM file_records WHERE baseline_id = ? ORDER BY file_path ASC;", (baseline_id,))
    files = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM integrity_alerts WHERE baseline_id = ? ORDER BY detected_at DESC;", (baseline_id,))
    alerts = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return {
        **dict(base_row),
        "files": files,
        "alerts": alerts
    }

@router.post("/baselines", status_code=status.HTTP_201_CREATED)
def create_baseline(payload: CreateBaselineRequest):
    conn = get_connection()
    cursor = conn.cursor()

    baseline_id = "base-" + str(uuid.uuid4())[:8]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Create dummy initial files if local directory scanning in virtual environment
    demo_records = [
        (str(uuid.uuid4()), baseline_id, f"{payload.directory_path}/core_config.conf", FIMEngine.calculate_sha256(b"core_app_settings=true\n"), 1024, 1731450000.0, "rw-r--r--"),
        (str(uuid.uuid4()), baseline_id, f"{payload.directory_path}/auth_service.py", FIMEngine.calculate_sha256(b"import hashlib\n"), 2048, 1731450100.0, "rwxr-xr-x"),
        (str(uuid.uuid4()), baseline_id, f"{payload.directory_path}/secrets.env", FIMEngine.calculate_sha256(b"DATABASE_KEY=prod_vault\n"), 512, 1731450200.0, "rw-------")
    ]

    total_bytes = sum(r[4] for r in demo_records)
    cursor.execute("""
    INSERT INTO baselines (id, name, directory_path, total_files, total_size_bytes, created_at)
    VALUES (?, ?, ?, ?, ?, ?);
    """, (baseline_id, payload.name, payload.directory_path, len(demo_records), total_bytes, now_iso))

    cursor.executemany("""
    INSERT INTO file_records (id, baseline_id, file_path, sha256_hash, size_bytes, mtime, permissions)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    """, demo_records)

    conn.commit()
    conn.close()

    return {
        "id": baseline_id,
        "name": payload.name,
        "directory_path": payload.directory_path,
        "total_files": len(demo_records),
        "total_size_bytes": total_bytes,
        "created_at": now_iso
    }

@router.post("/scan")
def scan_directory(payload: ScanDirectoryRequest):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM baselines WHERE id = ?;", (payload.baseline_id,))
    base_row = cursor.fetchone()
    if not base_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Baseline not found")

    cursor.execute("SELECT file_path, sha256_hash, size_bytes, mtime FROM file_records WHERE baseline_id = ?;", (payload.baseline_id,))
    baseline_records = {r["file_path"]: dict(r) for r in cursor.fetchall()}

    # If payload provided custom files snapshot, use that; otherwise simulate a test tamper check
    current_files = {}
    if payload.files_snapshot:
        for f in payload.files_snapshot:
            current_files[f["file_path"]] = {
                "sha256_hash": f.get("sha256_hash", FIMEngine.calculate_sha256(f.get("content", "").encode())),
                "size_bytes": f.get("size_bytes", 100),
                "mtime": f.get("mtime", 1731450000.0)
            }
    else:
        # Default scan against existing baseline (simulate clean or slight anomaly)
        current_files = dict(baseline_records)

    diff_alerts = FIMEngine.diff_snapshots(baseline_records, current_files)

    # Insert newly detected alerts
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for alt in diff_alerts:
        cursor.execute("""
        INSERT INTO integrity_alerts (id, baseline_id, file_path, change_type, severity, expected_hash, actual_hash, details, acknowledged, detected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?);
        """, (alt["id"], payload.baseline_id, alt["file_path"], alt["change_type"], alt["severity"], alt["expected_hash"], alt["actual_hash"], alt["details"], now_iso))

    conn.commit()
    conn.close()

    return {
        "baseline_id": payload.baseline_id,
        "scanned_files_count": len(current_files),
        "anomalies_detected": len(diff_alerts),
        "alerts": diff_alerts,
        "scan_timestamp": now_iso
    }

@router.get("/alerts")
def list_alerts(limit: int = 50):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM integrity_alerts ORDER BY detected_at DESC LIMIT ?;", (limit,))
    rows = cursor.fetchall()
    conn.close()

    return {
        "total": len(rows),
        "alerts": [dict(r) for r in rows]
    }

@router.post("/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE integrity_alerts SET acknowledged = 1 WHERE id = ?;", (alert_id,))
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    conn.commit()
    conn.close()

    return {"status": "success", "alert_id": alert_id, "acknowledged": True}
