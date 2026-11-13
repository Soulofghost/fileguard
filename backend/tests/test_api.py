import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database import init_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["service"] == "FileGuard"

def test_stats_and_baselines_listing():
    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200
    assert res_stats.json()["hashingAlgorithm"] == "SHA-256"

    res_base = client.get("/api/baselines")
    assert res_base.status_code == 200
    assert len(res_base.json()["baselines"]) >= 1

def test_baseline_creation_and_scan_workflow():
    # 1. Create Baseline
    create_res = client.post("/api/baselines", json={
        "name": "Production Webroot Baseline",
        "directory_path": "/var/www/production"
    })
    assert create_res.status_code == 201
    baseline_id = create_res.json()["id"]

    # 2. Get baseline details
    detail_res = client.get(f"/api/baselines/{baseline_id}")
    assert detail_res.status_code == 200
    assert len(detail_res.json()["files"]) == 3

    # 3. Trigger integrity scan with a tampered file
    scan_res = client.post("/api/scan", json={
        "baseline_id": baseline_id,
        "files_snapshot": [
            # Modify first file hash
            {"file_path": f"/var/www/production/core_config.conf", "sha256_hash": "TAMPERED_HASH_99999", "size_bytes": 1050},
            # Second file unchanged
            {"file_path": f"/var/www/production/auth_service.py", "content": "import hashlib\n"},
            # Third file deleted (omitted)
            # Fourth file created
            {"file_path": f"/var/www/production/backdoor.php", "sha256_hash": "BACKDOOR_HASH_12345", "size_bytes": 4096}
        ]
    })

    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["anomalies_detected"] >= 2

    # 4. Check alerts endpoint
    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    assert len(alerts_res.json()["alerts"]) >= 1

    first_alert = alerts_res.json()["alerts"][0]
    ack_res = client.post(f"/api/alerts/{first_alert['id']}/ack")
    assert ack_res.status_code == 200
    assert ack_res.json()["acknowledged"] is True
