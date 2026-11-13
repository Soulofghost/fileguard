import pytest
from backend.app.engine.fim_engine import FIMEngine

def test_calculate_sha256():
    content = b"Hello, FileGuard Integrity!"
    expected = "c5d5b32ff6a35ab2451dfdf55f7bb309d107e8d84c392683de7f22b8471f0431"
    assert FIMEngine.calculate_sha256(content) == expected

def test_classify_severity():
    # /etc/shadow or /etc/passwd are CRITICAL
    assert FIMEngine.classify_severity("/etc/shadow", "MODIFIED") == "CRITICAL"
    assert FIMEngine.classify_severity("/etc/passwd", "DELETED") == "CRITICAL"

    # Executable scripts are HIGH on modification
    assert FIMEngine.classify_severity("/usr/local/bin/backup.sh", "MODIFIED") == "HIGH"

    # General text file is MEDIUM
    assert FIMEngine.classify_severity("/var/log/app.log", "MODIFIED") == "MEDIUM"

def test_diff_snapshots_detection():
    baseline = {
        "/etc/nginx/nginx.conf": {"sha256_hash": "aaa111", "size_bytes": 1024},
        "/etc/pam.d/common-auth": {"sha256_hash": "bbb222", "size_bytes": 512},
        "/var/www/index.html": {"sha256_hash": "ccc333", "size_bytes": 2048}
    }

    current = {
        # Modified hash
        "/etc/nginx/nginx.conf": {"sha256_hash": "aaa999_TAMPERED", "size_bytes": 1050},
        # /etc/pam.d/common-auth DELETED (missing)
        # /var/www/index.html UNCHANGED
        "/var/www/index.html": {"sha256_hash": "ccc333", "size_bytes": 2048},
        # Newly CREATED file
        "/tmp/malicious_payload.sh": {"sha256_hash": "ddd444", "size_bytes": 8192}
    }

    alerts = FIMEngine.diff_snapshots(baseline, current)
    assert len(alerts) == 3

    types = {a["change_type"] for a in alerts}
    assert types == {"MODIFIED", "DELETED", "CREATED"}

    mod_alert = next(a for a in alerts if a["change_type"] == "MODIFIED")
    assert mod_alert["file_path"] == "/etc/nginx/nginx.conf"
    assert mod_alert["expected_hash"] == "aaa111"
    assert mod_alert["actual_hash"] == "aaa999_TAMPERED"

    del_alert = next(a for a in alerts if a["change_type"] == "DELETED")
    assert del_alert["file_path"] == "/etc/pam.d/common-auth"

    new_alert = next(a for a in alerts if a["change_type"] == "CREATED")
    assert new_alert["file_path"] == "/tmp/malicious_payload.sh"
    assert new_alert["severity"] == "HIGH"
