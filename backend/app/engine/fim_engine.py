import os
import hashlib
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Tuple

CRITICAL_PATHS = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "sshd_config", "id_rsa", ".env", "nginx.conf"]
HIGH_RISK_EXTS = [".sh", ".py", ".bin", ".so", ".exe", ".dll", ".service", ".conf"]

class FIMEngine:
    @staticmethod
    def calculate_sha256(content_bytes: bytes) -> str:
        return hashlib.sha256(content_bytes).hexdigest()

    @staticmethod
    def hash_local_file(file_path: Path) -> str:
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()

    @staticmethod
    def classify_severity(file_path_str: str, change_type: str) -> str:
        norm = file_path_str.replace("\\", "/").lower()

        # Critical files
        for crit in CRITICAL_PATHS:
            if crit.lower() in norm:
                return "CRITICAL"

        # Check high-risk executables & configs
        for ext in HIGH_RISK_EXTS:
            if norm.endswith(ext):
                return "HIGH"

        if change_type == "DELETED":
            return "HIGH"

        return "MEDIUM"

    @classmethod
    def diff_snapshots(
        cls,
        baseline_files: Dict[str, dict], # { path: { hash, size, mtime } }
        current_files: Dict[str, dict]
    ) -> List[dict]:
        alerts = []

        # Check for Modified and Deleted files
        for path, base_rec in baseline_files.items():
            if path not in current_files:
                severity = cls.classify_severity(path, "DELETED")
                alerts.append({
                    "id": str(uuid.uuid4()),
                    "file_path": path,
                    "change_type": "DELETED",
                    "severity": severity,
                    "expected_hash": base_rec.get("sha256_hash"),
                    "actual_hash": None,
                    "details": f"File removed from monitored directory (expected size: {base_rec.get('size_bytes', 0)} bytes)"
                })
            else:
                curr_rec = current_files[path]
                if curr_rec["sha256_hash"] != base_rec["sha256_hash"]:
                    severity = cls.classify_severity(path, "MODIFIED")
                    alerts.append({
                        "id": str(uuid.uuid4()),
                        "file_path": path,
                        "change_type": "MODIFIED",
                        "severity": severity,
                        "expected_hash": base_rec["sha256_hash"],
                        "actual_hash": curr_rec["sha256_hash"],
                        "details": f"Cryptographic integrity breach: SHA-256 hash changed from {base_rec['sha256_hash'][:8]}... to {curr_rec['sha256_hash'][:8]}..."
                    })

        # Check for Newly Created files
        for path, curr_rec in current_files.items():
            if path not in baseline_files:
                severity = cls.classify_severity(path, "CREATED")
                alerts.append({
                    "id": str(uuid.uuid4()),
                    "file_path": path,
                    "change_type": "CREATED",
                    "severity": severity,
                    "expected_hash": None,
                    "actual_hash": curr_rec["sha256_hash"],
                    "details": f"Unauthorized new file created in monitored directory (size: {curr_rec.get('size_bytes', 0)} bytes)"
                })

        return alerts
