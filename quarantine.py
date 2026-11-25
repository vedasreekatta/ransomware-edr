import json
from datetime import datetime
from pathlib import Path

QUARANTINE_DIR = Path("quarantine")
LOG_FILE = QUARANTINE_DIR / "quarantine_log.json"
RESTORED_DIR = Path("uploads") / "restored"


def _ensure_dirs() -> None:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    RESTORED_DIR.mkdir(parents=True, exist_ok=True)
    if not LOG_FILE.exists():
        LOG_FILE.write_text("[]", encoding="utf-8")


def load_quarantine_records() -> list[dict]:
    _ensure_dirs()
    try:
        return json.loads(LOG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save_quarantine_records(records: list[dict]) -> None:
    _ensure_dirs()
    LOG_FILE.write_text(json.dumps(records, indent=2), encoding="utf-8")


def quarantine_file(
    filename: str,
    file_bytes: bytes,
    sha256_hash: str,
    risk_score: int,
    risk_level: str,
    reason: str,
) -> dict:
    """
    Safely isolate suspicious binary bytes inside quarantine/ with a non-executable
    '.quarantined' extension so Windows cannot accidentally execute it.
    """
    _ensure_dirs()
    safe_name = Path(filename).name
    vault_filename = f"{sha256_hash[:16]}_{safe_name}.quarantined"
    vault_path = QUARANTINE_DIR / vault_filename
    vault_path.write_bytes(file_bytes)

    records = load_quarantine_records()
    record = {
        "id": f"QTN-{sha256_hash[:10].upper()}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "original_filename": safe_name,
        "vault_filename": vault_filename,
        "sha256": sha256_hash,
        "size_bytes": len(file_bytes),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reason": reason,
        "status": "QUARANTINED",
    }

    # Replace existing entry with same SHA-256 if already quarantined
    records = [r for r in records if r.get("sha256") != sha256_hash]
    records.insert(0, record)
    _save_quarantine_records(records)
    return record


def restore_quarantined_file(item_id: str) -> tuple[bool, str]:
    """Restore a quarantined file into uploads/restored/ for authorized inspection."""
    records = load_quarantine_records()
    for rec in records:
        if rec.get("id") == item_id and rec.get("status") == "QUARANTINED":
            vault_path = QUARANTINE_DIR / rec["vault_filename"]
            if not vault_path.exists():
                return False, "Quarantined vault file missing on disk."
            target = RESTORED_DIR / rec["original_filename"]
            target.write_bytes(vault_path.read_bytes())
            vault_path.unlink(missing_ok=True)
            rec["status"] = "RESTORED"
            rec["restored_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _save_quarantine_records(records)
            return True, f"Restored safely to {target}"
    return False, "Quarantine record not found or already processed."


def delete_quarantined_file(item_id: str) -> tuple[bool, str]:
    """Permanently purge a quarantined sample from the vault."""
    records = load_quarantine_records()
    for rec in records:
        if rec.get("id") == item_id:
            vault_path = QUARANTINE_DIR / rec["vault_filename"]
            vault_path.unlink(missing_ok=True)
            rec["status"] = "PURGED"
            rec["purged_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _save_quarantine_records(records)
            return True, f"Permanently purged {rec['original_filename']} from vault."
    return False, "Quarantine record not found."