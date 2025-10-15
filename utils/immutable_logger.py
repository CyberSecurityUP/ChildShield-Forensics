import os
import json
import hmac
import hashlib
from datetime import datetime

LOG_DIR = os.path.join(os.getcwd(), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "audit.log")
# In production, key management must be secure (HSM/KMS). This is a demo key.
_HMAC_KEY = os.environ.get("FORNSIC_HMAC_KEY", "replace-with-secure-key").encode()

def append_log(event: dict):
    """
    Append event with timestamp and hmac signature. File is append-only.
    """
    event = dict(event)  # copy
    event["timestamp_utc"] = datetime.utcnow().isoformat() + "Z"
    raw = json.dumps(event, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()
    record = {"payload": event, "hmac_sha256": sig}
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record
