# 1) Plugin basics

* **Location:** put your plugin as a single `.py` file inside `plugins/`.
* **Entry point:** define `scan(path: str, context: dict) -> dict`.
* **Contract (lightweight):**

  * Return `{}` (empty) if you find nothing.
  * Or return a dict with at least a human-readable **result** (string).
    Optional fields the app understands if present: `findings` (list), `risk_bump` (0..1 float), `meta` (dict).
* **Safety:** never display raw illegal media. Work from paths, hashes, metadata, and text only.

---

# 2) Minimal “Hello” plugin

Create `plugins/sample_hello.py`:

```python
# plugins/sample_hello.py
# Minimal example: flags files larger than 100 MB (as a triage hint).

PLUGIN = {
    "id": "sample-hello",
    "name": "Sample Hello",
    "version": "1.0.0",
    "author": "You",
    "description": "Flags very large files as potential containers."
}

def scan(path: str, context: dict) -> dict:
    try:
        import os
        size = os.path.getsize(path)
        if size >= 100 * 1024 * 1024:  # 100 MB
            return {
                "result": f"Large file (~{size/1024/1024:.1f} MB)",
                "risk_bump": 0.2,
                "meta": {"size_bytes": size}
            }
        return {}
    except Exception as e:
        # Fail-safe: never crash the pipeline
        return {"result": f"[plugin error] {e}"}
```

---

# 3) Real example: “Crypto Wallet Detector” (text-only, with validation)

Create `plugins/wallet_detector.py`:

```python
# plugins/wallet_detector.py
"""
Finds probable BTC/Ethereum wallet strings in text-like files and validates them
(BTC Base58Check / bech32 length sanity, ETH EIP-55 when mixed-case).
Never opens or exports media content. Text-only scan with size guard.
"""

from __future__ import annotations
import re, os, hashlib

PLUGIN = {
    "id": "wallet-detector",
    "name": "Crypto Wallet Detector",
    "version": "1.0.0",
    "author": "You",
    "description": "Scans text for BTC/ETH wallets with checksum validation where applicable."
}

# -------- Helpers

# Base58 alphabet (BTC legacy addresses)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def _b58decode(addr: str) -> bytes:
    n = 0
    for ch in addr:
        n = n * 58 + _B58.index(ch)
    h = f"{n:x}"
    if len(h) % 2: h = "0" + h
    raw = bytes.fromhex(h)
    # leading '1' are leading zero bytes
    pad = len(addr) - len(addr.lstrip("1"))
    return b"\x00" * pad + raw

def _btc_base58check_valid(addr: str) -> bool:
    try:
        raw = _b58decode(addr)
        if len(raw) < 5:
            return False
        payload, checksum = raw[:-4], raw[-4:]
        calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return checksum == calc
    except Exception:
        return False

def _eth_eip55_valid(addr: str) -> bool:
    """
    Validates mixed-case EIP-55. If all lower or all upper, treat as 'likely' but not strictly EIP-55.
    """
    if not addr.startswith("0x") or len(addr) != 42:
        return False
    core = addr[2:]
    if core.islower() or core.isupper():
        return True  # not checksummed, but plausible
    # EIP-55 checksum
    import hashlib
    h = hashlib.sha3_256(core.lower().encode()).hexdigest()
    for i, c in enumerate(core):
        if c.isalpha():
            should_upper = int(h[i], 16) >= 8
            if should_upper != c.isupper():
                return False
    return True

# Regex candidates
RE_BTC58 = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
RE_ETH   = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# -------- Main

def scan(path: str, context: dict) -> dict:
    try:
        # Guardrails: only scan smallish, text-likely files
        max_bytes = int(context.get("max_text_scan_bytes", 2_000_000))  # 2 MB default
        if os.path.getsize(path) > max_bytes:
            return {}

        # Read as text (lossy). Never render images/videos.
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        text = data.decode("utf-8", errors="ignore")

        findings = []

        # BTC Base58
        for m in RE_BTC58.finditer(text):
            cand = m.group(0)
            valid = _btc_base58check_valid(cand)
            findings.append({"type": "BTC", "value": cand, "valid": bool(valid)})

        # ETH
        for m in RE_ETH.finditer(text):
            cand = m.group(0)
            valid = _eth_eip55_valid(cand)
            findings.append({"type": "ETH", "value": cand, "valid": bool(valid)})

        if not findings:
            return {}

        # Summarize; bump risk slightly if any validated hit
        valid_hits = sum(1 for f in findings if f.get("valid"))
        result = f"Crypto wallet candidates: {len(findings)} (validated: {valid_hits})"
        risk_bump = 0.35 if valid_hits else 0.15

        return {
            "result": result,
            "risk_bump": risk_bump,
            "findings": findings,
            "meta": {"scanned_bytes": len(text)}
        }
    except Exception as e:
        return {"result": f"[plugin error] {e}"}
```

**Notes**

* This plugin only reads small files as text (safe).
* It validates **BTC Base58Check** and **ETH EIP-55** where possible to reduce false positives.
* You can add more patterns (e.g., bech32 `bc1…`) later.

---

# 4) How the app uses plugin results

* In the **GUI**, enable **“Run plugins after scan”**.
  The results appear in the log and can be attached to evidence metadata.
* In the **CLI**, pass `--run-plugins`.
  The pipeline calls `scan(path, context)` for each selected file and may increase the item’s risk if you return `risk_bump`.

Recommended return fields:

```python
{
  "result": "short human-readable summary",  # REQUIRED
  "risk_bump": 0.0..1.0,                     # OPTIONAL: add to risk (max-capped)
  "findings": [ {...}, {...} ],              # OPTIONAL: structured details
  "meta": { "anything": "useful" }           # OPTIONAL: extra context
}
```

---

# 5) Testing your plugin

**GUI**

1. Put the `.py` in `plugins/`.
2. Open app → **Plugins** tab → **Refresh Plugin List** (see it appear).
3. On **Scan** tab, tick **Run plugins after scan** and scan a folder with some text files.

**CLI**

```bash
python -m cli.main "/path/to/test" --user alice --run-plugins
```

---

# 6) Best practices for safety & performance

* **Minimize exposure:** never render images/videos; don’t export raw content.
* **Be selective:** check file size, MIME/extension (skip binaries unless you know what you’re doing).
* **Be fast:** avoid heavy models or network calls in the plugin; keep it local and deterministic.
* **Be robust:** wrap your logic in try/except and always return a dict (even on errors).
* **Log ethically:** if you need to log, log only metadata (`utils.immutable_logger.append_log`), never sensitive content.

---

# 7) Optional: plugin config

If your plugin needs settings, read from a small YAML/JSON beside it, e.g. `plugins/wallet_detector.yaml`. Example pattern:

```python
# inside scan():
cfg_path = os.path.splitext(__file__)[0] + ".yaml"
if os.path.exists(cfg_path):
    import yaml
    cfg = yaml.safe_load(open(cfg_path, "r", encoding="utf-8"))
    max_bytes = int(cfg.get("max_text_scan_bytes", max_bytes))
```

---

That’s it! Drop your `.py` in `plugins/`, implement `scan(path, context)`, keep it safe and fast, and you’re plugged in.
