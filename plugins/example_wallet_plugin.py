# simple plugin example
from core.crypto_wallets import find_wallets_in_text

def scan(path, context):
    try:
        if path.lower().endswith((".txt", ".log", ".cfg", ".json")):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
            matches = find_wallets_in_text(txt)
            return {"wallets": matches}
        return {"skipped": True}
    except Exception as e:
        return {"error": str(e)}
