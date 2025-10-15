# core/browsers.py
import os, shutil, sqlite3
from typing import List, Dict

def _safe_copy(src: str) -> str:
    tmp = src + ".forensic_copy"
    shutil.copy2(src, tmp)
    return tmp

def chrome_history(profile_dir: str) -> List[Dict]:
    """
    Parse Chrome/Edge history DB (History SQLite) from profile_dir.
    Returns list of {url, title, last_visit_time}.
    """
    hist = os.path.join(profile_dir, "History")
    if not os.path.exists(hist): return []
    db = _safe_copy(hist)
    out = []
    try:
        con = sqlite3.connect(db)
        cur = con.cursor()
        cur.execute("""
            SELECT url, title, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 1000
        """)
        for url, title, ts in cur.fetchall():
            out.append({"url": url, "title": title, "last_visit_time": ts})
        con.close()
    except Exception:
        pass
    try: os.remove(db)
    except Exception: pass
    return out
