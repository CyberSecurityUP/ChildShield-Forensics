# core/timeline.py
from typing import List, Dict
from datetime import datetime

def merge_timeline(events: List[Dict]) -> List[Dict]:
    """
    Input: list of events {ts: datetime|int|str, src: 'prefetch'|'browser'|..., desc: '...', path: '...'}
    Output: sorted list by ts (ISO string).
    """
    norm = []
    for e in events:
        ts = e.get("ts")
        if isinstance(ts, (int, float)):
            ts = datetime.utcfromtimestamp(ts)
        elif isinstance(ts, str):
            try: ts = datetime.fromisoformat(ts)
            except Exception: ts = None
        if isinstance(ts, datetime):
            ts = ts.isoformat() + "Z"
        norm.append({**e, "ts": ts})
    return sorted(norm, key=lambda x: (x.get("ts") or ""))
