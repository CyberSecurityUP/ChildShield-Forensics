import math
from utils.immutable_logger import append_log

def estimate_entropy(data: bytes):
    if not data:
        return 0.0
    from collections import Counter
    counts = Counter(data)
    probs = [c/len(data) for c in counts.values()]
    import math
    return -sum(p*math.log2(p) for p in probs)

def lsb_analysis(path):
    # Placeholder: read image bytes and inspect LSB distribution heuristics
    try:
        with open(path, "rb") as f:
            b = f.read(4096)
        ent = estimate_entropy(b)
        suspicious = ent > 7.5  # heuristic
        append_log({"event":"stego_check","path":path,"entropy":ent,"suspicious":suspicious})
        return {"entropy": ent, "suspicious": suspicious}
    except Exception as e:
        append_log({"event":"stego_error","path":path,"error":str(e)})
        return {"entropy": 0, "suspicious": False}
