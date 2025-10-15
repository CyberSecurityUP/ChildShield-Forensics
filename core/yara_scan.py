# core/yara_scan.py
# pip install yara-python
import os
from typing import List, Dict

def compile_rules(rule_file: str):
    try:
        import yara
    except Exception as e:
        raise RuntimeError("yara-python required") from e
    return yara.compile(filepath=rule_file)

def scan_paths(rule, paths: List[str], max_hits=5) -> Dict[str, List[str]]:
    hits = {}
    for p in paths:
        try:
            if os.path.isfile(p):
                m = rule.match(p)
                if m:
                    hits[p] = [str(x) for x in m][:max_hits]
        except Exception:
            pass
    return hits
