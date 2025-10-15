# core/win_registry.py
# Offline NTUSER.DAT parser with python-registry fallback.
# pip install python-registry

import os
import datetime
import codecs

def _rot13(s: str) -> str:
    return codecs.decode(s, 'rot_13')

def _try_python_registry(hive_path: str):
    try:
        from Registry import Registry
    except Exception:
        return None

    out = {"hive": hive_path, "typed_urls": [], "run_mru": [], "typed_paths": [], "userassist": []}
    try:
        reg = Registry.Registry(hive_path)

        # TypedURLs
        try:
            key = reg.open("Software\\Microsoft\\Internet Explorer\\TypedURLs")
            for v in key.values():
                if v.name().lower().startswith("url"):
                    out["typed_urls"].append(v.value())
        except Exception:
            pass

        # RunMRU
        try:
            key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
            order = ""
            for v in key.values():
                if v.name() == "MRUList":
                    order = v.value()
            for v in key.values():
                if len(v.name()) == 1:  # single-letter entries
                    out["run_mru"].append(v.value())
        except Exception:
            pass

        # TypedPaths
        try:
            key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
            for v in key.values():
                out["typed_paths"].append(v.value())
        except Exception:
            pass

        # UserAssist (names ROT13; simple listing of program names)
        try:
            ua_root = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
            for sub in ua_root.subkeys():
                try:
                    count = sub.open("Count")
                except Exception:
                    continue
                for v in count.values():
                    name = _rot13(v.name())  # ROT13
                    out["userassist"].append(name)
        except Exception:
            pass

        return out
    except Exception:
        return out

def parse_ntuser_hive(hive_path: str) -> dict:
    """
    Parse offline NTUSER.DAT and return basic artifacts.
    """
    if not hive_path or not os.path.exists(hive_path):
        return {"error": "NTUSER hive not found"}
    parsed = _try_python_registry(hive_path)
    if parsed is not None:
        return parsed
    # Fallback: library missing
    return {"hive": hive_path, "error": "python-registry not installed. pip install python-registry"}
