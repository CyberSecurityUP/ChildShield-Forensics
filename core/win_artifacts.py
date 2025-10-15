# core/win_artifacts.py
# Enumerate Prefetch, Jump Lists; hint for Amcache
import os
from glob import glob

def list_prefetch(root="C:\\Windows\\Prefetch") -> list:
    try:
        if os.path.isdir(root):
            return sorted([os.path.basename(p) for p in glob(os.path.join(root, "*.pf"))])
    except Exception:
        pass
    return []

def collect_jump_lists(user_profile: str) -> list:
    """
    List Jump List files under the user's profile:
    %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations
    """
    try:
        auto = os.path.join(user_profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "AutomaticDestinations")
        custom = os.path.join(user_profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "CustomDestinations")
        files = []
        for d in (auto, custom):
            if os.path.isdir(d):
                files.extend(sorted([os.path.basename(p) for p in glob(os.path.join(d, "*.*"))]))
        return files
    except Exception:
        return []

def amcache_hint() -> bool:
    """
    Returns True if Amcache.hve default path exists.
    """
    try:
        path = os.path.join("C:\\", "Windows", "AppCompat", "Programs", "Amcache.hve")
        return os.path.exists(path)
    except Exception:
        return False
