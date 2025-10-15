import platform
import psutil
import subprocess
import os
import json

def collect_basic_system_info():
    info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "hostname": platform.node(),
        "cpu_count": psutil.cpu_count(),
        "memory_total": psutil.virtual_memory().total,
        "users": [u.name for u in psutil.users()],
    }
    return info

def check_bitlocker_windows():
    if platform.system().lower() != "windows":
        return {"bitlocker": None}
    try:
        out = subprocess.check_output(["manage-bde", "-status"], stderr=subprocess.DEVNULL, text=True)
        return {"bitlocker": out}
    except Exception as e:
        return {"bitlocker_error": str(e)}
