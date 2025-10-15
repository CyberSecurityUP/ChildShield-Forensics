# core/ads.py
import sys, os
from typing import List, Dict
if sys.platform.startswith("win"):
    import ctypes
    from ctypes import wintypes

def list_streams(path: str) -> List[Dict]:
    """
    Enumerate NTFS ADS for a file (Windows only).
    Returns [{'name': 'Zone.Identifier:$DATA', 'size': 123}...]
    """
    if not sys.platform.startswith("win"): return []
    FindFirstStreamW = ctypes.windll.kernel32.FindFirstStreamW
    FindNextStreamW  = ctypes.windll.kernel32.FindNextStreamW
    FindClose = ctypes.windll.kernel32.FindClose

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", wintypes.LARGE_INTEGER),
                    ("cStreamName", wintypes.WCHAR * 296)]
    data = WIN32_FIND_STREAM_DATA()
    h = FindFirstStreamW(wintypes.LPCWSTR(path), 0, ctypes.byref(data), 0)
    if h == -1 or h == 0:
        return []
    streams = []
    try:
        while True:
            name = data.cStreamName
            if name and name != "::$DATA":
                streams.append({"name": name, "size": data.StreamSize.QuadPart})
            if not FindNextStreamW(h, ctypes.byref(data)):
                break
    finally:
        FindClose(h)
    return streams
