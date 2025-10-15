# core/video_frames.py
import os, subprocess, tempfile
from typing import List

def extract_scene_frames(video_path: str, out_dir: str=None, scene_th=0.3, limit=50) -> List[str]:
    """
    Extract frames where scene change > threshold using ffmpeg.
    Returns list of frame paths (png).
    """
    out = out_dir or tempfile.mkdtemp(prefix="frames_")
    try:
        cmd = [
            "ffmpeg", "-hide_banner", "-loglevel", "error",
            "-i", video_path,
            "-vf", f"select='gt(scene,{scene_th})',showinfo",
            "-vsync", "vfr",
            os.path.join(out, "frame_%06d.png")
        ]
        subprocess.run(cmd, check=True)
    except Exception:
        return []
    frames = sorted([os.path.join(out, f) for f in os.listdir(out) if f.lower().endswith(".png")])[:limit]
    return frames
