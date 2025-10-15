import os
import io
from dataclasses import dataclass, field
from typing import List
from PIL import Image, ImageFilter

from utils.hashing import sha256_file
from core.crypto_wallets import find_wallets_in_text, find_wallets_in_image_text
from utils.immutable_logger import append_log

# -----------------------------
# MIME detection: fallback auto
# -----------------------------
try:
    import magic
    def detect_mime(path):
        try:
            return magic.from_file(path, mime=True)
        except Exception:
            return "unknown"
except ImportError:
    import mimetypes
    def detect_mime(path):
        mime, _ = mimetypes.guess_type(path)
        return mime or "unknown"

# -----------------------------
# Data structure
# -----------------------------
@dataclass
class ForensicItem:
    path: str
    hash_sha256: str
    mime: str
    risk_score: float = 0.0
    stego_flag: bool = False
    wallet_matches: List[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

# -----------------------------
# Scanner
# -----------------------------
class FileScanner:
    def __init__(self, root_path, generate_thumbnails=True, dry_run=False):
        self.root = root_path
        self.results = []
        self.generate_thumbnails = generate_thumbnails
        self.dry_run = dry_run

    def _safe_thumbnail(self, path, size=(256, 256), blur_radius=12):
        try:
            im = Image.open(path)
            im.thumbnail(size)
            im = im.filter(ImageFilter.GaussianBlur(blur_radius))
            buf = io.BytesIO()
            im.save(buf, format="JPEG")
            buf.seek(0)
            return buf.read()
        except Exception:
            return None

    def scan(self):
        append_log({"event": "scan_start", "path": self.root})
        for dirpath, _, files in os.walk(self.root):
            for file in files:
                full_path = os.path.join(dirpath, file)
                try:
                    mime = detect_mime(full_path)

                    if self.dry_run:
                        sha = "DRY"
                    else:
                        sha = sha256_file(full_path)

                    item = ForensicItem(path=full_path, hash_sha256=sha, mime=mime)

                    # ---- Wallet search in text ----
                    if mime and mime.startswith("text"):
                        try:
                            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                txt = f.read()
                            wallets = find_wallets_in_text(txt)
                            item.wallet_matches.extend(wallets)
                        except Exception:
                            pass

                    # ---- Image processing ----
                    if mime and mime.startswith("image"):
                        if self.generate_thumbnails and not self.dry_run:
                            thumb = self._safe_thumbnail(full_path)
                            if thumb:
                                # salva só um preview em hex truncado
                                item.meta["thumbnail_blurred_hex"] = thumb.hex()[:512]

                        try:
                            img_wallets = find_wallets_in_image_text(full_path)
                            item.wallet_matches.extend(img_wallets)
                        except Exception:
                            pass

                    # ---- Heuristics for risk ----
                    if item.wallet_matches:
                        item.risk_score = max(item.risk_score, 0.15)
                    if mime and mime.startswith("image"):
                        item.risk_score = max(item.risk_score, 0.4)

                    self.results.append(item)
                    append_log({"event": "file_scanned", "path": full_path, "sha256": sha})

                except Exception as e:
                    append_log({"event": "scan_error", "path": full_path, "error": str(e)})

        append_log({"event": "scan_complete", "path": self.root, "total": len(self.results)})
        return self.results
