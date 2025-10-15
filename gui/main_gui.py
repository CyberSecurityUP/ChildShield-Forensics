import sys
import os
import json
from typing import List, Optional

from PyQt5.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QVariant, pyqtSignal, QThread,
    QSortFilterProxyModel, QSettings, QUrl, QTimer
)
from PyQt5.QtGui import QDesktopServices, QPixmap
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog,
    QTextEdit, QLineEdit, QLabel, QTabWidget, QTableView, QComboBox, QCheckBox,
    QMessageBox, QDialog, QFormLayout, QGridLayout, QProgressDialog, QSplashScreen, QProgressBar,
    QAction
)

from core.scanner import FileScanner  # uses fallback mime
from utils.auth import authenticate, create_user
from utils.immutable_logger import append_log
from core.reports import generate_reports
from core.plugins import discover_plugins, run_plugins_on_path
from core.win_registry import parse_ntuser_hive
from core.win_artifacts import collect_jump_lists, list_prefetch, amcache_hint
from core.evtx_reader import read_evtx_quick
from core.timeline import merge_timeline

# Optional: additional analysis (stubs)
try:
    from core.classifier import nsfw_score_image, gore_score_image, deepfake_score_image
except Exception:
    def nsfw_score_image(_):
        return 0.0
    def gore_score_image(_):
        return 0.0
    def deepfake_score_image(_):
        return 0.0

try:
    from core.stego import lsb_analysis
except Exception:
    def lsb_analysis(_):
        return {"entropy": 0, "suspicious": False}

# Advanced modules (best-effort imports)
try:
    from core.hashsets import HashDB
except Exception:
    HashDB = None
try:
    from core.ads import list_streams
except Exception:
    def list_streams(_):
        return []
try:
    from core.browsers import chrome_history
except Exception:
    def chrome_history(_):
        return []
try:
    from core.yara_scan import compile_rules, scan_paths
except Exception:
    def compile_rules(_):
        raise RuntimeError("yara-python not installed")
    def scan_paths(*_, **__):
        return {}

APP_TITLE = "Investigator GUI"

# -----------------------------
# Fancy pre-login loading dialog
# -----------------------------
class BootDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Initializing…")
        self.setModal(True)
        self.resize(520, 260)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        v = QVBoxLayout(self)
        title = QLabel("Starting Investigator Toolkit")
        title.setStyleSheet("font-size:18px;font-weight:600;")
        subtitle = QLabel("Preparing a safe, private workspace…")
        subtitle.setStyleSheet("color:gray;")
        self.bar = QProgressBar(); self.bar.setRange(0, 0)  # busy
        self.status = QLabel("Initializing components…")

        v.addStretch(1)
        v.addWidget(title, alignment=Qt.AlignHCenter)
        v.addWidget(subtitle, alignment=Qt.AlignHCenter)
        v.addSpacing(10)
        v.addWidget(self.bar)
        v.addSpacing(8)
        v.addWidget(self.status, alignment=Qt.AlignHCenter)
        creator = QLabel("Created by Joas A Santos")
        creator.setStyleSheet("color:gray;font-size:11px;")
        v.addSpacing(10)
        v.addWidget(creator, alignment=Qt.AlignHCenter)
        v.addStretch(2)

        self._steps = [
            "Loading configuration…",
            "Verifying dependencies…",
            "Initializing plugin system…",
            "Checking cryptographic modules…",
            "Finalizing setup…",
        ]
        self._i = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(650)

    def _tick(self):
        if self._i < len(self._steps):
            self.status.setText(self._steps[self._i])
            self._i += 1
        else:
            self._timer.stop()
            self.accept()

# -----------------------------
# Registration & Authentication dialogs
# -----------------------------
class RegisterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Register New Operator")
        self.created_username = None
        form = QFormLayout(self)
        self.ed_user = QLineEdit()
        self.ed_pass = QLineEdit(); self.ed_pass.setEchoMode(QLineEdit.Password)
        self.ed_conf = QLineEdit(); self.ed_conf.setEchoMode(QLineEdit.Password)
        self.cmb_role = QComboBox(); self.cmb_role.addItems(["analyst", "admin"]) 
        form.addRow("Username", self.ed_user)
        form.addRow("Password", self.ed_pass)
        form.addRow("Confirm Password", self.ed_conf)
        form.addRow("Role", self.cmb_role)
        btns = QHBoxLayout(); ok = QPushButton("Create"); cancel = QPushButton("Cancel")
        btns.addWidget(ok); btns.addWidget(cancel)
        form.addRow(btns)
        ok.clicked.connect(self.do_create)
        cancel.clicked.connect(self.reject)

    def do_create(self):
        u = self.ed_user.text().strip()
        p = self.ed_pass.text()
        c = self.ed_conf.text()
        if not u or not p:
            QMessageBox.warning(self, "Register", "Username and password are required.")
            return
        if p != c:
            QMessageBox.warning(self, "Register", "Passwords do not match.")
            return
        try:
            create_user(u, p, role=self.cmb_role.currentText())
            QMessageBox.information(self, "Register", "User created successfully.")
            self.created_username = u
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Register", f"Failed to create user: {e}")

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Operator Login")
        self.username = None
        self.role = None

        layout = QFormLayout(self)
        self.user_edit = QLineEdit()
        self.pass_edit = QLineEdit(); self.pass_edit.setEchoMode(QLineEdit.Password)
        layout.addRow("Username", self.user_edit)
        layout.addRow("Password", self.pass_edit)

        btns = QHBoxLayout()
        ok = QPushButton("Login")
        register = QPushButton("Register")
        cancel = QPushButton("Cancel")
        btns.addWidget(ok); btns.addWidget(register); btns.addWidget(cancel)
        layout.addRow(btns)
        ok.clicked.connect(self.do_login)
        register.clicked.connect(self.open_register)
        cancel.clicked.connect(self.reject)

    def do_login(self):
        from utils.auth import authenticate
        u = self.user_edit.text().strip(); p = self.pass_edit.text()
        ok, role = authenticate(u, p)
        if not ok:
            QMessageBox.warning(self, "Authentication", "Invalid username or password.")
            return
        self.username = u; self.role = role
        append_log({"event": "gui_auth", "user": u, "role": role})
        self.accept()

    def open_register(self):
        dlg = RegisterDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            self.user_edit.setText(dlg.created_username or "")

# -----------------------------
# Legal checklist dialog
# -----------------------------
class LegalDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Legal & Authorization Checklist")
        self.case_id = ""; self.authority = ""; self.authorization_ref = ""

        form = QFormLayout(self)
        self.case_edit = QLineEdit(); self.auth_edit = QLineEdit(); self.ref_edit = QLineEdit()
        self.chk_authorized = QCheckBox("I am legally authorized to run this tool for this case.")
        self.chk_notice = QCheckBox("I have read the legal notice: no raw redistribution of illicit content.")
        self.chk_min = QCheckBox("I will minimize exposure (blurred thumbnails, hashes, metadata-only exports).")

        form.addRow("Case ID", self.case_edit)
        form.addRow("Authority / Unit", self.auth_edit)
        form.addRow("Authorization Ref.", self.ref_edit)
        form.addRow(self.chk_authorized)
        form.addRow(self.chk_notice)
        form.addRow(self.chk_min)

        btns = QHBoxLayout(); ok = QPushButton("Confirm"); cancel = QPushButton("Cancel")
        btns.addWidget(ok); btns.addWidget(cancel)
        form.addRow(btns)
        ok.clicked.connect(self.confirm)
        cancel.clicked.connect(self.reject)

    def confirm(self):
        if not (self.chk_authorized.isChecked() and self.chk_notice.isChecked() and self.chk_min.isChecked()):
            QMessageBox.warning(self, "Checklist", "Please confirm all legal checkboxes.")
            return
        self.case_id = self.case_edit.text().strip()
        self.authority = self.auth_edit.text().strip()
        self.authorization_ref = self.ref_edit.text().strip()
        append_log({"event": "legal_checklist", "case_id": self.case_id, "authority": self.authority, "authorization_ref": self.authorization_ref, "confirmed": True})
        self.accept()

# -----------------------------
# Scan worker thread
# -----------------------------
class ScanWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(list, dict)

    def __init__(self, path: str, options: dict, parent=None):
        super().__init__(parent)
        self.path = path
        self.options = options

    def _load_hashdb(self):
        if not self.options.get("hashsets_enabled") or HashDB is None:
            return None
        db = HashDB()
        sha_file = self.options.get("sha256_file") or ""
        ph_file = self.options.get("phash_file") or ""
        try:
            if sha_file and os.path.exists(sha_file):
                with open(sha_file, "r", encoding="utf-8", errors="ignore") as f:
                    db.import_sha256_list(f)
                self.progress.emit("Loaded SHA-256 hashset.")
            if ph_file and os.path.exists(ph_file):
                with open(ph_file, "r", encoding="utf-8", errors="ignore") as f:
                    db.import_phash_list(f)
                self.progress.emit("Loaded perceptual hashset.")
            return db
        except Exception as e:
            self.progress.emit(f"[!] HashDB load error: {e}")
            return None

    def _build_timeline(self, artifacts):
        events = []
        # Browser history events (Chromium timestamps)
        browser = artifacts.get("browser") or []
        for it in browser:
            ts = it.get("last_visit_time")
            # Chromium stores microseconds since 1601-01-01
            try:
                base = 11644473600  # seconds between 1601 and 1970
                unix = (int(ts) / 1_000_000) - base
                events.append({
                    "ts": unix,
                    "src": "browser",
                    "desc": it.get("title") or it.get("url"),
                    "path": it.get("url"),
                })
            except Exception:
                continue
        return merge_timeline(events)

    def run(self):
        try:
            self.progress.emit(f"Starting scan: {self.path}")
            scanner = FileScanner(self.path, generate_thumbnails=self.options.get("thumbnails", True), dry_run=self.options.get("dry_run", False))
            items = scanner.scan()

            # Optional post-processing
            do_stego = self.options.get("stego", False)
            do_class = self.options.get("classification", False)

            # Custom model (loaded in worker thread)
            custom_model = None
            cm_cfg = self.options.get("custom_model") or {}
            if do_class and cm_cfg.get("enabled"):
                try:
                    from core.custom_model import ModelLoader
                    custom_model = ModelLoader(cm_cfg.get("type"), cm_cfg.get("path"))
                    self.progress.emit("Custom model loaded for classification.")
                except Exception as e:
                    self.progress.emit(f"[!] Custom model load failed: {e}")
                    custom_model = None

            # HashDB (optional)
            hashdb = self._load_hashdb()

            # YARA (optional)
            yara_rule = None
            if self.options.get("yara_enabled"):
                try:
                    rf = self.options.get("yara_rules")
                    if rf:
                        yara_rule = compile_rules(rf)
                        self.progress.emit("YARA rules compiled.")
                except Exception as e:
                    self.progress.emit(f"[!] YARA compile error: {e}")

            # Iterate items
            for it in items:
                # classification
                if do_class and it.mime and it.mime.startswith("image"):
                    if custom_model is not None:
                        try:
                            nsfw = float(custom_model.score_image(it.path))
                        except Exception as e:
                            nsfw = 0.0
                            self.progress.emit(f"[!] Model error on {os.path.basename(it.path)}: {e}")
                    else:
                        nsfw = nsfw_score_image(it.path)
                    gore = gore_score_image(it.path)
                    deep = deepfake_score_image(it.path)
                    it.risk_score = max(it.risk_score, nsfw, gore, deep)
                # stego
                if do_stego and it.mime and it.mime.startswith("image"):
                    res = lsb_analysis(it.path)
                    it.stego_flag = bool(res.get("suspicious"))
                # hashsets
                if hashdb:
                    meta = it.meta or {}
                    if it.mime and it.mime.startswith("image"):
                        try:
                            import imagehash, PIL.Image as Image
                            ph = str(imagehash.phash(Image.open(it.path)))
                            meta["phash"] = ph
                            ok, dist = hashdb.match_phash(ph)
                            if ok:
                                meta["phash_match"] = True; meta["phash_dist"] = dist
                                it.risk_score = max(it.risk_score, 0.9 if dist == 0 else 0.85)
                        except Exception:
                            pass
                    if it.hash_sha256 and len(it.hash_sha256) == 64 and it.hash_sha256 != "DRY":
                        try:
                            if hashdb.match_sha256(it.hash_sha256):
                                meta["sha256_match"] = True
                                it.risk_score = max(it.risk_score, 1.0)
                        except Exception:
                            pass
                    it.meta = meta
                # ADS
                if self.options.get("ads_enabled"):
                    try:
                        ads = list_streams(it.path) or []
                        if ads:
                            it.meta["ads"] = ads
                            it.risk_score = max(it.risk_score, 0.55)
                    except Exception:
                        pass

            # -------- Windows & browser artifacts
            artifacts = {}
            if self.options.get("win_deep"):
                try:
                    ntuser_path = self.options.get("ntuser_path")
                    if ntuser_path:
                        artifacts['ntuser'] = parse_ntuser_hive(ntuser_path)
                    evtx_dir = self.options.get("evtx_dir")
                    if evtx_dir:
                        artifacts['evtx'] = read_evtx_quick(evtx_dir, max_events=200)
                    profile = self.options.get("user_profile")
                    if profile:
                        artifacts['jumplists'] = collect_jump_lists(profile)
                    artifacts['prefetch'] = list_prefetch()
                    artifacts['amcache_hint'] = amcache_hint()
                except Exception as e:
                    self.progress.emit(f"[!] Windows deep artifacts error: {e}")

            if self.options.get("browser_enabled"):
                prof = self.options.get("browser_profile")
                if prof:
                    try:
                        artifacts['browser'] = chrome_history(prof)
                        self.progress.emit("Browser history parsed.")
                    except Exception as e:
                        self.progress.emit(f"[!] Browser parse error: {e}")

            # YARA scan on paths (limit)
            if yara_rule:
                try:
                    # limit to first 200 files for UI responsiveness
                    paths = [i.path for i in items[:200]]
                    yh = scan_paths(yara_rule, paths)
                    artifacts['yara_hits'] = yh
                    # annotate items
                    for it in items:
                        lst = yh.get(it.path)
                        if lst:
                            it.meta.setdefault("yara_hits", lst)
                            it.risk_score = max(it.risk_score, 0.7)
                    self.progress.emit("YARA scan complete.")
                except Exception as e:
                    self.progress.emit(f"[!] YARA scan error: {e}")

            # Timeline
            timeline = self._build_timeline(artifacts)

            summary = {
                "total": len(items),
                "high": sum(1 for i in items if i.risk_score >= 0.8),
                "medium": sum(1 for i in items if 0.5 <= i.risk_score < 0.8),
                "low": sum(1 for i in items if i.risk_score < 0.5),
                "artifacts": artifacts,
                "timeline": timeline,
            }
            self.finished.emit(items, summary)
        except Exception as e:
            self.progress.emit(f"[!] Error: {e}")
            self.finished.emit([], {"total": 0, "high": 0, "medium": 0, "low": 0, "artifacts": {}, "timeline": []})

# -----------------------------
# Evidence & Timeline models
# -----------------------------
COLUMNS = ["Path", "SHA-256", "MIME", "Risk", "HashHit", "YARA", "ADS"]

class EvidenceModel(QAbstractTableModel):
    def __init__(self, items: List[dict] = None):
        super().__init__()
        self._items = items or []

    def rowCount(self, parent=QModelIndex()):
        return len(self._items)

    def columnCount(self, parent=QModelIndex()):
        return len(COLUMNS)

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or role not in (Qt.DisplayRole, Qt.ToolTipRole):
            return QVariant()
        it = self._items[index.row()]
        col = index.column()
        meta = it.get("meta") or {}
        if col == 0:
            return it.get("path", "")
        if col == 1:
            return it.get("hash_sha256", "")
        if col == 2:
            return it.get("mime", "")
        if col == 3:
            return f"{it.get('risk_score', 0.0):.2f}"
        if col == 4:
            if meta.get("sha256_match"):
                return "SHA256"
            if meta.get("phash_match"):
                d = meta.get("phash_dist", "?")
                return f"pHash~ (d={d})"
            return ""
        if col == 5:
            yh = meta.get("yara_hits")
            return ", ".join(yh) if isinstance(yh, list) else ("Yes" if yh else "")
        if col == 6:
            ads = meta.get("ads")
            return str(len(ads)) if ads else "0"
        return QVariant()

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section]
        return super().headerData(section, orientation, role)

    def set_items(self, items: List[dict]):
        self.beginResetModel(); self._items = items; self.endResetModel()

    def item_at(self, row: int) -> Optional[dict]:
        if 0 <= row < len(self._items):
            return self._items[row]
        return None

class EvidenceFilter(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self._risk = "All"; self._text = ""

    def set_risk(self, risk: str):
        self._risk = risk; self.invalidateFilter()

    def set_text(self, text: str):
        self._text = text.lower(); self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        model: EvidenceModel = self.sourceModel()
        it = model.item_at(source_row)
        if not it:
            return True
        r = float(it.get("risk_score", 0.0))
        if self._risk == "High" and not (r >= 0.8):
            return False
        if self._risk == "Medium" and not (0.5 <= r < 0.8):
            return False
        if self._risk == "Low" and not (r < 0.5):
            return False
        if self._text:
            meta = it.get("meta") or {}
            hay = (it.get("path", "") + " " + (it.get("mime", "") or "") + " " + json.dumps(meta)).lower()
            return self._text in hay
        return True

# Timeline model
TL_COLS = ["Time", "Source", "Description", "Path"]
class TimelineModel(QAbstractTableModel):
    def __init__(self, rows=None):
        super().__init__(); self.rows = rows or []
    def rowCount(self, parent=QModelIndex()): return len(self.rows)
    def columnCount(self, parent=QModelIndex()): return len(TL_COLS)
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole: return QVariant()
        r = self.rows[index.row()]; c = index.column()
        if c == 0: return r.get("ts", "")
        if c == 1: return r.get("src", "")
        if c == 2: return r.get("desc", "")
        if c == 3: return r.get("path", "")
        return QVariant()
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return TL_COLS[section]
        return super().headerData(section, orientation, role)
    def set_rows(self, rows):
        self.beginResetModel(); self.rows = rows; self.endResetModel()

# -----------------------------
# Main Window
# -----------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1280, 860)

        self.settings = QSettings("ForensicToolkit", "InvestigatorGUI")
        self.operator = None
        self.case_meta = {}
        self.last_report_paths = None

        self.tabs = QTabWidget(); self.setCentralWidget(self.tabs)
        self._init_dashboard_tab()
        self._init_scan_tab()
        self._init_evidence_tab()
        self._init_timeline_tab()
        self._init_reports_tab()
        self._init_plugins_tab()
        self._init_settings_tab()
        self._init_menu()
        self._request_login_and_legal()

    # ---------- Dashboard
    def _init_dashboard_tab(self):
        w = QWidget(); v = QVBoxLayout(w)
        self.lbl_summary = QLabel("No scan yet.")
        self.btn_open_reports_dir = QPushButton("Open Reports Folder")
        self.btn_open_reports_dir.clicked.connect(self.open_reports_dir)
        v.addWidget(QLabel("Dashboard"))
        v.addWidget(self.lbl_summary)
        v.addWidget(self.btn_open_reports_dir)
        v.addStretch(1)
        self.tabs.addTab(w, "Dashboard")

    # ---------- Scan tab
    def _init_scan_tab(self):
        w = QWidget(); grid = QGridLayout(w)

        self.ed_path = QLineEdit(); self.btn_browse = QPushButton("Browse…"); self.btn_browse.clicked.connect(self.choose_folder)
        grid.addWidget(QLabel("Target directory"), 0, 0); grid.addWidget(self.ed_path, 0, 1); grid.addWidget(self.btn_browse, 0, 2)

        # Options
        self.chk_thumbs = QCheckBox("Generate blurred thumbnails (safe)"); self.chk_thumbs.setChecked(True)
        self.chk_class = QCheckBox("Enable image classification (NSFW/gore/deepfake — stub/custom)")
        self.chk_stego = QCheckBox("Enable steganography heuristics")
        self.chk_plugins = QCheckBox("Run plugins after scan")
        self.chk_dry = QCheckBox("Dry-run (no hashing, no writes)")
        grid.addWidget(self.chk_thumbs, 1, 0, 1, 3)
        grid.addWidget(self.chk_class, 2, 0, 1, 3)
        grid.addWidget(self.chk_stego, 3, 0, 1, 3)
        grid.addWidget(self.chk_plugins, 4, 0, 1, 3)
        grid.addWidget(self.chk_dry, 5, 0, 1, 3)

        # Windows artifacts
        self.chk_win_deep = QCheckBox("Collect Windows deep artifacts (Registry/EVTX/Prefetch/Jump Lists)")
        grid.addWidget(self.chk_win_deep, 6, 0, 1, 3)
        self.ed_ntuser = QLineEdit(); self.btn_ntuser = QPushButton("NTUSER.DAT…"); self.btn_ntuser.clicked.connect(self.choose_ntuser)
        self.ed_evtx = QLineEdit(); self.btn_evtx = QPushButton("EVTX dir…"); self.btn_evtx.clicked.connect(self.choose_evtx)
        self.ed_profile = QLineEdit(); self.btn_profile = QPushButton("User profile…"); self.btn_profile.clicked.connect(self.choose_profile)
        grid.addWidget(QLabel("NTUSER.DAT (offline)"), 7, 0); grid.addWidget(self.ed_ntuser, 7, 1); grid.addWidget(self.btn_ntuser, 7, 2)
        grid.addWidget(QLabel("Event Logs folder (.evtx)"), 8, 0); grid.addWidget(self.ed_evtx, 8, 1); grid.addWidget(self.btn_evtx, 8, 2)
        grid.addWidget(QLabel("User Profile (JumpLists)"), 9, 0); grid.addWidget(self.ed_profile, 9, 1); grid.addWidget(self.btn_profile, 9, 2)

        # Advanced triage: Hashsets, YARA, ADS, Browser
        self.chk_hashsets = QCheckBox("Enable hash intelligence (SHA-256 / perceptual hashes)")
        self.ed_sha256 = QLineEdit(); self.btn_sha256 = QPushButton("SHA256 list…"); self.btn_sha256.clicked.connect(self.choose_sha)
        self.ed_phash = QLineEdit(); self.btn_phash = QPushButton("pHash list…"); self.btn_phash.clicked.connect(self.choose_phash)
        grid.addWidget(self.chk_hashsets, 10, 0, 1, 3)
        grid.addWidget(QLabel("SHA-256 list"), 11, 0); grid.addWidget(self.ed_sha256, 11, 1); grid.addWidget(self.btn_sha256, 11, 2)
        grid.addWidget(QLabel("pHash list"), 12, 0); grid.addWidget(self.ed_phash, 12, 1); grid.addWidget(self.btn_phash, 12, 2)

        self.chk_yara = QCheckBox("Enable YARA scan (triage)")
        self.ed_yara = QLineEdit(); self.btn_yara = QPushButton("YARA rules…"); self.btn_yara.clicked.connect(self.choose_yara)
        grid.addWidget(self.chk_yara, 13, 0, 1, 3)
        grid.addWidget(QLabel("Rule file"), 14, 0); grid.addWidget(self.ed_yara, 14, 1); grid.addWidget(self.btn_yara, 14, 2)

        self.chk_ads = QCheckBox("Scan NTFS Alternate Data Streams (ADS)")
        grid.addWidget(self.chk_ads, 15, 0, 1, 3)

        self.chk_browser = QCheckBox("Collect browser artifacts (Chromium history)")
        self.ed_browser = QLineEdit(); self.btn_browser = QPushButton("Profile dir…"); self.btn_browser.clicked.connect(self.choose_browser)
        grid.addWidget(self.chk_browser, 16, 0, 1, 3)
        grid.addWidget(QLabel("Profile directory"), 17, 0); grid.addWidget(self.ed_browser, 17, 1); grid.addWidget(self.btn_browser, 17, 2)

        self.btn_scan = QPushButton("Start Scan"); self.btn_scan.clicked.connect(self.start_scan)
        grid.addWidget(self.btn_scan, 18, 0, 1, 3)

        self.txt_log = QTextEdit(); self.txt_log.setReadOnly(True)
        grid.addWidget(self.txt_log, 19, 0, 1, 3)
        self.tabs.addTab(w, "Scan")

    # ---------- Evidence tab
    def _init_evidence_tab(self):
        w = QWidget(); v = QVBoxLayout(w)
        top = QHBoxLayout()
        self.cmb_risk = QComboBox(); self.cmb_risk.addItems(["All", "High", "Medium", "Low"])
        self.ed_search = QLineEdit(); self.ed_search.setPlaceholderText("Search path/MIME/meta…")
        self.btn_open_dir = QPushButton("Open File Location")
        self.btn_view_detail = QPushButton("View Details (sandbox)")
        self.btn_run_plugins_sel = QPushButton("Run Plugins on Selected")
        top.addWidget(QLabel("Risk filter:")); top.addWidget(self.cmb_risk); top.addWidget(self.ed_search)
        top.addWidget(self.btn_open_dir); top.addWidget(self.btn_view_detail); top.addWidget(self.btn_run_plugins_sel)

        self.model = EvidenceModel([])
        self.proxy = EvidenceFilter(); self.proxy.setSourceModel(self.model)
        self.tbl = QTableView(); self.tbl.setModel(self.proxy)
        self.tbl.setSelectionBehavior(QTableView.SelectRows)
        self.tbl.setSelectionMode(QTableView.SingleSelection)
        self.tbl.setSortingEnabled(True)

        v.addLayout(top); v.addWidget(self.tbl)
        self.tabs.addTab(w, "Evidence")

        self.cmb_risk.currentTextChanged.connect(self.proxy.set_risk)
        self.ed_search.textChanged.connect(self.proxy.set_text)
        self.btn_open_dir.clicked.connect(self.open_selected_location)
        self.btn_view_detail.clicked.connect(self.view_selected_details)
        self.btn_run_plugins_sel.clicked.connect(self.run_plugins_selected)

    # ---------- Timeline tab
    def _init_timeline_tab(self):
        w = QWidget(); v = QVBoxLayout(w)
        self.timeline_model = TimelineModel([])
        self.timeline_tbl = QTableView(); self.timeline_tbl.setModel(self.timeline_model)
        self.btn_export_timeline = QPushButton("Export Timeline JSON")
        self.btn_export_timeline.clicked.connect(self.export_timeline)
        v.addWidget(self.timeline_tbl)
        v.addWidget(self.btn_export_timeline)
        self.tabs.addTab(w, "Timeline")

    # ---------- Reports tab
    def _init_reports_tab(self):
        w = QWidget(); v = QVBoxLayout(w)
        self.ed_report_base = QLineEdit(); self.ed_report_base.setPlaceholderText("report")
        self.btn_generate_reports = QPushButton("Generate HTML & JSON Report")
        self.lbl_reports_out = QLabel("")
        v.addWidget(QLabel("Report basename")); v.addWidget(self.ed_report_base)
        v.addWidget(self.btn_generate_reports); v.addWidget(self.lbl_reports_out)
        self.btn_generate_reports.clicked.connect(self.generate_reports_now)
        self.tabs.addTab(w, "Reports")

    # ---------- Plugins tab
    def _init_plugins_tab(self):
        w = QWidget(); v = QVBoxLayout(w)
        self.lbl_plugins = QLabel("Plugins:")
        self.txt_plugins = QTextEdit(); self.txt_plugins.setReadOnly(True)
        self.btn_list_plugins = QPushButton("Refresh Plugin List"); self.btn_list_plugins.clicked.connect(self.refresh_plugins)
        v.addWidget(self.lbl_plugins); v.addWidget(self.txt_plugins); v.addWidget(self.btn_list_plugins)
        self.tabs.addTab(w, "Plugins")
        self.refresh_plugins()

    # ---------- Settings tab (Custom Model)
    def _init_settings_tab(self):
        w = QWidget(); form = QFormLayout(w)
        # External API
        self.ed_ai_api_key = QLineEdit(); self.ed_ai_api_key.setEchoMode(QLineEdit.Password)
        self.chk_external_upload = QCheckBox("Require explicit confirmation before any external upload")
        self.chk_external_upload.setChecked(True)
        form.addRow("aiornot / external API key", self.ed_ai_api_key)
        form.addRow(self.chk_external_upload)

        # Custom image model
        self.chk_custom_model = QCheckBox("Enable custom image model for classification")
        self.cmb_model_type = QComboBox(); self.cmb_model_type.addItems(["python_module", "onnx"]) 
        self.ed_model_path = QLineEdit(); self.btn_model_browse = QPushButton("Browse…"); self.btn_model_browse.clicked.connect(self.choose_model_file)
        self.btn_model_test = QPushButton("Load/Test Model"); self.btn_model_test.clicked.connect(self.test_model_load)
        self.lbl_model_status = QLabel("Model: not loaded")

        form.addRow(self.chk_custom_model)
        form.addRow("Model type", self.cmb_model_type)
        hl = QHBoxLayout(); hl.addWidget(self.ed_model_path); hl.addWidget(self.btn_model_browse)
        form.addRow("Model file / module", hl)
        form.addRow(self.btn_model_test)
        form.addRow(self.lbl_model_status)

        btn_save = QPushButton("Save Settings"); btn_save.clicked.connect(self.save_settings)
        form.addRow(btn_save)
        self.tabs.addTab(w, "Settings")
        self.load_settings()

    # ---------- Login + Legal
    def _request_login_and_legal(self):
        dlg = LoginDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            QMessageBox.information(self, "Exit", "Login required.")
            sys.exit(0)
        self.operator = dlg.username
        ldlg = LegalDialog(self)
        if ldlg.exec_() != QDialog.Accepted:
            QMessageBox.information(self, "Exit", "Legal confirmation required.")
            sys.exit(0)
        self.case_meta = {"case_id": ldlg.case_id, "authority": ldlg.authority, "authorization_ref": ldlg.authorization_ref}
        self.statusBar().showMessage(f"Logged in as {self.operator} | Case: {self.case_meta.get('case_id','N/A')}")

    # ---------- Actions (choose dialogs)
    def choose_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select Directory")
        if d: self.ed_path.setText(d)
    def choose_ntuser(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select NTUSER.DAT", filter="Registry Hive (NTUSER.DAT)")
        if p: self.ed_ntuser.setText(p)
    def choose_evtx(self):
        d = QFileDialog.getExistingDirectory(self, "Select EVTX folder")
        if d: self.ed_evtx.setText(d)
    def choose_profile(self):
        d = QFileDialog.getExistingDirectory(self, "Select User Profile folder")
        if d: self.ed_profile.setText(d)
    def choose_sha(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select SHA-256 hash list", filter="Text (*.txt)")
        if p: self.ed_sha256.setText(p)
    def choose_phash(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select perceptual hash list", filter="Text (*.txt)")
        if p: self.ed_phash.setText(p)
    def choose_yara(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select YARA rules", filter="YARA (*.yar *.yara);;All (*)")
        if p: self.ed_yara.setText(p)
    def choose_browser(self):
        d = QFileDialog.getExistingDirectory(self, "Select Chromium profile directory")
        if d: self.ed_browser.setText(d)
    def choose_model_file(self):
        if self.cmb_model_type.currentText() == "onnx":
            p, _ = QFileDialog.getOpenFileName(self, "Select ONNX model", filter="ONNX model (*.onnx)")
        else:
            p, _ = QFileDialog.getOpenFileName(self, "Select Python module", filter="Python module (*.py)")
        if p: self.ed_model_path.setText(p)

    # ---------- Model test & settings
    def test_model_load(self):
        cfg = {"enabled": self.chk_custom_model.isChecked(), "type": self.cmb_model_type.currentText(), "path": self.ed_model_path.text().strip()}
        if not cfg["enabled"]:
            self.lbl_model_status.setText("Model: disabled"); return
        try:
            from core.custom_model import ModelLoader
            _ = ModelLoader(cfg.get("type"), cfg.get("path"))
            self.lbl_model_status.setText("Model: loaded OK")
            append_log({"event": "custom_model_loaded_test", "type": cfg.get("type")})
        except Exception as e:
            self.lbl_model_status.setText(f"Model load error: {e}")
            append_log({"event": "custom_model_load_error", "error": str(e)})

    # ---------- Start scan
    def start_scan(self):
        path = self.ed_path.text().strip()
        if not path or not os.path.isdir(path):
            QMessageBox.warning(self, "Scan", "Please select a valid directory to scan.")
            return
        options = {
            "thumbnails": self.chk_thumbs.isChecked(),
            "dry_run": self.chk_dry.isChecked(),
            "stego": self.chk_stego.isChecked(),
            "classification": self.chk_class.isChecked(),
            "run_plugins": self.chk_plugins.isChecked(),
            "win_deep": self.chk_win_deep.isChecked(),
            "ntuser_path": self.ed_ntuser.text().strip(),
            "evtx_dir": self.ed_evtx.text().strip(),
            "user_profile": self.ed_profile.text().strip(),
            "hashsets_enabled": self.chk_hashsets.isChecked(),
            "sha256_file": self.ed_sha256.text().strip(),
            "phash_file": self.ed_phash.text().strip(),
            "yara_enabled": self.chk_yara.isChecked(),
            "yara_rules": self.ed_yara.text().strip(),
            "ads_enabled": self.chk_ads.isChecked(),
            "browser_enabled": self.chk_browser.isChecked(),
            "browser_profile": self.ed_browser.text().strip(),
            "custom_model": {"enabled": self.chk_custom_model.isChecked(), "type": self.cmb_model_type.currentText(), "path": self.ed_model_path.text().strip()},
        }
        append_log({"event": "scan_requested", "user": self.operator, **self.case_meta, **options, "path": path})
        self.txt_log.append(f"[+] Scan requested: {path}")
        self.btn_scan.setEnabled(False)
        self.loading = QProgressDialog("Scanning…", None, 0, 0, self)
        self.loading.setWindowTitle("Processing"); self.loading.setWindowModality(Qt.ApplicationModal); self.loading.setMinimumDuration(0); self.loading.show()
        self.worker = ScanWorker(path, options)
        self.worker.progress.connect(self.txt_log.append)
        self.worker.progress.connect(self.loading.setLabelText)
        self.worker.finished.connect(self._scan_finished)
        self.worker.start()

    def _scan_finished(self, items, summary):
        self.btn_scan.setEnabled(True)
        try:
            if hasattr(self, "loading") and self.loading: self.loading.cancel()
        except Exception: pass
        if not items:
            self.txt_log.append("[!] No items or scan failed.")
            return
        self.lbl_summary.setText(f"Total: {summary['total']} | High: {summary['high']} | Medium: {summary['medium']} | Low: {summary['low']}")
        art = summary.get('artifacts') or {}
        if art:
            parts = []
            if 'ntuser' in art:
                parts.append(f"NTUSER Parsed: {len(art['ntuser'].get('typed_urls', []))} typed URLs, {len(art['ntuser'].get('run_mru', []))} RunMRU")
            if 'evtx' in art:
                ev = art['evtx']; parts.append(f"EVTX: {ev.get('total_events',0)} events (4624 logons: {ev.get('id_4624',0)}, 4688 proc: {ev.get('id_4688',0)})")
            if 'jumplists' in art: parts.append(f"Jump Lists: {len(art['jumplists'])} files")
            if 'prefetch' in art: parts.append(f"Prefetch: {len(art['prefetch'])} files")
            if 'amcache_hint' in art: parts.append("Amcache present" if art['amcache_hint'] else "Amcache not found")
            if 'yara_hits' in art: parts.append(f"YARA matches: {len(art['yara_hits'])}")
            if 'browser' in art: parts.append(f"Browser entries: {len(art['browser'])}")
            self.txt_log.append("[Artifacts] " + " | ".join(parts))
        serial = [dict(it.__dict__) if hasattr(it, "__dict__") else dict(it) for it in items]
        self.model.set_items(serial)
        self.timeline_model.set_rows(summary.get("timeline") or [])
        self.txt_log.append("[+] Scan finished.")
        append_log({"event": "scan_finished", **self.case_meta, "total": len(items)})

        if self.chk_plugins.isChecked():
            self.txt_log.append("[+] Running plugins on scanned items (summary)…")
            ran = 0
            for it in serial[:100]:
                res = run_plugins_on_path(it.get("path"), {"user": self.operator, **self.case_meta})
                if any(r.get("result") for r in res):
                    self.txt_log.append(f"[plugin] {os.path.basename(it.get('path',''))}: {res}")
                ran += 1
            self.txt_log.append(f"[+] Plugins executed on {ran} items (showing first matches).")

    # ---------- Evidence actions
    def open_selected_location(self):
        idx = self.tbl.currentIndex();
        if not idx.isValid(): return
        src_row = self.proxy.mapToSource(idx).row(); it = self.model.item_at(src_row)
        if not it: return
        folder = os.path.dirname(it.get("path"))
        QDesktopServices.openUrl(QUrl.fromLocalFile(folder))
        append_log({"event": "open_location", "path": folder, **self.case_meta})

    def view_selected_details(self):
        idx = self.tbl.currentIndex();
        if not idx.isValid(): return
        it = self.model.item_at(self.proxy.mapToSource(idx).row())
        if not it: return
        dlg = QDialog(self); dlg.setWindowTitle("Evidence Detail (blurred preview)")
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel(f"Path: {it.get('path','')}"))
        lay.addWidget(QLabel(f"SHA-256: {it.get('hash_sha256','')}"))
        lay.addWidget(QLabel(f"MIME: {it.get('mime','')} | Risk: {it.get('risk_score',0.0):.2f} | Stego: {'Yes' if it.get('stego_flag') else 'No'}"))
        meta = it.get("meta") or {}
        if meta.get("sha256_match"): lay.addWidget(QLabel("Hash match: SHA-256 known-bad"))
        if meta.get("phash_match"): lay.addWidget(QLabel(f"Perceptual near-match (d={meta.get('phash_dist','?')})"))
        yh = meta.get("yara_hits");
        if yh: lay.addWidget(QLabel("YARA rules: " + ", ".join([str(x) for x in yh][:10])))
        ads = meta.get("ads");
        if ads: lay.addWidget(QLabel(f"ADS streams: {len(ads)}"))
        img_lbl = QLabel(); thumb_hex = meta.get("thumbnail_blurred_hex")
        if thumb_hex:
            try:
                data = bytes.fromhex(thumb_hex); pix = QPixmap(); pix.loadFromData(data, "JPG")
                img_lbl.setPixmap(pix.scaledToWidth(320, Qt.SmoothTransformation))
            except Exception:
                img_lbl.setText("(No preview)")
        else:
            img_lbl.setText("(No preview available)")
        lay.addWidget(img_lbl)
        btns = QHBoxLayout(); btn_copy = QPushButton("Copy Hash"); btn_close = QPushButton("Close")
        btns.addWidget(btn_copy); btns.addWidget(btn_close); lay.addLayout(btns)
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(it.get("hash_sha256","")))
        btn_close.clicked.connect(dlg.accept)
        append_log({"event": "view_detail", "path": it.get("path"), **self.case_meta})
        dlg.exec_()

    def run_plugins_selected(self):
        idx = self.tbl.currentIndex();
        if not idx.isValid(): return
        it = self.model.item_at(self.proxy.mapToSource(idx).row())
        if not it: return
        res = run_plugins_on_path(it.get("path"), {"user": self.operator, **self.case_meta})
        QMessageBox.information(self, "Plugin Result", str(res)[:2000])
        append_log({"event": "plugin_run_item", "path": it.get("path"), **self.case_meta, "result_count": len(res)})

    # ---------- Reports & Timeline
    def generate_reports_now(self):
        base = self.ed_report_base.text().strip() or "report"
        items = self.model._items
        if not items:
            QMessageBox.information(self, "Reports", "No evidence in table.")
            return
        out = generate_reports(items, out_basename=base)
        self.last_report_paths = out
        self.lbl_reports_out.setText(f"JSON: {out['json']}\nHTML: {out['html']}")
        append_log({"event": "report_generated_gui", **self.case_meta, **out})
        if QMessageBox.question(self, "Open Report", "Open HTML report now?") == QMessageBox.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(out['html']))

    def export_timeline(self):
        rows = getattr(self.timeline_model, 'rows', [])
        if not rows:
            QMessageBox.information(self, "Timeline", "No timeline data.")
            return
        from core.reports import REPORTS_DIR
        os.makedirs(REPORTS_DIR, exist_ok=True)
        path = os.path.join(REPORTS_DIR, "timeline.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rows, f, indent=2)
            QMessageBox.information(self, "Timeline", f"Timeline exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Timeline", f"Failed to export: {e}")

    def refresh_plugins(self):
        files = discover_plugins()
        if not files:
            self.txt_plugins.setPlainText("(No plugins found in ./plugins)")
            return
        self.txt_plugins.setPlainText("\n".join(files))

    def open_reports_dir(self):
        from core.reports import REPORTS_DIR
        QDesktopServices.openUrl(QUrl.fromLocalFile(REPORTS_DIR))

    # ---------- Menu / About
    def _init_menu(self):
        menubar = self.menuBar()
        help_menu = menubar.addMenu("Help")
        about = QAction("About", self)
        def show_about():
            QMessageBox.about(self, "About", "<b>Investigator GUI</b><br/>Created by Joas A Santos<br/><br/>For authorized use only. Minimize exposure. No redistribution of illegal content.")
        about.triggered.connect(show_about)
        help_menu.addAction(about)
        # Add permanent credit on status bar
        credit = QLabel("Created by Joas A Santos")
        credit.setStyleSheet("color: gray;")
        self.statusBar().addPermanentWidget(credit)

    # ---------- Settings persistence
    def load_settings(self):
        self.ed_ai_api_key.setText(self.settings.value("ai_api_key", ""))
        self.chk_external_upload.setChecked(self.settings.value("require_confirm", True, type=bool))
        self.chk_custom_model.setChecked(self.settings.value("custom_model_enabled", False, type=bool))
        self.cmb_model_type.setCurrentText(self.settings.value("custom_model_type", "python_module"))
        self.ed_model_path.setText(self.settings.value("custom_model_path", ""))

    def save_settings(self):
        self.settings.setValue("ai_api_key", self.ed_ai_api_key.text())
        self.settings.setValue("require_confirm", self.chk_external_upload.isChecked())
        self.settings.setValue("custom_model_enabled", self.chk_custom_model.isChecked())
        self.settings.setValue("custom_model_type", self.cmb_model_type.currentText())
        self.settings.setValue("custom_model_path", self.ed_model_path.text().strip())
        QMessageBox.information(self, "Settings", "Settings saved.")
        append_log({"event": "settings_saved", "require_confirm": self.chk_external_upload.isChecked()})

# ---------- App entry

def main():
    app = QApplication(sys.argv)
    # Loading first
    boot = BootDialog(); boot.exec_()
    win = MainWindow(); win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
