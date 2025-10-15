# ChildShield Forensics — CSAM/Anti-Trafficking Investigator Suite

> **Strictly for authorized law enforcement/auditors.**  
> Designed to minimize exposure to illegal content by using blurred thumbnails, hashes, and metadata-first workflows.

## ⚖️ Legal & Ethical Use

- Use **only** with valid legal authority for the specific case.
- **Never** redistribute illegal images/videos. Reports export only **hashes**, **metadata**, and **blurred** previews.
- Every action is **append-only logged** for audit and chain-of-custody.
- The tool aims to **reduce human exposure** by prioritizing hash-intelligence, perceptual matches, and machine triage.

---

## ✨ Features

- **Dual interface**: CLI and Desktop GUI (PyQt).
- **Image/Video triage**:
  - Blurred thumbnails by default.
  - Optional classification (NSFW/gore/deepfake). Supports **custom models**:
    - `python_module`: your `.py` with `score_image(path) -> float[0..1]`
    - `onnx`: via **onnxruntime**
- **Hash intelligence**:
  - Exact SHA-256 match (Bloom-backed)
  - Perceptual hash (pHash) with near-match thresholds
- **Steganography heuristics** (LSB/entropy; minimal & safe).
- **Windows artifacts**:
  - Offline **NTUSER.DAT** (TypedURLs, RunMRU, TypedPaths, UserAssist listing)
  - **EVTX** (quick counts: 4624 logon, 4688 process create)
  - **Prefetch**, **Jump Lists**, **Amcache hint**
- **Browser artifacts (Chromium)**: History (metadata-only, via safe copy).
- **ADS (NTFS Alternate Data Streams)** listing.
- **YARA** triage on files (optional).
- **Reports**: HTML + JSON (with SHA-256, metadata). Timeline export (`timeline.json`).
- **Plugins**: Python plugin API (`plugins/`).

---

## 🧰 Requirements

- **Python 3.11+** on Windows or Linux.
- Install Python deps:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
````

### OS Notes

* **Windows**:

  * MIME: `python-magic-bin` is installed automatically via marker.
  * WinAPI helpers: `pywin32`.
  * For some packages (e.g., `yara-python`) you may need recent Visual C++ build tools if no wheel is available.
* **Linux**:

  * MIME: `python-magic` requires system `libmagic`:

    * Debian/Ubuntu: `sudo apt-get install libmagic1`
    * Fedora: `sudo dnf install file-libs`

### External Tools (optional)

* **FFmpeg** (for video frame extraction / scene changes)

  * Windows (choco): `choco install ffmpeg`
  * Debian/Ubuntu: `sudo apt-get install ffmpeg`
* **YARA**: already via `yara-python` (rules are your responsibility).

---

## 🚀 Quick Start

### GUI

```bash
python -m gui.main_gui
```

1. A **loading** screen appears (“Initializing…”).
2. **Login** → or **Register** a new operator (role: analyst/admin).
3. Legal checklist (Case ID, Authority, Authorization Ref).
4. **Scan** tab: choose target folder and toggles:

   * Blurred thumbnails (default)
   * Classification (optionally with your **custom model** in Settings)
   * Steganography heuristics
   * Windows deep artifacts (NTUSER/EVTX/Jump Lists/Prefetch)
   * Hash intelligence (SHA-256/pHash lists)
   * YARA rules
   * ADS scan
   * Browser (Chromium) profile directory
5. **Evidence** tab: filter by risk/search; view **blurred** preview; copy hash.
6. **Timeline** tab: review and **Export Timeline JSON**.
7. **Reports** tab: generate **HTML & JSON**.

### CLI

```bash
python -m cli.main "E:/evidence" --user alice \
  --hashsets --sha256db data/sha256_bad.txt --phashdb data/phash_bad.txt \
  --yara rules/triage.yar --ads \
  --browser-profile "C:/Users/Case/AppData/Local/Google/Chrome/User Data/Default" \
  --win-deep --ntuser "E:/dumps/NTUSER.DAT" --evtx-dir "E:/evtx" --profile "E:/Users/Case" \
  --timeline-out reports/timeline.json
```

Other examples:

```bash
# Minimal run with report
python -m cli.main "/cases/DEVICE_IMG" --user bob

# Hash intelligence only
python -m cli.main "/cases/DEVICE_IMG" --user bob \
  --hashsets --sha256db data/sha.txt --phashdb data/ph.txt
```

---

## 🔧 Custom Image Model (NSFW/Classifier)

**Settings → Enable custom image model** and choose:

* **python_module**: select a `.py` file exposing:

  ```python
  def score_image(path: str) -> float:
      # return probability in [0..1]
      return 0.73
  ```
* **onnx**: select a `.onnx` (requires `onnxruntime`).
  The loader assumes a common RGB 224×224 preproc; if your model needs a different normalization,
  prefer **python_module** and handle preprocessing inside `score_image`.

---

## 🔌 Plugins

* Place Python modules in `plugins/`.
* Each plugin should expose:

  ```python
  def scan(path: str, context: dict) -> dict:
      # return {"result": "..."} or {}
  ```
* Enable “Run plugins after scan” in GUI, or use `--run-plugins` in CLI.

---

## 📁 Outputs

* **Reports**: `reports/` (HTML + JSON)
* **Timeline**: `reports/timeline.json` (GUI) or via `--timeline-out` (CLI)
* **Audit logs**: append-only JSON lines (location depends on project `utils/immutable_logger.py` settings)

Each file entry in the JSON includes:

* `path`, `hash_sha256`, `mime`, `risk_score`, `stego_flag`, `wallet_matches` (if implemented),
* `meta` (e.g., `phash`, `phash_dist`, `sha256_match`, `yara_hits`, `ads`, blurred thumbnail hex).

---

## 🏗️ Build Executables (optional)

Using PyInstaller:

```bash
pyinstaller --onefile --windowed --name childshield_gui gui/main_gui.py
pyinstaller --onefile --name childshield_cli cli/main.py
```

For best results, build on the target OS and ensure dependencies are installed.

---

## 🧪 Testing

* Use **synthetic datasets** and benign images/videos.
* Enable **dry-run** to simulate scanning without hashing/writing.
* Validate artifact parsers on virtual machines and known-good samples.

---

## 🆘 Troubleshooting

* **`ImportError: failed to find libmagic` (Windows)**
  Ensure `python-magic-bin` is installed (it is listed in `requirements.txt`).
  If you installed `python-magic` by mistake on Windows, uninstall it and install `python-magic-bin`.

* **`yara-python` install issues (Windows)**
  Prefer Python versions with prebuilt wheels. Otherwise install the latest Visual C++ Build Tools.

* **No thumbnails / preview**
  Previews are deliberately **blurred** or disabled to minimize exposure. Check the “Generate blurred thumbnails” option.

* **EVTX parsing slow**
  The EVTX reader does a **quick triage** (limited events). Increase limits gradually.

---

## 🔐 Security & Privacy

* Local DB can be encrypted at the filesystem level; temporary files are wiped where feasible.
* External API uploads (e.g., deepfake checks) are **opt-in** and require confirmation.
* Chain-of-custody events (scan start/stop/export) are logged with timestamps, user, host, and tool hash.

---

## 📜 License / Attribution

* **ChildShield Forensics** is intended for **lawful investigative use** only.
* You are responsible for compliance with local laws, policies, and data handling requirements.
