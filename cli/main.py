# cli/main.py
import json
import os
import sys
import click

from core.scanner import FileScanner
from core.reports import generate_reports
from utils.auth import authenticate
from utils.immutable_logger import append_log

# Optional modules (best-effort)
try:
    from core.hashsets import HashDB
except Exception:
    HashDB = None

try:
    from core.yara_scan import compile_rules, scan_paths
except Exception:
    compile_rules = None
    def scan_paths(*args, **kwargs): return {}

try:
    from core.ads import list_streams
except Exception:
    def list_streams(_): return []

try:
    from core.browsers import chrome_history
except Exception:
    def chrome_history(_): return []

from core.win_registry import parse_ntuser_hive
from core.win_artifacts import collect_jump_lists, list_prefetch, amcache_hint
from core.evtx_reader import read_evtx_quick
from core.timeline import merge_timeline

def _load_hashdb(sha_file, ph_file):
    if HashDB is None:
        return None
    db = HashDB()
    if sha_file and os.path.exists(sha_file):
        with open(sha_file, "r", encoding="utf-8", errors="ignore") as f:
            db.import_sha256_list(f)
    if ph_file and os.path.exists(ph_file):
        with open(ph_file, "r", encoding="utf-8", errors="ignore") as f:
            db.import_phash_list(f)
    return db

def _chrome_ts_to_unix(ts_micro):
    try:
        base = 11644473600  # seconds 1601->1970
        return (int(ts_micro) / 1_000_000) - base
    except Exception:
        return None

@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "json_out", default=None, help="Output JSON report basename")
@click.option("--html", "html_out", default=None, help="Output HTML report basename")
@click.option("--user", prompt=True, help="Operator username")
@click.option("--dry-run", is_flag=True, default=False, help="Do not compute hashes or write files")
@click.option("--run-plugins", is_flag=True, default=False, help="Run plugins after scan")

# Windows deep artifacts
@click.option("--win-deep", is_flag=True, default=False, help="Collect Windows deep artifacts (Registry/EVTX/Prefetch/JumpLists)")
@click.option("--ntuser", "ntuser_path", type=click.Path(exists=True), default=None, help="Path to offline NTUSER.DAT")
@click.option("--evtx-dir", "evtx_dir", type=click.Path(exists=True), default=None, help="Directory with .evtx files")
@click.option("--profile", "user_profile", type=click.Path(exists=True), default=None, help="User profile for Jump Lists")

# Advanced triage
@click.option("--hashsets", is_flag=True, default=False, help="Enable hash intelligence (SHA-256/pHash)")
@click.option("--sha256db", type=click.Path(exists=True), default=None, help="Text file with SHA-256 hashes (one per line)")
@click.option("--phashdb", type=click.Path(exists=True), default=None, help="Text file with perceptual hashes")
@click.option("--yara", "yara_file", type=click.Path(exists=True), default=None, help="YARA rules file")
@click.option("--ads", is_flag=True, default=False, help="Scan NTFS Alternate Data Streams")
@click.option("--browser-profile", type=click.Path(exists=True), default=None, help="Chromium profile directory for History")
@click.option("--timeline-out", type=click.Path(), default=None, help="Write merged timeline JSON to this path")
def main(path, json_out, html_out, user, dry_run, run_plugins,
         win_deep, ntuser_path, evtx_dir, user_profile,
         hashsets, sha256db, phashdb, yara_file, ads, browser_profile, timeline_out):

    password = click.prompt("Password", hide_input=True)
    ok, role = authenticate(user, password)
    if not ok:
        click.echo("Authentication failed. Exiting.")
        return
    append_log({"event":"auth_success","user":user,"role":role})

    scanner = FileScanner(path, generate_thumbnails=not dry_run, dry_run=dry_run)
    items = scanner.scan()

    # Hash intelligence
    db = _load_hashdb(sha256db, phashdb) if hashsets else None
    if db:
        import imagehash
        from PIL import Image
        for it in items:
            meta = it.meta or {}
            if it.hash_sha256 and it.hash_sha256 != "DRY":
                if db.match_sha256(it.hash_sha256):
                    meta["sha256_match"] = True
                    it.risk_score = max(it.risk_score, 1.0)
            if it.mime and it.mime.startswith("image"):
                try:
                    ph = str(imagehash.phash(Image.open(it.path)))
                    meta["phash"] = ph
                    ok, dist = db.match_phash(ph)
                    if ok:
                        meta["phash_match"] = True; meta["phash_dist"] = dist
                        it.risk_score = max(it.risk_score, 0.9 if dist == 0 else 0.85)
                except Exception:
                    pass
            it.meta = meta

    # ADS
    if ads:
        for it in items:
            try:
                streams = list_streams(it.path)
                if streams:
                    it.meta.setdefault("ads", streams)
                    it.risk_score = max(it.risk_score, 0.55)
            except Exception:
                pass

    # YARA
    artifacts = {}
    if yara_file and compile_rules:
        try:
            rule = compile_rules(yara_file)
            paths = [i.path for i in items[:300]]
            hits = scan_paths(rule, paths)
            artifacts["yara_hits"] = hits
            for it in items:
                if it.path in hits:
                    it.meta.setdefault("yara_hits", hits[it.path])
                    it.risk_score = max(it.risk_score, 0.7)
        except Exception as e:
            click.echo(f"[!] YARA error: {e}")

    # Windows deep artifacts
    if win_deep:
        if ntuser_path:
            artifacts["ntuser"] = parse_ntuser_hive(ntuser_path)
        if evtx_dir:
            artifacts["evtx"] = read_evtx_quick(evtx_dir, max_events=200)
        if user_profile:
            artifacts["jumplists"] = collect_jump_lists(user_profile)
        artifacts["prefetch"] = list_prefetch()
        artifacts["amcache_hint"] = amcache_hint()

    # Browser artifacts
    if browser_profile:
        try:
            artifacts["browser"] = chrome_history(browser_profile)
        except Exception as e:
            click.echo(f"[!] Browser parse error: {e}")

    # Timeline (browser for now)
    timeline = []
    for b in artifacts.get("browser", []) or []:
        ts = _chrome_ts_to_unix(b.get("last_visit_time"))
        if ts:
            timeline.append({"ts": ts, "src": "browser", "desc": b.get("title") or b.get("url"), "path": b.get("url")})
    timeline = merge_timeline(timeline)
    if timeline_out:
        try:
            with open(timeline_out, "w", encoding="utf-8") as f:
                json.dump(timeline, f, indent=2)
            click.echo(f"Timeline exported to: {timeline_out}")
        except Exception as e:
            click.echo(f"[!] Failed to write timeline: {e}")

    # Plugins (optional)
    if run_plugins:
        from core.plugins import run_plugins_on_path
        for it in items[:200]:
            try:
                run_plugins_on_path(it.path, {"user": user})
            except Exception:
                pass

    # Reports
    out = generate_reports(items, out_basename=json_out or "forensic_report")
    append_log({"event":"report_generated","generated":out,"user":user,"artifacts":list(artifacts.keys())})
    click.echo(f"Reports generated: {out}")
    if artifacts:
        click.echo(f"Artifacts summary keys: {list(artifacts.keys())}")

if __name__ == "__main__":
    main()
