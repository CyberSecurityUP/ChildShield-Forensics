# core/evtx_reader.py
# Quick EVTX scan using python-evtx if available.
# pip install python-evtx

import os
from glob import glob

def _parse_with_python_evtx(evtx_path, wanted_ids, max_events=100):
    out = {"path": evtx_path, "counts": {eid: 0 for eid in wanted_ids}}
    try:
        from Evtx.Evtx import Evtx
        from Evtx.Views import evtx_file_xml_view
    except Exception:
        return out
    try:
        with Evtx(evtx_path) as log:
            n = 0
            for rec in log.records():
                try:
                    xml = rec.xml()
                    # quick+dirty event id extraction
                    start = xml.find("<EventID>")
                    if start != -1:
                        end = xml.find("</EventID>", start)
                        if end != -1:
                            eid = int(xml[start+9:end].strip())
                            if eid in out["counts"]:
                                out["counts"][eid] += 1
                    n += 1
                    if n >= max_events:
                        break
                except Exception:
                    pass
    except Exception:
        pass
    return out

def read_evtx_quick(evtx_dir: str, max_events=100):
    """
    Summarize EVTX events in a folder for IDs 4624 (logon) and 4688 (proc create).
    """
    if not evtx_dir or not os.path.isdir(evtx_dir):
        return {"error": "evtx_dir not found", "total_events": 0}
    wanted = [4624, 4688]
    total = 0
    agg = {4624: 0, 4688: 0}
    files = glob(os.path.join(evtx_dir, "*.evtx"))
    for f in files:
        res = _parse_with_python_evtx(f, wanted, max_events=max_events)
        for k, v in res.get("counts", {}).items():
            agg[k] = agg.get(k, 0) + v
        total += sum(res.get("counts", {}).values())
    return {
        "files": [os.path.basename(f) for f in files],
        "id_4624": agg.get(4624, 0),
        "id_4688": agg.get(4688, 0),
        "total_events": total
    }
