"""detect.py -- preservation, integrity, schema inference, timeline and detection.

No column names or usernames are assumed: columns are mapped through aliases and
the data dictionary; accounts/devices come from the evidence itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import pandas as pd

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None

SOURCES = ["authentication", "file_activity", "usb", "browser", "network", "forensic_artifacts"]
SOURCE_LABEL = {
    "authentication": "authentication", "file_activity": "file_activity", "usb": "usb",
    "browser": "browser", "network": "network", "forensic_artifacts": "forensic_artifacts",
}
SEV_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
CLOUD_CATEGORIES = {"cloud_storage", "file_share", "webmail"}
CLOUD_DOMAINS = {
    "mega.nz", "wetransfer.com", "dropbox.com", "drive.google.com", "onedrive.live.com",
    "box.com", "sendspace.com", "file.io", "transfer.sh", "gmail.com", "mail.google.com",
}
SAAS_ALLOW = {"sharepoint.com", "outlook.office.com", "github.com", "microsoft.com"}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- custody
class CustodyLog:
    """Append-only, hash-chained JSONL. Any edit breaks the chain."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if os.path.exists(path):
            os.remove(path)
        self.prev = "GENESIS"

    def add(self, actor: str, action: str, file: str = "", sha256: str = "",
            detail: str = "", extra: dict | None = None) -> dict:
        entry = {
            "timestamp": now_iso(), "actor": actor, "action": action,
            "file": file, "sha256": sha256, "detail": detail,
            "prev_entry_hash": self.prev,
        }
        if extra:
            entry["extra"] = extra
        payload = {k: v for k, v in entry.items() if k != "entry_hash"}
        entry["entry_hash"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self.prev = entry["entry_hash"]
        return entry


def verify_custody(path: str) -> tuple[bool, str]:
    prev = "GENESIS"
    if not os.path.exists(path):
        return False, "custody log missing"
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    for n, line in enumerate(lines, 1):
        try:
            e = json.loads(line)
        except Exception:
            return False, f"line {n} is not JSON"
        if e.get("prev_entry_hash") != prev:
            return False, f"line {n} prev hash mismatch"
        payload = {k: v for k, v in e.items() if k != "entry_hash"}
        calc = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        if calc != e.get("entry_hash"):
            return False, f"line {n} entry hash mismatch"
        prev = e["entry_hash"]
    return True, "chain valid"


# --------------------------------------------------------------------------- dictionary
def _first(data_dir: str, patterns: list[str]) -> str | None:
    for p in patterns:
        for fn in os.listdir(data_dir):
            if re.search(p, fn, re.I):
                return os.path.join(data_dir, fn)
    return None


def load_dictionary(data_dir: str) -> dict:
    d = {
        "timezones": {}, "authorized_users": set(), "approved_usb": set(),
        "backup_accounts": set(), "backup_domains": set(),
        "business": (9, 18), "business_tz": "America/New_York",
        "target_hint": "", "text": "",
    }
    path = _first(data_dir, [r"data[_ -]?dictionary.*\.(md|txt|csv|json)$", r"dictionary.*\.(md|txt|json)$"])
    if not path:
        return d
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    d["text"] = raw
    if path.lower().endswith(".json"):
        try:
            j = json.loads(raw)
            d.update({k: v for k, v in j.items() if k in d})
            for k in ("authorized_users", "approved_usb", "backup_accounts", "backup_domains"):
                d[k] = set(d[k])
            return d
        except Exception:
            pass

    section = ""
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("##"):
            section = s.lstrip("# ").strip().lower()
            continue
        m = re.match(r"^([\w.-]+\.csv)\s*:\s*([^\s(]+)(?:\s*\((UTC[+-]\d{2}:\d{2})\))?", s, re.I)
        if m and ("timezone" in section or "time zone" in section):
            d["timezones"][m.group(1).lower()] = (m.group(2), m.group(3) or "")
        if section.startswith("authorized") or section.startswith("authorised"):
            m = re.match(r"^[-*]\s+([\w.@\\-]+)\s*(?:[-:]\s*(.*))?$", s)
            if m and "not author" not in (m.group(2) or "").lower():
                d["authorized_users"].add(m.group(1).strip().lower())
        if "usb" in section and "approved" in section:
            m = re.match(r"^[-*]\s+([A-Za-z0-9._-]+)", s)
            if m:
                d["approved_usb"].add(m.group(1).upper())
        if "backup" in section:
            m = re.match(r"^[-*]\s+([\w.@\\-]+)", s)
            if m and ("backup" in s.lower() or "daily" in s.lower()):
                d["backup_accounts"].add(m.group(1).strip().lower())
            for dom in re.findall(r"\b([a-z0-9.-]+\.(?:com|net|org|internal))\b", s.lower()):
                if not dom.endswith(".csv"):
                    d["backup_domains"].add(dom)
        if "business" in section:
            m = re.search(r"(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s+([A-Za-z/_+-]+)", s)
            if m:
                d["business"] = (int(m.group(1)), int(m.group(3)))
                d["business_tz"] = m.group(5)
        m = re.search(r"target asset\s*:\s*(\S+)", s, re.I)
        if m:
            d["target_hint"] = m.group(1)
    if not d["target_hint"]:
        m = re.search(r"([A-Za-z0-9_.-]+\.(?:xlsx|xls|csv|pdf|docx|zip))", raw)
        if m:
            d["target_hint"] = m.group(1)
    return d


def resolve_tz(name: str, offset: str = ""):
    if name and name.upper() != "UTC" and ZoneInfo:
        try:
            return ZoneInfo(name), name
        except Exception:
            pass
    if offset:
        m = re.match(r"UTC([+-])(\d{2}):(\d{2})", offset)
        if m:
            delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
            if m.group(1) == "-":
                delta = -delta
            return timezone(delta), offset
    return timezone.utc, "UTC"


# --------------------------------------------------------------------------- schema
ALIASES = {
    "time": ["timestamp", "event_time", "datetime", "date_time", "occurred_at", "time", "ts", "timestamp_utc"],
    "user": ["username", "user_name", "user", "account", "account_name", "actor", "principal", "upn", "subject"],
    "host": ["hostname", "host_name", "computer_name", "endpoint", "workstation", "src_host", "source_host", "host", "computer", "device_name"],
    "event": ["event_type", "event", "action", "activity", "operation", "technique"],
    "path": ["file_path", "path", "filename", "file_name", "source_path", "file"],
    "new_path": ["new_path", "destination_path", "target_path", "to_path"],
    "classification": ["classification", "sensitivity", "data_class", "label"],
    "process": ["process_name", "process", "image", "program", "app"],
    "device": ["device_id", "usb_id", "serial_number", "serial", "device", "volume_id"],
    "approved": ["is_approved", "approved", "authorized", "authorised"],
    "bytes": ["bytes_out", "bytes_sent", "size_bytes", "size", "bytes"],
    "domain": ["dest_domain", "destination_domain", "remote_domain", "domain"],
    "dest_ip": ["dest_ip", "destination_ip", "remote_ip", "ip_address", "ip"],
    "url": ["url", "uri", "link"],
    "category": ["site_category", "url_category", "category"],
    "artifact_type": ["artifact_type", "artifact", "technique", "type"],
    "tool": ["tool", "command", "program"],
    "detail": ["detail", "description", "message", "notes"],
    "source_ip": ["source_ip", "src_ip", "ip_address", "ip"],
    "new_device": ["is_new_device", "new_device"],
    "location": ["location", "geo", "country", "city"],
    "object": ["object", "target", "detail", "description"],
}


def norm_col(c: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(c).strip().lower()).strip("_")


def infer_schema(df: pd.DataFrame) -> dict:
    cols = {norm_col(c): c for c in df.columns}
    mapping = {}
    for role, aliases in ALIASES.items():
        for a in aliases:
            if a in cols:
                mapping[role] = cols[a]
                break
        if role not in mapping:
            for n, orig in cols.items():
                if any(a == n or a in n for a in aliases):
                    mapping[role] = orig
                    break
    return mapping


def source_for_file(filename: str) -> str | None:
    stem = os.path.splitext(filename)[0].lower()
    for s in SOURCES:
        if stem == s:
            return s
    rules = [
        ("authentication", ["auth", "logon", "login", "ad_"]),
        ("file_activity", ["file", "access", "dlp", "share"]),
        ("usb", ["usb", "removable", "device"]),
        ("browser", ["browser", "web", "proxy"]),
        ("network", ["network", "netflow", "dns", "traffic"]),
        ("forensic_artifacts", ["forensic", "artifact", "anti"]),
    ]
    for s, keys in rules:
        if any(k in stem for k in keys):
            return s
    return None


# --------------------------------------------------------------------------- time
def parse_timestamp(raw, tz):
    s = str(raw).strip()
    if not s:
        return None
    if re.fullmatch(r"\d{9,17}(?:\.\d+)?", s):
        try:
            v = float(s)
            if v > 1e14:
                v /= 1e6
            elif v > 1e11:
                v /= 1e3
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except Exception:
            return None
    iso = s.replace("Z", "+00:00")
    dt = None
    try:
        dt = datetime.fromisoformat(iso)
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                    "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d %b %Y %H:%M:%S",
                    "%b %d %Y %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M",
                    "%m/%d/%Y %H:%M", "%d/%m/%Y %H:%M"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except Exception:
                dt = None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt.astimezone(timezone.utc)


def norm_user(v) -> str:
    u = str(v).strip().strip('"').lower()
    if "\\" in u:
        u = u.split("\\")[-1]
    return re.sub(r"\s+", " ", u).strip()


def norm_host(v) -> str:
    return str(v).strip().upper()


def is_service(user: str, d: dict) -> bool:
    return user in d["backup_accounts"] or user.startswith(("svc_", "svc-", "service_"))


def in_business_hours(dt_utc: datetime, d: dict) -> bool:
    tz, _ = resolve_tz(d.get("business_tz", "America/New_York"))
    local = dt_utc.astimezone(tz)
    start, end = d.get("business", (9, 18))
    return local.weekday() < 5 and start <= local.hour < end


def deep_off_hours(dt_utc: datetime, d: dict) -> bool:
    tz, _ = resolve_tz(d.get("business_tz", "America/New_York"))
    h = dt_utc.astimezone(tz).hour
    return h < 7 or h >= 20


def is_internal_domain(domain: str, d: dict) -> bool:
    dom = (domain or "").lower()
    return (dom.endswith(".internal") or dom in d.get("backup_domains", set())
            or dom in SAAS_ALLOW or dom.startswith("10.") or dom.startswith("192.168.")
            or bool(re.match(r"^172\.(1[6-9]|2\d|3[01])\.", dom)))


# --------------------------------------------------------------------------- preserve
def preserve_and_verify(data_dir: str, evidence_dir: str, custody: CustodyLog,
                        actor: str = "system:digital-evidence-detective") -> dict:
    orig_dir = os.path.join(evidence_dir, "original")
    os.makedirs(orig_dir, exist_ok=True)
    raw_files = sorted(f for f in os.listdir(data_dir) if os.path.isfile(os.path.join(data_dir, f)))
    manifest_path = os.path.join(data_dir, "evidence_manifest.csv")
    expected = {}
    manifest_present = os.path.exists(manifest_path)
    if manifest_present:
        mdf = pd.read_csv(manifest_path, dtype=str, keep_default_na=False)
        fcol = next((c for c in mdf.columns if norm_col(c) in ("filename", "file", "name", "file_name")), mdf.columns[0])
        hcol = next((c for c in mdf.columns if "sha" in norm_col(c) or "hash" in norm_col(c)), None)
        scol = next((c for c in mdf.columns if "size" in norm_col(c)), None)
        for _, r in mdf.iterrows():
            fn = os.path.basename(str(r[fcol]).strip().replace("\\", "/"))
            expected[fn] = {
                "sha256": str(r[hcol]).strip().lower() if hcol else "",
                "size": str(r[scol]).strip() if scol else "",
            }

    files = []
    preservation_ok = True
    for fn in raw_files:
        src = os.path.join(data_dir, fn)
        dst = os.path.join(orig_dir, fn)
        try:
            if os.path.exists(dst):
                os.chmod(dst, 0o644)
            shutil.copy2(src, dst)
            os.chmod(dst, 0o444)
            raw_hash = sha256_file(src)
            copy_hash = sha256_file(dst)
            custody.add(actor, "preserve_copy", fn, copy_hash,
                        f"copied raw to evidence/original and set read-only; raw_sha256={raw_hash}")
        except Exception as e:
            preservation_ok = False
            files.append({"file": fn, "source": source_for_file(fn), "expected": "", "actual": "",
                          "status": "UNTRUSTED", "reason": f"copy failed: {e}", "included": False})
            custody.add(actor, "preserve_copy_failed", fn, "", str(e))
            continue

        if fn == "evidence_manifest.csv":
            status, reason, exp = "REFERENCE", "manifest is the trust anchor (not self-hashed)", ""
        elif not manifest_present:
            status, reason, exp = "UNTRUSTED", "evidence_manifest.csv missing; cannot verify", ""
        elif fn not in expected:
            status, reason, exp = "UNTRUSTED", "file not listed in manifest", ""
        else:
            exp = expected[fn]["sha256"]
            if not exp:
                status, reason = "UNTRUSTED", "manifest has no sha256 for file"
            elif copy_hash != exp:
                status, reason = "UNTRUSTED", "SHA-256 MISMATCH - possible tampering"
            elif raw_hash != copy_hash:
                status, reason = "UNTRUSTED", "raw/copy hash mismatch"
            else:
                status, reason = "TRUSTED", "SHA-256 matches manifest"
        included = status == "TRUSTED" and source_for_file(fn) is not None
        files.append({"file": fn, "source": source_for_file(fn), "expected": exp, "actual": copy_hash,
                      "status": status, "reason": reason, "included": included})
        custody.add(actor, "verify_hash", fn, copy_hash, f"{status}: {reason}",
                    {"expected": exp, "status": status})

    present = {f["file"] for f in files}
    for fn, meta in expected.items():
        if fn not in present and fn != "evidence_manifest.csv":
            files.append({"file": fn, "source": source_for_file(fn), "expected": meta["sha256"],
                          "actual": "", "status": "UNTRUSTED", "reason": "file missing from data set",
                          "included": False})
            custody.add(actor, "verify_hash", fn, "", "UNTRUSTED: file missing")

    untrusted = [f["file"] for f in files if f["status"] == "UNTRUSTED"]
    integrity_ok = manifest_present and not untrusted
    custody.add(actor, "preservation_summary", "", "",
                f"preservation_ok={preservation_ok} integrity_ok={integrity_ok} untrusted={untrusted}")
    return {
        "files": files, "preservation_ok": preservation_ok, "integrity_ok": integrity_ok,
        "untrusted": untrusted, "manifest_present": manifest_present,
        "trusted_sources": sorted({f["source"] for f in files if f["included"]}),
        "evidence_dir": orig_dir,
    }


# --------------------------------------------------------------------------- timeline
def build_timeline(data_dir: str, integrity: dict, dictionary: dict) -> dict:
    rows, failures, source_info, duplicates = [], [], {}, []
    trusted = {f["file"]: f for f in integrity["files"] if f["included"]}
    for fn, meta in trusted.items():
        source = meta["source"]
        path = os.path.join(data_dir, fn)
        try:
            df = pd.read_csv(path, dtype=str, keep_default_na=False)
        except Exception as e:
            failures.append({"evidence_id": fn, "source": source, "raw": "", "reason": f"read error: {e}"})
            continue
        mapping = infer_schema(df)
        if "time" not in mapping:
            failures.append({"evidence_id": fn, "source": source, "raw": "",
                             "reason": f"no timestamp column among {list(df.columns)}"})
            continue
        tzname, offset = dictionary["timezones"].get(fn.lower(), ("UTC", ""))
        if (tzname, offset) == ("UTC", "") and dictionary["timezones"]:
            for k, v in dictionary["timezones"].items():
                if source_for_file(k) == source:
                    tzname, offset = v
                    break
        tz, tzlabel = resolve_tz(tzname, offset)
        source_info[source] = {"file": fn, "rows": len(df), "columns": list(df.columns),
                               "mapping": {k: v for k, v in mapping.items()}, "tz": tzname}

        for i, rec in df.iterrows():
            raw = {str(k): str(v) for k, v in rec.items()}
            eid = f"{fn}:{i + 2}"
            utc = parse_timestamp(raw.get(mapping["time"], ""), tz)
            if utc is None:
                failures.append({"evidence_id": eid, "source": source,
                                 "raw": raw.get(mapping["time"], ""), "reason": "unparseable timestamp"})
                continue

            def pick(role):
                return raw.get(mapping.get(role, ""), "").strip()

            event = pick("event").lower()
            user = norm_user(pick("user"))
            host = norm_host(pick("host"))
            if source == "authentication":
                obj = pick("device") or pick("source_ip") or event
            elif source == "usb":
                obj = pick("path") or pick("device")
            elif source == "browser":
                obj = pick("url") or pick("domain")
            elif source == "network":
                obj = pick("domain") or pick("dest_ip") or pick("object")
            elif source == "forensic_artifacts":
                obj = pick("detail") or pick("artifact_type") or event
            else:
                obj = (pick("new_path") if event in ("copy", "archive", "rename", "backup") else "") or pick("path") or pick("object")

            extras = {
                "path": pick("path"), "new_path": pick("new_path"),
                "classification": pick("classification").upper(), "process": pick("process"),
                "device": pick("device").upper(), "approved": pick("approved").lower() in ("true", "1", "yes", "y"),
                "bytes": int(float(pick("bytes") or 0)) if re.fullmatch(r"\d+(?:\.\d+)?", pick("bytes") or "0") else 0,
                "domain": pick("domain").lower(), "dest_ip": pick("dest_ip"),
                "url": pick("url"), "category": pick("category").lower(),
                "artifact_type": (pick("artifact_type") or event).lower(),
                "tool": pick("tool"), "source_ip": pick("source_ip"),
                "is_new_device": pick("new_device").lower() in ("true", "1", "yes", "y"),
                "location": pick("location"), "detail": pick("detail"),
            }
            rows.append({
                "time_utc": utc, "source": source, "user": user, "host": host,
                "event": event, "object": obj, "evidence_id": eid,
                "time_local": utc.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %z"),
                "source_tz": tzlabel, "extras": extras,
            })

    # exact-duplicate suppression (all evidence fields except the row identifier)
    seen, unique = {}, []
    for r in sorted(rows, key=lambda x: (x["time_utc"], SOURCES.index(x["source"]))):
        sig = json.dumps({k: r[k] for k in ("time_utc", "source", "user", "host", "event", "object")}
                         | {"extras": r["extras"]}, sort_keys=True, default=str)
        if sig in seen:
            duplicates.append({"kept": seen[sig], "dropped": r["evidence_id"], "source": r["source"]})
            continue
        seen[sig] = r["evidence_id"]
        unique.append(r)

    return {"rows": unique, "failures": failures, "source_info": source_info,
            "duplicates": duplicates, "raw_count": len(rows)}


# --------------------------------------------------------------------------- target
def identify_target(rows: list[dict], dictionary: dict) -> dict:
    cand = defaultdict(lambda: {"score": 0, "ids": [], "classification": "", "actions": set()})
    hint = (dictionary.get("target_hint") or "").lower()
    for r in rows:
        if r["source"] != "file_activity":
            continue
        path = r["extras"].get("path") or r["object"]
        if not path:
            continue
        text = f"{path} {r['extras'].get('new_path','')}".lower()
        score = 0
        if r["extras"].get("classification") == "RESTRICTED":
            score += 3
        if "restricted" in text:
            score += 2
        if "pricing" in text:
            score += 3
        if any(k in text for k in ("model", "workbook", ".xlsx", ".xls")):
            score += 1
        if hint and hint in text:
            score += 4
        if score <= 0:
            continue
        c = cand[path]
        c["score"] += score
        c["ids"].append(r["evidence_id"])
        c["classification"] = c["classification"] or r["extras"].get("classification", "")
        c["actions"].add(r["event"])
    if not cand:
        counts = Counter((r["extras"].get("path") or r["object"]) for r in rows
                         if r["source"] == "file_activity" and (r["extras"].get("path") or r["object"]))
        if not counts:
            return {"path": "", "basename": "", "stem": "", "evidence_ids": [], "score": 0}
        path = counts.most_common(1)[0][0]
        return {"path": path, "basename": os.path.basename(path), "stem": os.path.splitext(os.path.basename(path))[0],
                "evidence_ids": [r["evidence_id"] for r in rows if r["object"] == path], "score": 0}
    path, meta = max(cand.items(), key=lambda kv: (kv[1]["score"], len(kv[1]["ids"])))
    base = os.path.basename(path)
    return {"path": path, "basename": base, "stem": os.path.splitext(base)[0],
            "evidence_ids": meta["ids"], "score": meta["score"], "classification": meta["classification"],
            "actions": sorted(meta["actions"])}


# --------------------------------------------------------------------------- rules
def _add(findings, rule, row, severity, strong, description, score=0):
    findings.append({
        "rule": rule, "source": row["source"], "severity": severity, "strong": strong,
        "user": row["user"], "host": row["host"], "time_utc": row["time_utc"],
        "object": row["object"], "evidence_ids": [row["evidence_id"]],
        "description": description, "score": score or SEV_WEIGHT[severity],
        "device": row["extras"].get("device", ""), "domain": row["extras"].get("domain", ""),
        "decoy": False, "decoy_reason": "",
    })


def run_rules(rows: list[dict], target: dict, dictionary: dict) -> list[dict]:
    findings = []
    tbase = (target.get("basename") or "").lower()
    tstem = (target.get("stem") or "").lower()
    for r in rows:
        src, ev, obj, ex = r["source"], r["event"], r["object"], r["extras"]
        text = f"{obj} {ex.get('path','')} {ex.get('new_path','')} {ex.get('detail','')}".lower()
        target_hit = bool(tbase and tbase in text) or bool(tstem and tstem in text)

        if src == "file_activity":
            if target_hit and ev in ("read", "copy", "rename", "archive", "delete"):
                sev = "HIGH" if ev in ("copy", "rename", "archive") else "MEDIUM"
                _add(findings, "restricted_file_activity", r, sev, ev in ("copy", "rename", "archive"),
                     f"{ev} of restricted workbook {target.get('basename')}", 5 if sev == "HIGH" else 3)
            if ev == "archive" and ("pricing" in text or target_hit):
                _add(findings, "restricted_archive_created", r, "HIGH", True,
                     f"restricted data archived to {obj}", 5)
            if ev == "delete" and ("pricing" in text or target_hit):
                _add(findings, "evidence_cleanup", r, "MEDIUM", True,
                     f"staged copy deleted: {obj}", 4)
            if ev == "backup" or "backup" in (ex.get("process") or "").lower():
                _add(findings, "bulk_backup", r, "LOW", False,
                     f"bulk copy to {obj} ({ex.get('bytes',0)} bytes)", 1)

        elif src == "usb":
            approved = ex.get("approved") or ex.get("device", "").upper() in dictionary["approved_usb"]
            if ev in ("write", "connect"):
                if not approved:
                    _add(findings, "unapproved_usb", r, "HIGH" if ev == "write" else "MEDIUM",
                         ev == "write", f"unapproved USB {ex.get('device')} {ev} on {r['host']}", 5)
                if ev == "write" and ("pricing" in text or target_hit):
                    _add(findings, "usb_restricted_copy", r, "HIGH", True,
                         f"restricted archive written to USB {ex.get('device')}: {obj}", 6)
                if approved:
                    _add(findings, "approved_usb_write", r, "LOW", False,
                         f"approved USB {ex.get('device')} {ev} ({obj})", 1)

        elif src == "browser":
            cat = ex.get("category")
            dom = (ex.get("domain") or "").lower()
            if cat in CLOUD_CATEGORIES or dom in CLOUD_DOMAINS:
                _add(findings, "cloud_file_share_visit", r, "MEDIUM", False,
                     f"{cat or 'cloud'} visit to {dom or obj}", 3)

        elif src == "network":
            domain = (ex.get("domain") or obj).lower()
            nbytes = ex.get("bytes", 0)
            if nbytes >= 10 * 1024 * 1024 and not is_internal_domain(domain, dictionary):
                _add(findings, "external_large_transfer", r, "HIGH", True,
                     f"{nbytes/1048576:.1f} MB outbound to {domain} ({ex.get('dest_ip')})", 6)
            elif nbytes >= 10 * 1024 * 1024:
                _add(findings, "large_internal_transfer", r, "LOW", False,
                     f"{nbytes/1048576:.1f} MB to internal/backup {domain}", 1)

        elif src == "authentication":
            if ev in ("failed_login", "failed", "failure"):
                _add(findings, "failed_login", r, "MEDIUM", False,
                     f"failed login from {ex.get('source_ip')} ({ex.get('location')})", 2)
            if ev in ("login", "logon", "success") and (
                    ex.get("is_new_device") or deep_off_hours(r["time_utc"], dictionary)):
                _add(findings, "anomalous_login", r, "HIGH", True,
                     f"login from new device {ex.get('source_ip')} at {r['time_local']} (off-hours/new-device)", 4)
            if ev in ("service_login", "service"):
                _add(findings, "service_login", r, "LOW", False,
                     f"service account login on {r['host']}", 1)

        elif src == "forensic_artifacts":
            at = ex.get("artifact_type") or ev
            scheduled = any(k in text for k in ("scheduled", "rotation", "retention", "logrotate"))
            if at in ("log_cleared", "timestomp", "wipe_tool", "deleted_file", "wiping"):
                if scheduled and is_service(r["user"], dictionary):
                    _add(findings, "scheduled_log_rotation", r, "LOW", False,
                         f"scheduled log maintenance on {r['host']}: {obj}", 1)
                else:
                    _add(findings, "anti_forensics", r, "HIGH", True,
                         f"{at} on {r['host']}: {obj}", 6)

    findings.sort(key=lambda f: f["time_utc"])
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i:03d}"
    return findings


# --------------------------------------------------------------------------- decoys
def classify_decoys(findings, rows, target, dictionary):
    by_id = {r["evidence_id"]: r for r in rows}
    target_users = {f["user"] for f in findings if f["rule"] in ("restricted_file_activity", "restricted_archive_created", "usb_restricted_copy")}
    exfil_users = {f["user"] for f in findings if f["rule"] in ("external_large_transfer", "unapproved_usb", "usb_restricted_copy")}

    for f in findings:
        row = by_id.get(f["evidence_ids"][0])
        if not row:
            continue
        ex = row["extras"]
        u, src, ev = f["user"], f["source"], row["event"]
        reason = ""
        if f["rule"] in ("bulk_backup", "service_login", "scheduled_log_rotation", "large_internal_transfer") and is_service(u, dictionary):
            reason = "Scheduled service account / approved backup job to internal backup destination"
        elif f["rule"] == "approved_usb_write":
            reason = "Approved USB device on the corporate allow-list; non-restricted file"
        elif src == "authentication" and ev in ("service_login", "service") and is_service(u, dictionary):
            reason = "Service account authentication, not a human session"
        elif f["rule"] == "restricted_file_activity" and u in dictionary["authorized_users"] and in_business_hours(f["time_utc"], dictionary) and u not in exfil_users:
            reason = "Authorised pricing analyst, business hours, read-only, no USB/network exfiltration"
        elif f["rule"] == "cloud_file_share_visit" and u not in exfil_users:
            reason = "Cloud/file-share browsing without any restricted-file access or external transfer by this account"
        elif f["rule"] == "large_internal_transfer" or (src == "network" and is_internal_domain(ex.get("domain", ""), dictionary)):
            reason = "Internal/backup destination matching scheduled backup, not external exfiltration"
        elif f["rule"] == "failed_login" and u not in target_users:
            reason = "Isolated failed login, no subsequent restricted access or exfiltration"
        if reason:
            f["decoy"] = True
            f["decoy_reason"] = reason
    return findings


# --------------------------------------------------------------------------- verdict
def correlate(findings, target):
    linked = [f for f in findings if not f["decoy"]]
    groups = defaultdict(list)
    for f in linked:
        groups[(f["user"], f["host"])].append(f)
    best = None
    tbase, tstem = (target.get("basename") or "").lower(), (target.get("stem") or "").lower()
    for (user, host), fs in groups.items():
        direct = [f for f in fs if f["rule"] in ("restricted_file_activity", "restricted_archive_created", "usb_restricted_copy")
                  or (tbase and tbase in f["object"].lower()) or (tstem and tstem in f["object"].lower())]
        if not direct:
            continue
        t0 = min(f["time_utc"] for f in direct)
        win = [f for f in fs if abs((f["time_utc"] - t0).total_seconds()) <= 3 * 3600]
        sources = {f["source"] for f in win}
        key = (len(sources), sum(SEV_WEIGHT[f["severity"]] for f in win), len(win))
        if best is None or key > best[0]:
            best = (key, user, host, sorted(win, key=lambda f: f["time_utc"]))
    if not best:
        return {"linked": [], "account": "", "endpoint": "", "window_start": None,
                "window_end": None, "sources": [], "confidence": "INCONCLUSIVE"}
    _, user, host, win = best
    return {"linked": win, "account": user, "endpoint": host,
            "window_start": min(f["time_utc"] for f in win),
            "window_end": max(f["time_utc"] for f in win),
            "sources": sorted({f["source"] for f in win})}


def compute_verdict(linked, target, decoys, dictionary):
    sources = sorted({f["source"] for f in linked})
    strong = any(f["strong"] for f in linked)
    if len(sources) >= 3:
        confidence = "CONFIRMED"
    elif len(sources) == 2 and strong:
        confidence = "HIGH_CONFIDENCE"
    elif linked:
        confidence = "SUSPICIOUS"
    else:
        confidence = "INCONCLUSIVE"

    usb = [f for f in linked if f["source"] == "usb" and "usb" in f["rule"]]
    net = [f for f in linked if f["source"] == "network" and f["rule"] == "external_large_transfer"]
    browser = [f for f in linked if f["source"] == "browser"]
    if usb and (net or browser):
        method = "USB copy + cloud upload"
    elif usb:
        method = "USB copy"
    elif net:
        method = "Cloud upload / outbound transfer"
    elif linked:
        method = "Restricted-file access and staging"
    else:
        method = ""

    usb_ids = sorted({f.get("device") or f["object"] for f in usb if (f.get("device") or f["object"])})
    domains = sorted({f["object"] for f in net}) or sorted({f["object"] for f in browser})
    dest = ", ".join([d for d in domains if d] + usb_ids)
    return {
        "verdict": confidence, "confidence": confidence, "sources": sources,
        "source_count": len(sources), "strong_indicator": strong,
        "account": linked[0]["user"] if linked else "",
        "endpoint": linked[0]["host"] if linked else "",
        "file": target.get("basename", ""), "method": method, "destination": dest,
        "usb_device": ", ".join(usb_ids), "domains": [d for d in domains if d],
        "linked": linked, "decoys": decoys,
    }


def detect_all(rows, dictionary):
    target = identify_target(rows, dictionary)
    findings = run_rules(rows, target, dictionary)
    findings = classify_decoys(findings, rows, target, dictionary)
    corr = correlate(findings, target)
    verdict = compute_verdict(corr["linked"], target, [f for f in findings if f["decoy"]], dictionary)
    verdict.update({
        "account": corr["account"], "endpoint": corr["endpoint"],
        "window_start": corr["window_start"], "window_end": corr["window_end"],
        "target": target, "all_findings": findings,
    })
    return verdict


# --------------------------------------------------------------------------- inspect
def inspect_data(data_dir: str) -> None:
    print("\n=== STEP 0: DATA INSPECTION ===")
    for fn in sorted(os.listdir(data_dir)):
        if not fn.lower().endswith(".csv"):
            continue
        p = os.path.join(data_dir, fn)
        try:
            df = pd.read_csv(p, dtype=str, keep_default_na=False)
        except Exception as e:
            print(f"\n[{fn}] UNREADABLE: {e}")
            continue
        print(f"\n[{fn}] rows={len(df)} cols={len(df.columns)}")
        print("  columns/dtypes:", ", ".join(f"{c}:{t}" for c, t in zip(df.columns, df.dtypes)))
        print("  sample:")
        for line in df.head(3).to_string(index=False).splitlines():
            print("   ", line)
        for c in df.columns:
            n = df[c].nunique()
            if n <= 8:
                print(f"  value_counts[{c}] ({n}):", dict(df[c].value_counts().head(8)))
