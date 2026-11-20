"""respond.py -- evidence packaging first, then approval-gated SIMULATED containment."""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone

from detect import CustodyLog, sha256_file

PLAYBOOK_VERSION = "1.0"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_evidence_package(output_dir: str, evidence_dir: str, data_dir: str,
                           timeline_csv: str, findings_json: str, custody_path: str,
                           custody: CustodyLog, verdict: dict, integrity: dict,
                           actor: str = "system:digital-evidence-detective") -> dict:
    """Create the package BEFORE any response action. Returns path + hash."""
    os.makedirs(output_dir, exist_ok=True)
    zip_path = os.path.join(output_dir, "evidence_package.zip")
    members = []

    def add_file(zf, src, arcname):
        if not os.path.exists(src):
            return
        zf.write(src, arcname)
        members.append({"path": arcname, "sha256": sha256_file(src), "size": os.path.getsize(src)})

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        orig = os.path.join(evidence_dir, "original")
        if os.path.isdir(orig):
            for fn in sorted(os.listdir(orig)):
                p = os.path.join(orig, fn)
                if os.path.isfile(p):
                    add_file(zf, p, f"originals/{fn}")
        add_file(zf, os.path.join(data_dir, "evidence_manifest.csv"), "evidence_manifest.csv")
        add_file(zf, timeline_csv, "timeline.csv")
        add_file(zf, findings_json, "findings.json")
        add_file(zf, custody_path, "chain_of_custody.jsonl")
        manifest = {
            "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "case": "Digital Evidence Detective",
            "verdict": verdict.get("verdict"),
            "account": verdict.get("account"),
            "endpoint": verdict.get("endpoint"),
            "target_file": verdict.get("file"),
            "integrity_ok": integrity.get("integrity_ok"),
            "untrusted_files": integrity.get("untrusted", []),
            "members": members,
        }
        zf.writestr("package_manifest.json", json.dumps(manifest, indent=2, default=str))

    digest = sha256_file(zip_path)
    with open(zip_path + ".sha256", "w", encoding="utf-8") as f:
        f.write(f"{digest}  evidence_package.zip\n")
    custody.add(actor, "evidence_package_created", "evidence_package.zip", digest,
                f"package built before containment; {len(members)} members")
    return {"path": zip_path, "sha256": digest, "members": len(members),
            "manifest": manifest}


class SimulatedAdapters:
    """No real systems are touched. Every method returns a rollback command."""

    def __init__(self, mode: str):
        self.mode = mode  # dry_run | execute
        self.status = "DRY_RUN" if mode == "dry_run" else "SIMULATED_OK"

    def _result(self, action, target, rollback, detail):
        return {"action": action, "target": target, "status": self.status,
                "mode": self.mode, "rollback": rollback, "detail": detail,
                "requires_approval": True,
                "simulated_command": f"SIMULATED::{action}({target})"}

    def isolate_endpoint(self, host):
        return self._result("isolate_endpoint", host,
                            f"unisolate_endpoint(host='{host}')",
                            "EDR network isolation applied (simulated)")

    def revoke_sessions(self, user):
        return self._result("revoke_sessions", user,
                            f"restore_sessions(user='{user}')",
                            "All active tokens/sessions invalidated (simulated)")

    def disable_account(self, user):
        return self._result("disable_account", user,
                            f"enable_account(user='{user}')",
                            "Account sign-in blocked, reversible (simulated)")

    def block_destination(self, domain):
        return self._result("block_destination", domain,
                            f"unblock_destination(domain='{domain}')",
                            "Egress firewall/proxy block (simulated)")

    def block_usb(self, device_id):
        return self._result("block_usb", device_id,
                            f"unblock_usb(device_id='{device_id}')",
                            "USB device denied by device-control policy (simulated)")

    def open_incident_record(self, incident_id):
        return self._result("open_incident_record", incident_id,
                            f"close_incident(incident_id='{incident_id}')",
                            "Incident record opened (simulated)")


def _incident_id(verdict: dict) -> str:
    key = f"{verdict.get('account')}|{verdict.get('window_start')}|{verdict.get('endpoint')}"
    return "INC-" + str(int(hashlib.sha256(key.encode()).hexdigest(), 16) % 9000 + 1000)


def execute_playbook(verdict: dict, output_dir: str, approve: bool, package: dict,
                     custody: CustodyLog, integrity_ok: bool,
                     actor: str = "analyst:cli") -> dict:
    """Gate, then execute in order. Refuses if the evidence package is absent."""
    os.makedirs(output_dir, exist_ok=True)
    actions_path = os.path.join(output_dir, "actions.jsonl")

    # HARD GATE: package must exist before any action record is written.
    if not package or not os.path.exists(package.get("path", "")):
        raise RuntimeError("REFUSING response: evidence_package.zip does not exist")

    if verdict.get("verdict") not in ("CONFIRMED", "HIGH_CONFIDENCE"):
        result = {"status": "SKIPPED", "mode": "none", "actions": [],
                  "reason": f"verdict {verdict.get('verdict')} does not authorise containment"}
        with open(actions_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(),
                                "action": "playbook_skipped", "target": "",
                                "status": "SKIPPED", "rollback": "",
                                "reason": result["reason"]}) + "\n")
        return result

    if not integrity_ok:
        result = {"status": "REFUSED", "mode": "none", "actions": [],
                  "reason": "integrity failure: untrusted/missing evidence; preservation not trustworthy"}
        with open(actions_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(),
                                "action": "playbook_refused", "target": "",
                                "status": "REFUSED", "rollback": "",
                                "reason": result["reason"]}) + "\n")
        return result

    mode = "execute" if approve else "dry_run"
    adapter = SimulatedAdapters(mode)
    inc_id = _incident_id(verdict)
    user, host = verdict.get("account", ""), verdict.get("endpoint", "")
    domains = [d for d in verdict.get("domains", []) if d][:2]
    device = (verdict.get("usb_device") or "").split(",")[0].strip()

    planned = [adapter.isolate_endpoint(host), adapter.revoke_sessions(user),
               adapter.disable_account(user)]
    planned += [adapter.block_destination(d) for d in domains]
    if device:
        planned.append(adapter.block_usb(device))
    planned.append(adapter.open_incident_record(inc_id))

    incident_path = os.path.join(output_dir, f"incident_{inc_id}.json")
    records = []
    evidence_ids = list(dict.fromkeys(e for f in verdict.get("linked", []) for e in f["evidence_ids"]))[:20]
    for i, a in enumerate(planned, 1):
        rec = {
            "action_id": f"A-{i:02d}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "action": a["action"], "target": a["target"], "status": a["status"],
            "mode": mode, "rollback": a["rollback"], "detail": a["detail"],
            "simulated_command": a["simulated_command"], "requires_approval": True,
            "evidence_package_sha256": package["sha256"],
            "evidence_ids": evidence_ids,
        }
        records.append(rec)
        custody.add(actor, f"response:{a['action']}", a["target"], "",
                    f"{a['status']} mode={mode} rollback={a['rollback']}")

    with open(actions_path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, default=str) + "\n")

    if approve:
        incident = {
            "incident_id": inc_id, "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "playbook_version": PLAYBOOK_VERSION, "status": "OPEN_SIMULATED",
            "verdict": verdict.get("verdict"), "confidence": verdict.get("confidence"),
            "account": user, "endpoint": host, "file": verdict.get("file"),
            "incident_window_utc": [
                verdict["window_start"].strftime("%Y-%m-%dT%H:%M:%SZ") if verdict.get("window_start") else "",
                verdict["window_end"].strftime("%Y-%m-%dT%H:%M:%SZ") if verdict.get("window_end") else "",
            ],
            "method": verdict.get("method"), "destination": verdict.get("destination"),
            "corroborating_sources": verdict.get("sources", []),
            "evidence_package": {"file": "evidence_package.zip", "sha256": package["sha256"]},
            "actions": records,
            "rollback_plan": [a["rollback"] for a in records],
            "notes": "SIMULATED incident. No production system was changed.",
        }
        with open(incident_path, "w", encoding="utf-8") as f:
            json.dump(incident, f, indent=2, default=str)
        custody.add(actor, "incident_record_created", os.path.basename(incident_path),
                    sha256_file(incident_path), f"incident {inc_id} opened")
    return {"status": "EXECUTED" if approve else "DRY_RUN", "mode": mode,
            "actions": records, "incident_id": inc_id,
            "incident_path": incident_path if approve else "", "actions_path": actions_path,
            "reason": ""}
