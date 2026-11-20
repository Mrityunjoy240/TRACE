"""tests.py -- short, focused regression tests (stdlib unittest)."""
from __future__ import annotations

import csv
import json
import os
import shutil
import stat
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone

import pandas as pd

import detect
import respond

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")


def rmtree(path):
    def onerror(func, p, exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    shutil.rmtree(path, onerror=onerror)


def copy_data(tmp):
    dst = os.path.join(tmp, "data")
    shutil.copytree(DATA, dst)
    return dst


def analyse(data_dir, tmp):
    out = os.path.join(tmp, "output")
    ev = os.path.join(tmp, "evidence")
    os.makedirs(out, exist_ok=True)
    custody = detect.CustodyLog(os.path.join(out, "chain_of_custody.jsonl"))
    integrity = detect.preserve_and_verify(data_dir, ev, custody)
    analysis_dir = integrity["evidence_dir"]
    dictionary = detect.load_dictionary(analysis_dir)
    timeline = detect.build_timeline(analysis_dir, integrity, dictionary)
    verdict = detect.detect_all(timeline["rows"], dictionary)

    timeline_csv = os.path.join(out, "timeline.csv")
    findings_json = os.path.join(out, "findings.json")
    pd.DataFrame([{k: (r[k].isoformat() if k == "time_utc" else r[k])
                   for k in ("time_utc", "source", "user", "host", "event", "object", "evidence_id")}
                  for r in timeline["rows"]]).to_csv(timeline_csv, index=False)
    with open(findings_json, "w", encoding="utf-8") as f:
        json.dump({"verdict": verdict["verdict"], "findings": verdict["all_findings"]}, f, default=str)
    package = respond.build_evidence_package(
        out, ev, data_dir, timeline_csv, findings_json,
        os.path.join(out, "chain_of_custody.jsonl"), custody, verdict, integrity)
    return {"out": out, "ev": ev, "custody": custody, "integrity": integrity,
            "timeline": timeline, "verdict": verdict, "package": package}


class TestDigitalEvidenceDetective(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ded_test_")

    def tearDown(self):
        rmtree(self.tmp)

    def test_tampered_hash_detected_and_excluded(self):
        data = copy_data(self.tmp)
        with open(os.path.join(data, "browser.csv"), "a", encoding="utf-8") as f:
            f.write("\n")  # one byte changes the hash
        out = os.path.join(self.tmp, "out")
        custody = detect.CustodyLog(os.path.join(out, "custody.jsonl"))
        integrity = detect.preserve_and_verify(data, os.path.join(self.tmp, "ev"), custody)
        browser = next(f for f in integrity["files"] if f["file"] == "browser.csv")
        self.assertEqual(browser["status"], "UNTRUSTED")
        self.assertIn("MISMATCH", browser["reason"])
        self.assertFalse(integrity["integrity_ok"])
        self.assertNotIn("browser", integrity["trusted_sources"])
        self.assertTrue(detect.verify_custody(os.path.join(out, "custody.jsonl"))[0])

        dictionary = detect.load_dictionary(integrity["evidence_dir"])
        timeline = detect.build_timeline(integrity["evidence_dir"], integrity, dictionary)
        self.assertNotIn("browser", {r["source"] for r in timeline["rows"]})
        verdict = detect.detect_all(timeline["rows"], dictionary)
        self.assertFalse(any(f["source"] == "browser" for f in verdict["linked"]))

    def test_decoys_not_flagged(self):
        data = copy_data(self.tmp)
        res = analyse(data, self.tmp)
        v = res["verdict"]
        self.assertEqual(v["verdict"], "CONFIRMED")
        self.assertEqual(v["account"], "dana.lee")
        decoy_users = {f["user"] for f in v["decoys"]}
        self.assertTrue({"alice.chen", "bob.martin", "svc_backup", "maria.gomez"} <= decoy_users)
        self.assertFalse(decoy_users & {f["user"] for f in v["linked"]})
        self.assertTrue(all(f["decoy_reason"] for f in v["decoys"]))
        self.assertNotIn("backup.acme-internal.com", v["domains"])
        self.assertFalse(any(f["rule"] in ("bulk_backup", "large_internal_transfer",
                                           "approved_usb_write", "service_login")
                             for f in v["linked"]))

    def test_verdict_requires_three_sources_for_confirmed(self):
        now = datetime.now(timezone.utc)

        def finding(source, strong=False):
            return {"source": source, "strong": strong, "user": "u", "host": "H",
                    "time_utc": now, "object": "x", "evidence_ids": ["f:2"],
                    "rule": "r", "severity": "HIGH" if strong else "MEDIUM"}

        target = {"basename": "x.xlsx"}
        d = {"authorized_users": set()}
        self.assertEqual(detect.compute_verdict(
            [finding("authentication"), finding("file_activity"), finding("usb")],
            target, [], d)["verdict"], "CONFIRMED")
        self.assertEqual(detect.compute_verdict(
            [finding("authentication", True), finding("usb")],
            target, [], d)["verdict"], "HIGH_CONFIDENCE")
        self.assertEqual(detect.compute_verdict(
            [finding("authentication"), finding("usb")],
            target, [], d)["verdict"], "SUSPICIOUS")
        self.assertEqual(detect.compute_verdict([], target, [], d)["verdict"], "INCONCLUSIVE")

    def test_containment_refused_without_package(self):
        out = os.path.join(self.tmp, "out")
        os.makedirs(out)
        custody = detect.CustodyLog(os.path.join(out, "custody.jsonl"))
        verdict = {"verdict": "CONFIRMED", "account": "u", "endpoint": "H",
                   "linked": [], "domains": [], "usb_device": ""}
        with self.assertRaises(RuntimeError):
            respond.execute_playbook(verdict, out, True, None, custody, True)
        self.assertFalse(os.path.exists(os.path.join(out, "actions.jsonl")))

    def test_end_to_end_package_then_actions(self):
        data = copy_data(self.tmp)
        res = analyse(data, self.tmp)
        play = respond.execute_playbook(res["verdict"], res["out"], True, res["package"],
                                        res["custody"], res["integrity"]["integrity_ok"])
        self.assertEqual(play["status"], "EXECUTED")
        self.assertTrue(os.path.exists(play["incident_path"]))
        self.assertTrue(os.path.exists(os.path.join(res["out"], "actions.jsonl")))
        self.assertTrue(all(a["status"] == "SIMULATED_OK" and a["rollback"] for a in play["actions"]))
        usb = [a for a in play["actions"] if a["action"] == "block_usb"]
        self.assertEqual(usb[0]["target"], "USB-UNK-9F3C")
        with zipfile.ZipFile(res["package"]["path"]) as zf:
            names = set(zf.namelist())
        for required in ("originals/authentication.csv", "timeline.csv", "findings.json",
                         "chain_of_custody.jsonl", "evidence_manifest.csv", "package_manifest.json"):
            self.assertIn(required, names)
        with open(res["package"]["path"] + ".sha256", encoding="utf-8") as f:
            self.assertEqual(f.read().split()[0], res["package"]["sha256"])
        with open(play["incident_path"], encoding="utf-8") as f:
            incident = json.load(f)
        self.assertEqual(incident["incident_id"], play["incident_id"])
        self.assertTrue(incident["rollback_plan"])


if __name__ == "__main__":
    if not os.path.isdir(DATA):
        raise SystemExit("data/ missing")
    unittest.main(verbosity=2)
