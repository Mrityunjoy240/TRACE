"""run.py -- CLI orchestration for Digital Evidence Detective.

Usage:
  python run.py --data ./data            # verify + analyse + DRY-RUN playbook
  python run.py --data ./data --approve  # execute SIMULATED containment
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from datetime import datetime, timezone

import pandas as pd

import detect
import respond


def fmt(dt):
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%SZ")


def short(h, n=12):
    return (h or "")[:n]


def esc(v):
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(esc(c) for c in r) + " |")
    return "\n".join(out)


def write_timeline(rows, path):
    data = [{
        "time_utc": fmt(r["time_utc"]), "time_local": r["time_local"],
        "source_tz": r["source_tz"], "source": r["source"], "user": r["user"],
        "host": r["host"], "event": r["event"], "object": r["object"],
        "evidence_id": r["evidence_id"],
    } for r in rows]
    pd.DataFrame(data).to_csv(path, index=False, encoding="utf-8")


def build_report(ctx) -> str:
    v = ctx["verdict"]
    integ = ctx["integrity"]
    tl = ctx["timeline"]
    pkg = ctx["package"]
    play = ctx["play"]
    dict_text = ctx["dictionary"].get("text", "")
    synthetic = "synthetic" in dict_text.lower()

    wstart, wend = v.get("window_start"), v.get("window_end")
    window = f"{fmt(wstart)} to {fmt(wend)} UTC"
    if wstart and wend:
        def local_of(dt):
            r = next((x for x in tl["rows"] if x["time_utc"] == dt), None)
            return f"{r['time_local']} ({r['source_tz']})" if r else ""
        ls, le = local_of(wstart), local_of(wend)
        if ls and le:
            window += f"; local: {ls} -> {le}"
    linked = v.get("linked", [])
    decoys = v.get("decoys", [])
    all_findings = v.get("all_findings", [])

    L = []
    L.append("# Digital Evidence Detective - Investigation Report\n")
    L.append(f"**Generated:** {detect.now_iso()}  ")
    L.append(f"**Case:** Suspected theft of restricted pricing data  ")
    L.append(f"**Data set:** `{ctx['data_dir']}`  ")
    L.append(f"**Report mode:** {'SIMULATED EXECUTION' if ctx['approve'] else 'DRY-RUN'}\n")
    if synthetic:
        L.append("> **Evidence notice:** the supplied evidence set is synthetic training data. "
                 "All identities, hosts and destinations are fictional.\n")

    L.append("## 1. Executive summary\n")
    L.append(f"**Verdict: {v.get('verdict')}**  ")
    L.append(f"**Account:** `{v.get('account') or 'n/a'}`  ")
    L.append(f"**Endpoint:** `{v.get('endpoint') or 'n/a'}`  ")
    L.append(f"**File:** `{v.get('file') or 'n/a'}`  ")
    L.append(f"**Incident window:** {window}  ")
    L.append(f"**Method:** {v.get('method') or 'n/a'}  ")
    L.append(f"**Destination / device:** {v.get('destination') or 'n/a'}  ")
    L.append(f"**Independent corroborating sources:** {v.get('source_count', 0)} "
             f"({', '.join(v.get('sources', [])) or 'none'})  ")
    L.append(f"**Response:** {play.get('status')} - {play.get('reason') or 'see actions table'}\n")
    if v.get("verdict") == "CONFIRMED":
        L.append(f"The evidence independently shows the account `{v.get('account')}` on `{v.get('endpoint')}` "
                 f"accessing and staging the restricted workbook, writing it to an unapproved USB device, "
                 f"uploading data to external cloud/file-share destinations, and then attempting to destroy "
                 f"artifacts on the endpoint. {v.get('source_count')} independent source types agree, so the "
                 f"verdict is CONFIRMED and the simulated containment playbook is authorised.\n")
    elif v.get("verdict") == "HIGH_CONFIDENCE":
        L.append("Two independent source types with strong indicators agree. The verdict is HIGH_CONFIDENCE; "
                 "containment is authorised but a second corroborating source is still desirable.\n")
    else:
        L.append("The evidence does not meet the CONFIRMED/HIGH_CONFIDENCE threshold. No containment is authorised; "
                 "collect more telemetry.\n")

    L.append("## 2. Integrity results\n")
    L.append(f"**Preservation succeeded:** {integ.get('preservation_ok')}  ")
    L.append(f"**Integrity verified:** {integ.get('integrity_ok')}  ")
    L.append(f"**Custody chain:** {ctx['custody_status']}  ")
    L.append(f"**Raw files copied read-only to:** `{ctx['evidence_dir']}/original`  ")
    L.append(f"**Exact duplicate rows suppressed:** {len(tl['duplicates'])}  ")
    L.append(f"**Timestamp parse failures (excluded):** {len(tl['failures'])}\n")
    L.append(md_table(
        ["File", "Source", "Expected SHA-256", "Actual SHA-256", "Status", "Reason", "Included"],
        [[f["file"], f["source"] or "-", short(f["expected"]), short(f["actual"]),
          f["status"], f["reason"], f["included"]] for f in integ["files"]]))
    if integ["untrusted"]:
        L.append(f"\n**UNTRUSTED / POSSIBLE TAMPERING:** {', '.join(integ['untrusted'])}. "
                 "These files were excluded from findings and containment is refused.\n")
    if tl["failures"]:
        L.append("\n**Unparsed timestamps (excluded, listed for audit):**\n")
        L.append(md_table(["Evidence ID", "Source", "Raw value", "Reason"],
                          [[x["evidence_id"], x["source"], x["raw"], x["reason"]] for x in tl["failures"]]))
    if tl["duplicates"]:
        L.append("\n**Duplicate rows (kept first occurrence):**\n")
        L.append(md_table(["Source", "Kept evidence_id", "Dropped evidence_id"],
                          [[d["source"], d["kept"], d["dropped"]] for d in tl["duplicates"][:20]]))

    L.append("\n## 3. Timeline\n")
    L.append(f"All six sources are normalized to UTC and also shown in each source's local timezone "
             f"(`timeline.csv`, {len(tl['rows'])} de-duplicated events).\n")
    L.append("### 3.1 Correlated incident window\n")
    L.append(md_table(["UTC", "Local (source tz)", "Source", "User", "Host", "Event", "Object", "Evidence"],
                      [[fmt(f["time_utc"]), next((r["time_local"] for r in tl["rows"] if r["evidence_id"] == f["evidence_ids"][0]), ""),
                        f["source"], f["user"], f["host"], f["rule"], f["object"], ", ".join(f["evidence_ids"])]
                       for f in linked]))
    L.append("\n### 3.2 Other events and ruled-out context\n")
    others = [f for f in all_findings if f["decoy"]]
    L.append(md_table(["UTC", "Source", "User", "Host", "Event", "Object", "Evidence"],
                      [[fmt(f["time_utc"]), f["source"], f["user"], f["host"], f["rule"], f["object"],
                        ", ".join(f["evidence_ids"])] for f in others]))
    L.append("\nFull merged timeline (including non-finding events) is in `timeline.csv`.\n")

    L.append("## 4. Verdict and reasoning\n")
    L.append(f"**Confidence rule:** >=3 independent source types => CONFIRMED; 2 source types with a strong "
             f"indicator => HIGH_CONFIDENCE; otherwise SUSPICIOUS/INCONCLUSIVE with no containment. "
             f"This case has **{v.get('source_count')}** independent sources and "
             f"**{'a' if v.get('strong_indicator') else 'no'} strong indicator**.\n")
    src_rows = []
    for s in v.get("sources", []):
        fs = [f for f in linked if f["source"] == s]
        src_rows.append([s, len(fs), ", ".join(sorted({e for f in fs for e in f["evidence_ids"]})),
                         "; ".join(sorted({f["rule"] for f in fs}))])
    L.append(md_table(["Independent source", "Linked events", "Evidence IDs", "Rules"], src_rows))
    L.append("\n### 4.1 Who / What / When / How\n")
    L.append(md_table(["Question", "Answer"], [
        ["Who", f"`{v.get('account')}` on endpoint `{v.get('endpoint')}`"],
        ["What", f"Restricted workbook `{v.get('file')}` read, copied/archived, then moved out"],
        ["When", window],
        ["How", f"{v.get('method')} via {v.get('destination')}"],
    ]))
    L.append("")

    L.append("## 5. Decoys ruled out\n")
    L.append("Each alternative explanation was explicitly tested. These events are **not** counted toward the verdict.\n")
    grouped = {}
    for f in decoys:
        key = (f["user"], f["decoy_reason"])
        g = grouped.setdefault(key, {"sources": set(), "ids": [], "events": set()})
        g["sources"].add(f["source"])
        g["ids"].extend(f["evidence_ids"])
        g["events"].add(f["rule"])
    L.append(md_table(["Account", "Observed", "Why it is NOT the incident", "Evidence IDs"],
                      [[u, ", ".join(sorted(g["events"])), reason, ", ".join(sorted(set(g["ids"])))]
                       for (u, reason), g in grouped.items()]) if grouped else "_No decoys matched._")
    L.append("")

    L.append("## 6. Facts vs assumptions\n")
    L.append("### 6.1 FACTS (each cites evidence)\n")
    for f in linked:
        L.append(f"- **{f['id']} / {f['rule']}** ({f['severity']}, {fmt(f['time_utc'])}) - "
                 f"{f['description']} `[{', '.join(f['evidence_ids'])}]`")
    L.append("\n### 6.2 ASSUMPTIONS and GAPS\n")
    L.append(f"- **Assumption:** the target file was identified from the data (classification/name heuristic) as "
             f"`{v.get('target', {}).get('basename')}`; its evidence rows are "
             f"`{', '.join(v.get('target', {}).get('evidence_ids', []))}`.")
    L.append("- **Assumption:** naive timestamps are local to the timezone declared in `data_dictionary.md`; "
             "timezone-aware values are converted directly. Local times are displayed alongside UTC.")
    L.append("- **Assumption:** exact duplicate rows are export artifacts and are counted once; corroboration counts "
             "source *types*, not event volume.")
    L.append("- **Assumption:** 'external' means a non-internal domain/IP outside the approved SaaS/backup allow-list; "
             "DNS/domain attribution is taken from the log, not independently resolved.")
    L.append("- **Gap:** no EDR process lineage, DLP content inspection, VPN, mail or cloud-provider logs; the exact "
             "bytes transferred and whether the archive was opened at the destination are unknown.")
    L.append("- **Gap:** IP geolocation and device ownership are not independently verified; insider theft vs. "
             "compromised credentials cannot be distinguished from these logs alone.")
    L.append("- **Gap:** the evidence package and its custody snapshot are point-in-time; response actions are "
             "simulated and do not alter any real system.")
    if synthetic:
        L.append("- **Gap:** this run uses a synthetic evidence fixture, so findings demonstrate the method rather "
                 "than a real incident.")
    L.append("")

    L.append("## 7. Actions taken and rollback\n")
    L.append(f"**Order enforced:** evidence package created first (`{os.path.basename(pkg['path']) if pkg else 'NOT CREATED'}`), "
             f"then containment. Package SHA-256: `{pkg['sha256'] if pkg else 'n/a'}`.  ")
    L.append(f"**Mode:** {play.get('mode')} - {'no real system was changed' if not ctx['approve'] else 'simulated adapters executed'}.\n")
    if play.get("actions"):
        L.append(md_table(["#", "Action", "Target", "Status", "Rollback"],
                          [[a["action_id"], a["action"], a["target"], a["status"], a["rollback"]]
                           for a in play["actions"]]))
        if play.get("incident_id"):
            if play.get("incident_path"):
                L.append(f"\n**Incident record:** `{os.path.basename(play.get('incident_path',''))}` "
                         f"({play.get('incident_id')})")
            else:
                L.append(f"\n**Incident record:** would create `incident_{play.get('incident_id')}.json` "
                         f"(dry-run; not created)")
    else:
        L.append(f"**No actions executed.** {play.get('reason')}")
    L.append("\n**Approval gate:** any action that could alter evidence or production state requires `--approve` "
             "or an interactive `y`; default is DRY-RUN. Containment is refused if preservation or integrity fails.\n")

    L.append("## 8. Limitations\n")
    L.append("- Rule-based detection is explainable but not behavioural; a novel exfiltration path may be missed.")
    L.append("- Corroboration uses a 3-hour window around the first restricted-file event; a patient attacker "
             "spacing actions beyond that window would reduce the source count.")
    L.append("- Simulated adapters prove orchestration and rollback design, not integration with EDR/IAM/firewall APIs.")
    L.append("- `evidence_manifest.csv` is treated as the trust anchor; if the manifest and data share a compromised "
             "source, hashes alone cannot establish provenance. Sign the manifest externally in production.")
    L.append("- The custody chain starts at preservation, not at acquisition; it proves post-collection integrity, "
             "not who collected the data before this tool ran.")
    L.append("- The package is written before response so response logs are appended to the live custody log after "
             "packaging; a production workflow would re-package or seal the log.")
    return "\n".join(L)


def md_to_html(md: str, title: str) -> str:
    lines = md.splitlines()
    out, in_table, in_list = [], False, False
    for line in lines:
        s = line.rstrip()
        if s.startswith("|") and s.endswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
                continue
            if not in_table:
                out.append("<table>")
                in_table = True
                out.append("<tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr>")
            else:
                out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        if in_list and not s.startswith("- "):
            out.append("</ul>")
            in_list = False
        if s.startswith("#"):
            level = len(s) - len(s.lstrip("#"))
            out.append(f"<h{level}>{inline(s.lstrip('# ').strip())}</h{level}>")
        elif s.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(s[2:])}</li>")
        elif s.startswith(">"):
            out.append(f"<blockquote>{inline(s.lstrip('> ').strip())}</blockquote>")
        elif s.strip() == "":
            out.append("")
        else:
            out.append(f"<p>{inline(s)}</p>")
    if in_table:
        out.append("</table>")
    if in_list:
        out.append("</ul>")
    body = "\n".join(out)
    body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", body)
    body = re.sub(r"`(.+?)`", r"<code>\1</code>", body)
    body = body.replace("  \n", "<br>")
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1b1b1b}}
table{{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.88rem}}th,td{{border:1px solid #ccc;padding:.4rem;text-align:left;vertical-align:top}}
th{{background:#f2f4f7}}code{{background:#f4f4f4;padding:.1rem .25rem;border-radius:3px;word-break:break-all}}
blockquote{{border-left:4px solid #c9a227;background:#fffbea;padding:.5rem 1rem}}h1{{border-bottom:2px solid #333}}</style>
</head><body>{body}</body></html>"""


def inline(s):
    s = html.escape(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


def main():
    ap = argparse.ArgumentParser(description="Digital Evidence Detective - DFIR CLI prototype")
    ap.add_argument("--data", default="./data")
    ap.add_argument("--output", default="./output")
    ap.add_argument("--evidence", default="./evidence")
    ap.add_argument("--approve", action="store_true", help="execute the SIMULATED containment playbook")
    ap.add_argument("--no-prompt", action="store_true", help="never ask interactively; default to dry-run")
    ap.add_argument("--actor", default="analyst:cli")
    args = ap.parse_args()

    data_dir = os.path.abspath(args.data)
    out_dir = os.path.abspath(args.output)
    ev_dir = os.path.abspath(args.evidence)
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 72)
    print("DIGITAL EVIDENCE DETECTIVE")
    print("=" * 72)
    if not os.path.isdir(data_dir):
        print(f"ERROR: data directory not found: {data_dir}")
        return 2

    detect.inspect_data(data_dir)

    custody_path = os.path.join(out_dir, "chain_of_custody.jsonl")
    custody = detect.CustodyLog(custody_path)
    print("\n=== STEP 1: PRESERVE + VERIFY ===")
    integrity = detect.preserve_and_verify(data_dir, ev_dir, custody, actor="system:preservation")
    integrity["untrusted"] = [f["file"] for f in integrity["files"] if f["status"] == "UNTRUSTED"]
    for f in integrity["files"]:
        print(f"  {f['status']:9} {f['file']:28} {f['reason']}")
    print(f"  integrity_ok={integrity['integrity_ok']} preservation_ok={integrity['preservation_ok']}")

    analysis_dir = integrity["evidence_dir"]
    dictionary = detect.load_dictionary(analysis_dir)
    print(f"\n=== STEP 2/3: NORMALIZE TIME + BUILD TIMELINE ===")
    print(f"  timezones from dictionary: {dictionary['timezones']}")
    timeline = detect.build_timeline(analysis_dir, integrity, dictionary)
    print(f"  raw rows={timeline['raw_count']} unique={len(timeline['rows'])} "
          f"duplicates={len(timeline['duplicates'])} parse_failures={len(timeline['failures'])}")

    print("\n=== STEP 4/5: DETECT + VERDICT ===")
    verdict = detect.detect_all(timeline["rows"], dictionary)
    target = verdict["target"]
    print(f"  target file: {target.get('path')}")
    print(f"  account={verdict.get('account')} endpoint={verdict.get('endpoint')}")
    print(f"  window={fmt(verdict.get('window_start'))} -> {fmt(verdict.get('window_end'))}")
    print(f"  sources={verdict.get('sources')} count={verdict.get('source_count')}")
    print(f"  VERDICT={verdict.get('verdict')} method={verdict.get('method')} dest={verdict.get('destination')}")
    decoys = [f for f in verdict["all_findings"] if f["decoy"]]
    print(f"  findings={len(verdict['all_findings'])} linked={len(verdict['linked'])} decoys={len(decoys)}")
    for u, r in sorted({(f["user"], f["decoy_reason"]) for f in decoys}):
        print(f"    decoy: {u:14} {r}")

    timeline_csv = os.path.join(out_dir, "timeline.csv")
    findings_json = os.path.join(out_dir, "findings.json")
    write_timeline(timeline["rows"], timeline_csv)
    with open(findings_json, "w", encoding="utf-8") as f:
        json.dump({
            "generated_utc": detect.now_iso(), "verdict": verdict["verdict"],
            "account": verdict["account"], "endpoint": verdict["endpoint"],
            "window_start": fmt(verdict["window_start"]), "window_end": fmt(verdict["window_end"]),
            "sources": verdict["sources"], "source_count": verdict["source_count"],
            "target": target, "method": verdict["method"], "destination": verdict["destination"],
            "findings": verdict["all_findings"],
            "linked": verdict["linked"],
            "decoys": [f for f in verdict["all_findings"] if f["decoy"]],
            "integrity": integrity,
            "parse_failures": timeline["failures"],
            "duplicates": timeline["duplicates"],
        }, f, indent=2, default=str)

    print("\n=== STEP 6: EVIDENCE PACKAGE (BEFORE RESPONSE) ===")
    package = None
    if integrity["preservation_ok"]:
        package = respond.build_evidence_package(
            out_dir, ev_dir, data_dir, timeline_csv, findings_json, custody_path,
            custody, verdict, integrity, actor="system:packaging")
        print(f"  package={package['path']}")
        print(f"  sha256={package['sha256']}")
    else:
        print("  REFUSED: preservation did not succeed; no package and no response")

    approve = args.approve
    if not approve and not args.no_prompt and sys.stdin.isatty():
        try:
            ans = input("\nExecute SIMULATED containment playbook? [y/N] ").strip().lower()
            approve = ans in ("y", "yes")
        except EOFError:
            approve = False
    if not approve:
        print("  (DRY-RUN: showing planned actions; pass --approve to execute simulated adapters)")

    print("\n=== STEP 6b: RESPONSE PLAYBOOK ===")
    try:
        play = respond.execute_playbook(verdict, out_dir, approve, package, custody,
                                        integrity["integrity_ok"], actor=args.actor)
    except RuntimeError as e:
        play = {"status": "REFUSED", "mode": "none", "actions": [], "reason": str(e),
                "incident_id": "", "incident_path": "", "actions_path": ""}
        print(f"  {e}")
    print(f"  status={play['status']} mode={play['mode']} {play.get('reason','')}")
    for a in play.get("actions", []):
        print(f"    {a['action_id']} {a['action']:24} {a['target']:24} {a['status']:12} rollback: {a['rollback']}")
    if play.get("incident_id"):
        print(f"  incident={play['incident_id']} path={play.get('incident_path')}")

    custody_ok, custody_msg = detect.verify_custody(custody_path)
    print(f"\n  custody chain: {custody_ok} ({custody_msg})")

    ctx = {"verdict": verdict, "integrity": integrity, "timeline": timeline, "package": package,
           "play": play, "dictionary": dictionary, "data_dir": data_dir, "evidence_dir": ev_dir,
           "approve": approve, "custody_status": f"{custody_ok} ({custody_msg})"}
    report_md = build_report(ctx)
    report_path = os.path.join(out_dir, "report.md")
    html_path = os.path.join(out_dir, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_md)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(md_to_html(report_md, "Digital Evidence Detective Report"))

    print("\n=== OUTPUTS ===")
    for p in [report_path, html_path, timeline_csv, findings_json, custody_path,
              play.get("actions_path", ""), play.get("incident_path", ""),
              package["path"] if package else "", package["path"] + ".sha256" if package else ""]:
        if p and os.path.exists(p):
            print(f"  {p}")
    print(f"\nDONE. Verdict={verdict['verdict']}. Response={play['status']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
