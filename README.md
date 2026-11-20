# Digital Evidence Detective

A reproducible, explainable DFIR CLI prototype that:

1. preserves raw evidence read-only and verifies SHA-256 against a manifest,
2. normalizes six log sources from different timezones into one UTC timeline,
3. detects restricted-file theft with rule-based findings that cite `file:row` evidence IDs,
4. rules out decoys (authorised users, approved USB, scheduled backups, benign cloud use),
5. issues a source-counted verdict, and
6. **builds the evidence package first**, then runs an approval-gated, fully simulated
   containment playbook with rollback commands and an incident record.

No network calls, credentials, or real systems are used.

---

## Quick start

```bash
python -m pip install pandas
python run.py --data ./data                 # verify + analyse + DRY-RUN playbook
python run.py --data ./data --approve       # execute SIMULATED containment
python tests.py                             # 5 regression tests
```

`run.py` prompts `y/N` for containment when run in an interactive terminal and
`--approve` is omitted. In CI/non-interactive shells it stays in DRY-RUN. Use
`--no-prompt` to force DRY-RUN.

Optional flags: `--output ./output`, `--evidence ./evidence`, `--actor analyst:name`.

### Expected demo result

```
VERDICT=CONFIRMED
account=dana.lee  endpoint=WS-0207
file=FY26_Pricing_Model_RESTRICTED.xlsx
window=2026-11-18 23:38:05Z -> 2026-11-19 00:16:00Z
sources=6 (authentication, browser, file_activity, forensic_artifacts, network, usb)
method=USB copy + cloud upload
destination=mega.nz, wetransfer.com, USB-UNK-9F3C
```

> **Evidence notice:** the workspace contained no `./data` directory when this
> prototype was built, so a realistic **synthetic** six-source fixture was created
> (all names/domains fictional, TEST-NET IPs). The analyzer is schema-inferred, not
> tied to this fixture: swap in a real `./data` with the same source concepts and
> update `data_dictionary.md`.

---

## Outputs (`./output/`)

| File | Purpose |
|---|---|
| `report.md` / `report.html` | Full report: executive summary, integrity, timeline, verdict, decoys, facts vs assumptions, actions/rollback, limitations |
| `timeline.csv` | De-duplicated merged timeline with UTC + per-source local time |
| `findings.json` | Machine-readable verdict, findings, integrity, parse failures, duplicates |
| `chain_of_custody.jsonl` | Hash-chained audit log (`prev_entry_hash` -> `entry_hash`) |
| `actions.jsonl` | Every planned/executed action with target, status, rollback, evidence IDs |
| `evidence_package.zip` | Originals, manifest, timeline, findings, custody log, package manifest |
| `evidence_package.zip.sha256` | Package digest sidecar |
| `incident_INC-XXXX.json` | Created only with `--approve` (simulated incident) |

Raw files are copied to `./evidence/original/` and made read-only (`chmod 444`).
Analysis reads those copies, never the raw inputs.

---

## Pipeline (exact order)

1. **Preserve + verify** - copy all raw files to `evidence/original`, set read-only,
   hash the copies, compare to `evidence_manifest.csv`. Mismatch/missing/not-listed
   => `UNTRUSTED`, excluded from findings, reported as possible tampering.
   A missing manifest or a preservation failure blocks containment.
2. **Normalize time** - per-source timezone comes from `data_dictionary.md`
   (`America/New_York`, `Asia/Kolkata`, `Europe/London`, `America/Los_Angeles`, UTC).
   Naive values are localized, aware values converted; epoch seconds/ms and mixed
   formats supported. Failures are logged with evidence IDs.
3. **Build timeline** - merge all six sources into
   `time_utc, time_local, source_tz, source, user, host, event, object, evidence_id`.
   Exact duplicate rows are suppressed and listed. Usernames are trimmed/lowercased
   (`Dana.Lee ` -> `dana.lee`); hosts uppercased.
4. **Detect** - target workbook identified from data (`RESTRICTED` classification +
   `pricing`/`model`/workbook filename scoring + dictionary hint), not hardcoded.
   Rules: restricted read/copy/rename/archive/delete, unapproved USB write, USB copy
   of the restricted archive, cloud/file-share/webmail visits, large external
   outbound transfers, off-hours/new-device/failed authentication, anti-forensics
   (log clear, timestomp, wipe tool, deletion). Correlate by `(user, host)` within a
   3-hour window around the first restricted-file event.
5. **Verdict** - count independent source types corroborating the same account +
   endpoint + file:
   - `>= 3` sources -> `CONFIRMED`
   - `2` sources with a strong indicator -> `HIGH_CONFIDENCE`
   - otherwise -> `SUSPICIOUS` / `INCONCLUSIVE` (no containment)
6. **Response** - build `evidence_package.zip` first, then:
   `isolate_endpoint` -> `revoke_sessions` -> `disable_account` ->
   `block_destination` (top external domains) -> `block_usb` -> `open_incident_record`.
   Every adapter is simulated and returns a rollback command. Default is DRY-RUN.
7. **Report** - facts cite evidence IDs; assumptions/gaps are separated.

---

## Decoys explicitly tested

| Decoy | Why ruled out |
|---|---|
| `alice.chen` reads the restricted workbook | On the authorised-user allow-list, business hours, read-only, no USB/network exfiltration |
| `bob.martin` writes to USB | Device `USB-APPR-1140` is approved; file is non-restricted |
| `svc_backup` 2.5 GB copy | Service account, scheduled 02:00 UTC job, internal backup destination |
| `maria.gomez` visits OneDrive | Cloud browse with no restricted-file access by that account |
| `svc_backup` clears logs on `SRV-BACKUP01` | Scheduled `logrotate` maintenance, different account/host, outside window |
| Duplicate export rows | Suppressed before counting; corroboration counts source types, not volume |

---

## Design and integrity details

- **No hardcoded columns:** `detect.infer_schema()` maps aliases to canonical roles
  (time/user/host/event/path/new_path/device/domain/bytes/...). Missing time column
  is a hard, reported failure.
- **No hardcoded accounts:** the suspect is selected by correlation; authorised users,
  approved USB devices and backup destinations come from the dictionary and/or data.
- **Hash-chained custody:** each entry includes `timestamp, actor, action, file,
  sha256, prev_entry_hash, entry_hash`. `verify_custody()` recomputes the chain.
- **Package before action:** `respond.execute_playbook()` raises if
  `evidence_package.zip` is absent; the test suite asserts no `actions.jsonl` is
  written in that case.
- **Tamper handling:** tampered sources are marked `UNTRUSTED`, excluded from the
  timeline/findings, and containment is refused (`integrity_ok=False`).

---

## Tests

`python tests.py` covers:

1. tampered SHA-256 is detected, source excluded, custody chain still valid;
2. decoy users/devices/backups are not linked to the verdict;
3. `CONFIRMED` requires 3 independent sources; 2 strong -> `HIGH_CONFIDENCE`;
4. containment raises and writes no actions when the package is missing;
5. end-to-end package -> actions -> incident, zip contents, sidecar hash, rollback,
   and `block_usb` targets the device ID (`USB-UNK-9F3C`), not a file path.

---

## Assumptions and limitations

- Synthetic fixture: findings demonstrate the method, not a real breach.
- Target identification is heuristic; a differently named restricted workbook may
  need a dictionary hint or a classification field.
- "External" is derived from domain/IP and an internal/SaaS allow-list; DNS is not
  independently resolved and IP geolocation is unverified.
- No EDR process lineage, DLP content inspection, VPN, mail, or cloud-provider logs;
  transferred content and destination-side opening are unknown.
- Corroboration uses a 3-hour window; a patient attacker spacing actions wider would
  reduce the source count (and correctly lower confidence).
- Adapters are simulated. They prove orchestration, ordering, gating and rollback,
  not integration with real EDR/IAM/firewall APIs.
- `evidence_manifest.csv` is the trust anchor; if manifest and data share a
  compromised source, hashes alone do not establish provenance. Sign it externally
  in production. The custody chain starts at preservation, not acquisition.
- The package is sealed before response, so later action entries exist only in the
  live custody log; production should re-seal or append a signed delta.

---

## Two-minute demo script

**0:00 - Context.** "The workspace had no evidence, so I generated a documented
six-source synthetic case. The code infers columns and accounts; nothing is
hardcoded."

**0:10 - Run dry-run.**
```bash
python run.py --data ./data --no-prompt
```
Point out:
- Step 0 prints columns/dtypes/rows/samples/value counts; note the USB schema trap
  caught during inspection.
- Integrity table: all `TRUSTED`, manifest is `REFERENCE`, custody chain valid.
- Timezone normalization: USB `05:25 +0530` becomes `23:55Z`; forensic `16:12 -0800`
  becomes `00:12Z` next day. Duplicates suppressed.
- Verdict: `CONFIRMED`, `dana.lee` / `WS-0207`, 6 sources, window 23:38-00:16Z.
- Decoys table: alice (authorised, business hours), bob (approved USB), svc_backup
  (scheduled internal backup), maria (cloud browse without file access).
- Package SHA-256 printed **before** the DRY-RUN action list; every action has a
  rollback.

**1:10 - Execute simulated containment.**
```bash
python run.py --data ./data --approve
```
Open `output/incident_INC-4613.json` and `output/actions.jsonl`; show
`isolate_endpoint`, `revoke_sessions`, `disable_account`, `block_destination`,
`block_usb` (`USB-UNK-9F3C`), `open_incident_record`, each `SIMULATED_OK` with a
rollback.

**1:35 - Prove the guardrails.**
```bash
python tests.py
```
Highlight: tampered hash excluded; decoys not flagged; 3-source threshold; no
containment without a package.

**1:50 - Close.** "Facts cite evidence IDs, assumptions/gaps are separate, and the
response is ordered, reversible and simulated."
