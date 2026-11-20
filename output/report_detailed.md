# Digital Forensic Investigation Report
## Suspected Exfiltration of Restricted Pricing Data

**Report ID:** DED-2026-11-20-001  
**Classification:** Internal - DFIR Training Exercise  
**Prepared for:** TCS Hackathon evaluation panel  
**Prepared by:** Digital Evidence Detective v1.0 (automated analysis)  
**Reviewer:** ______________________________  
**Report date:** 2026-11-20  
**Analysis generated:** 2026-11-20T09:47:26Z  
**Distribution:** Evaluators, Incident Response Lead, Data Owner, Legal/HR as appropriate

> **Evidence provenance notice.** This report was produced from a synthetic six-source training evidence set created for this prototype. All people, hosts, IP addresses and domains are fictional; destinations use TEST-NET ranges. Nothing in this report describes a real person, organisation or production system. The analytical method, integrity controls and response orchestration are real and reproducible.

## Document control
| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-11-20 | Digital Evidence Detective (automated) | Initial professional report generated from verified run artifacts |

## 1. Executive summary

**Verdict: CONFIRMED.** The account `dana.lee` on endpoint `WS-0207` accessed the restricted pricing workbook `FY26_Pricing_Model_RESTRICTED.xlsx`, copied and archived it, wrote the archive to unapproved USB device `USB-UNK-9F3C`, visited cloud/file-share services, transferred approximately 46 MB and 12 MB to `mega.nz` and `wetransfer.com`, and then executed anti-forensic actions on the endpoint. **Six independent source types** corroborate the same account, endpoint and file within the incident window.

**Incident window (UTC):** 2026-11-18 23:38:05Z to 2026-11-19 00:16:00Z.  
**Method:** USB copy + cloud upload.  
**Destinations / device:** mega.nz, wetransfer.com, USB-UNK-9F3C.  
**Response:** evidence package sealed first (SHA-256 below), then seven simulated containment actions with rollback commands; incident record `INC-4613` opened. No production system was changed.

**Impact statement.** The confidentiality of a restricted pricing workbook is assessed as breached. The data may have left through two independent channels (USB and cloud), so containment must assume the workbook is outside the organisation's control. Financial, competitive and contractual impact cannot be quantified from these logs alone.

**Key judgement.** The activity is not consistent with authorised business use, scheduled backup, approved USB use or routine log maintenance. It is consistent with deliberate staging and exfiltration followed by anti-forensic cleanup. Whether the actor is the account owner or a third party using compromised credentials remains unresolved.

## 2. Scope, authority and evidence

### 2.1 Scope
- **In scope:** six log sources (`authentication`, `file_activity`, `usb`, `browser`, `network`, `forensic_artifacts`), the evidence manifest, the data dictionary, account `dana.lee`, endpoint `WS-0207`, and the restricted pricing workbook.
- **Out of scope:** disk and memory forensics, EDR process lineage, DLP content inspection, VPN, mail, cloud-provider logs, HR records, legal attribution and law-enforcement notification.
- **Authority:** simulated DFIR exercise. The response adapters are simulated; no firewall, IAM, EDR or USB policy was changed.

### 2.2 Evidence inventory and integrity
Preservation succeeded: **True**. Integrity verification succeeded: **True**. Manifest present: **True**. Raw files were copied to `C:\Users\Asus\OneDrive\Desktop\TCS Hackathon\evidence\original` and set read-only (`0444`); analysis read the copies.

| File | Source | Timezone | Rows | Integrity | SHA-256 (truncated) | Included |
|---|---|---|---|---|---|---|
| authentication.csv | authentication | America/New_York (UTC-05:00) | 7 | TRUSTED | 446a08b7085caa2517f607ba | True |
| browser.csv | browser | Europe/London (UTC+00:00) | 6 | TRUSTED | 79c906f9b1c5d2c5abd937c1 | True |
| data_dictionary.md | reference | n/a | n/a | TRUSTED | 585bb2b0ecc2f5cb19323b2c | False |
| evidence_manifest.csv | reference | n/a | n/a | REFERENCE | eba7c864dc21f47d6eecb867 | False |
| file_activity.csv | file_activity | UTC | 10 | TRUSTED | 4ab2e1807eebec01f29ae39e | True |
| forensic_artifacts.csv | forensic_artifacts | America/Los_Angeles (UTC-08:00) | 4 | TRUSTED | 5a292bb315114264765bcd9f | True |
| network.csv | network | UTC | 6 | TRUSTED | e6fe8f3a18434151eb5fc625 | True |
| usb.csv | usb | Asia/Kolkata (UTC+05:30) | 5 | TRUSTED | d2ff624607e86e7bb8a1be05 | True |

The manifest contains **7** file hashes. All six source files and the data dictionary match their manifest SHA-256. `evidence_manifest.csv` is marked **REFERENCE** because it is the trust anchor and cannot self-hash. No file was UNTRUSTED in this run; a tampered-file test is documented in section 11.

### 2.3 Evidence package
The package was created **before** any response action: `evidence_package.zip`, **12,471 bytes**, **13 members** (including 8 originals), SHA-256 `f980fc3b95e818b111c868f8c5360b8ce0eb36245fd12f87e7a757e67e03710c`. The sidecar `evidence_package.zip.sha256`, the incident record and every action record carry the same digest.

### 2.4 Chain of custody
The custody log contains **26** hash-chained entries. Verification result: **(True, 'chain valid')**. First entry `ffcc2b61dc12dc2867750002...`; last entry `21803f02b035a9e5d2710c9a...`.

| Custody action | Entries |
|---|---|
| evidence_package_created | 1 |
| incident_record_created | 1 |
| preservation_summary | 1 |
| preserve_copy | 8 |
| response:block_destination | 2 |
| response:block_usb | 1 |
| response:disable_account | 1 |
| response:isolate_endpoint | 1 |
| response:open_incident_record | 1 |
| response:revoke_sessions | 1 |
| verify_hash | 8 |

Each entry includes `timestamp`, `actor`, `action`, `file`, `sha256`, `prev_entry_hash` and a computed `entry_hash`. Any insertion, deletion or edit breaks the chain at the next entry.

## 3. Methodology

The analysis followed a fixed, reproducible sequence:

1. **Preserve + verify.** Copy every raw file to `evidence/original`, set read-only, compute SHA-256 and compare with `evidence_manifest.csv`. A mismatch, missing file, unlisted file or missing manifest marks the file UNTRUSTED and excludes it from findings.
2. **Normalize time.** Apply the per-source timezone declared in `data_dictionary.md`: authentication `America/New_York`, file_activity UTC, USB `Asia/Kolkata`, browser `Europe/London`, network UTC, forensic_artifacts `America/Los_Angeles`. Convert all values to UTC and retain local time for reporting. Epoch values and mixed formats are supported; failures are logged with evidence IDs.
3. **Build timeline.** Merge all six sources into `time_utc, time_local, source_tz, source, user, host, event, object, evidence_id`. Normalize usernames (trim, lowercase, domain-prefix removal) and hosts (uppercase). Suppress exact duplicate rows and record them.
4. **Detect.** Infer columns through aliases; identify the target from data (`RESTRICTED` classification, `pricing`/`model`/workbook filename, dictionary hint). Apply explainable rules for restricted-file access, archiving, USB writes, cloud visits, external transfers, anomalous authentication and anti-forensics.
5. **Correlate.** Group findings by `(user, host)` and retain events within three hours of the first restricted-file event. Count independent source types, not event volume.
6. **Verdict.** `>=3` independent sources -> `CONFIRMED`; `2` sources with a strong indicator -> `HIGH_CONFIDENCE`; otherwise `SUSPICIOUS`/`INCONCLUSIVE` with no containment.
7. **Respond.** Build and seal the evidence package first. Then execute the playbook only with `--approve` or an interactive `y`; default is DRY-RUN. Every action is simulated and carries a rollback command.

### 3.1 Target identification
Target: `\\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx`. Classification: **RESTRICTED**. Evidence rows: `file_activity.csv:2, file_activity.csv:3, file_activity.csv:7, file_activity.csv:8, file_activity.csv:9`. The file scored highest because it carries the `RESTRICTED` label, contains `pricing`, `model` and `.xlsx` tokens, and matches the dictionary target hint. No path or username is hardcoded in the detector.

### 3.2 Time normalization evidence
The same incident spans different local dates because sources use different zones. Examples:

| UTC | Local time | Source | Why it matters |
|---|---|---|---|
| 2026-11-18 23:38:05Z | 2026-11-18 18:38:05 -0500 | authentication | Failed login appears 18:38 EST, still 18 Nov |
| 2026-11-18 23:55:00Z | 2026-11-19 05:25:00 +0530 | usb | USB connect appears 19 Nov in IST |
| 2026-11-19 00:12:00Z | 2026-11-18 16:12:00 -0800 | forensic_artifacts | Log clear appears 18 Nov in PST |

## 4. Incident narrative

The following sequence is reconstructed from the linked findings. Times are UTC; the full local-time view is in Appendix A.

| UTC | Source | Event | Analytic meaning | Evidence |
|---|---|---|---|---|
| 2026-11-18 23:38:05 | authentication | failed_login | Failed login from 203.0.113.77 on a new device, before the successful session | authentication.csv:5 |
| 2026-11-18 23:40:27 | authentication | anomalous_login | Successful login from the same new device/IP outside normal hours | authentication.csv:6 |
| 2026-11-18 23:47:33 | file_activity | restricted read | Restricted workbook opened by dana.lee on WS-0207 | file_activity.csv:7 |
| 2026-11-18 23:49:10 | file_activity | restricted copy | Workbook copied to local Temp as pricing_copy.xlsx | file_activity.csv:8 |
| 2026-11-18 23:52:18 | file_activity | archive | Workbook archived as pricing_export_2026.zip with 7z.exe | file_activity.csv:9 |
| 2026-11-18 23:55:00 | usb | unapproved USB connect | USB-UNK-9F3C mounted on WS-0207 | usb.csv:4 |
| 2026-11-18 23:57:00 | usb | USB write | pricing_export_2026.zip written to F: | usb.csv:5 |
| 2026-11-19 00:03:12 | browser | cloud visit | mega.nz cloud-storage page visited | browser.csv:5 |
| 2026-11-19 00:04:05 | browser | file-share visit | wetransfer.com visited | browser.csv:7 |
| 2026-11-19 00:06:44 | network | 46.0 MB outbound | Large transfer to mega.nz (203.0.113.200) | network.csv:4 |
| 2026-11-19 00:08:10 | network | 12.0 MB outbound | Large transfer to wetransfer.com (203.0.113.201) | network.csv:6 |
| 2026-11-19 00:12:00 | forensic_artifacts | log_cleared | Security log cleared with wevtutil | forensic_artifacts.csv:2 |
| 2026-11-19 00:14:00 | forensic_artifacts | timestomp | SetFileTime on the archive | forensic_artifacts.csv:3 |
| 2026-11-19 00:14:40 | file_activity | delete | Staged copy pricing_copy.xlsx deleted | file_activity.csv:10 |
| 2026-11-19 00:16:00 | forensic_artifacts | wipe_tool | sdelete used on the staged copy | forensic_artifacts.csv:4 |

The sequence shows a coherent progression: authenticate, access, stage, archive, copy to removable media, upload to cloud, then destroy local traces. The 23:38 failed login is treated as a precursor, not as a separate incident, because it is followed within two minutes by a successful session from the same new device/IP and then by the restricted-file activity.

## 5. Technical findings

**27** rule findings were produced: **17 linked to the incident** and **10 classified as decoys**. The linked findings are listed below; the complete set, including decoys, is in Appendix B.

| ID | Rule | Source | Severity | UTC | User | Host | Object | Evidence |
|---|---|---|---|---|---|---|---|---|
| F-007 | failed_login | authentication | MEDIUM | 2026-11-18 23:38:05Z | dana.lee | WS-0207 | DEV-UNKNOWN-77 | authentication.csv:5 |
| F-008 | anomalous_login | authentication | HIGH | 2026-11-18 23:40:27Z | dana.lee | WS-0207 | DEV-UNKNOWN-77 | authentication.csv:6 |
| F-009 | restricted_file_activity | file_activity | MEDIUM | 2026-11-18 23:47:33Z | dana.lee | WS-0207 | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:7 |
| F-010 | restricted_file_activity | file_activity | HIGH | 2026-11-18 23:49:10Z | dana.lee | WS-0207 | C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx | file_activity.csv:8 |
| F-011 | restricted_file_activity | file_activity | HIGH | 2026-11-18 23:52:18Z | dana.lee | WS-0207 | C:\Users\dana.lee\AppData\Local\Temp\pricing_export_2026.zip | file_activity.csv:9 |
| F-012 | restricted_archive_created | file_activity | HIGH | 2026-11-18 23:52:18Z | dana.lee | WS-0207 | C:\Users\dana.lee\AppData\Local\Temp\pricing_export_2026.zip | file_activity.csv:9 |
| F-013 | unapproved_usb | usb | MEDIUM | 2026-11-18 23:55:00Z | dana.lee | WS-0207 | USB-UNK-9F3C | usb.csv:4 |
| F-014 | unapproved_usb | usb | HIGH | 2026-11-18 23:57:00Z | dana.lee | WS-0207 | F:\pricing_export_2026.zip | usb.csv:5 |
| F-015 | usb_restricted_copy | usb | HIGH | 2026-11-18 23:57:00Z | dana.lee | WS-0207 | F:\pricing_export_2026.zip | usb.csv:5 |
| F-016 | cloud_file_share_visit | browser | MEDIUM | 2026-11-19 00:03:12Z | dana.lee | WS-0207 | https://mega.nz/fm/abc123 | browser.csv:5 |
| F-017 | cloud_file_share_visit | browser | MEDIUM | 2026-11-19 00:04:05Z | dana.lee | WS-0207 | https://wetransfer.com/ | browser.csv:7 |
| F-018 | external_large_transfer | network | HIGH | 2026-11-19 00:06:44Z | dana.lee | WS-0207 | mega.nz | network.csv:4 |
| F-019 | external_large_transfer | network | HIGH | 2026-11-19 00:08:10Z | dana.lee | WS-0207 | wetransfer.com | network.csv:6 |
| F-020 | anti_forensics | forensic_artifacts | HIGH | 2026-11-19 00:12:00Z | dana.lee | WS-0207 | wevtutil cl Security (Security log cleared) | forensic_artifacts.csv:2 |
| F-021 | anti_forensics | forensic_artifacts | HIGH | 2026-11-19 00:14:00Z | dana.lee | WS-0207 | SetFileTime on pricing_export_2026.zip | forensic_artifacts.csv:3 |
| F-022 | evidence_cleanup | file_activity | MEDIUM | 2026-11-19 00:14:40Z | dana.lee | WS-0207 | C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx | file_activity.csv:10 |
| F-023 | anti_forensics | forensic_artifacts | HIGH | 2026-11-19 00:16:00Z | dana.lee | WS-0207 | sdelete -p 3 pricing_copy.xlsx | forensic_artifacts.csv:4 |

### 5.1 Independent source corroboration
| Source | Linked events | Evidence IDs | Rules |
|---|---|---|---|
| authentication | 2 | authentication.csv:5, authentication.csv:6 | anomalous_login; failed_login |
| browser | 2 | browser.csv:5, browser.csv:7 | cloud_file_share_visit |
| file_activity | 5 | file_activity.csv:10, file_activity.csv:7, file_activity.csv:8, file_activity.csv:9 | evidence_cleanup; restricted_archive_created; restricted_file_activity |
| forensic_artifacts | 3 | forensic_artifacts.csv:2, forensic_artifacts.csv:3, forensic_artifacts.csv:4 | anti_forensics |
| network | 2 | network.csv:4, network.csv:6 | external_large_transfer |
| usb | 3 | usb.csv:4, usb.csv:5 | unapproved_usb; usb_restricted_copy |

**Independent source count: 6.** The threshold for CONFIRMED is three. This case exceeds it by three sources. The count uses distinct source types, not the number of rows; duplicate exports and repeated events do not inflate confidence.

### 5.2 Strong indicators
- Archive creation from the restricted workbook (`7z.exe`) and a USB write of the resulting archive.
- Two external large transfers to cloud/file-share destinations immediately after the USB copy.
- New-device/new-IP authentication and a failed login immediately before success.
- Anti-forensic log clearing, timestomping and secure deletion on the same endpoint.

### 5.3 Indicators of compromise
| Indicator type | Value |
|---|---|
| Account | dana.lee (variants: Dana.Lee , DANA.LEE ) |
| Endpoint | WS-0207 |
| Restricted file | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx |
| Staged copies | C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx; pricing_export_2026.zip |
| USB device | USB-UNK-9F3C (not on approved list) |
| Cloud destinations | mega.nz; wetransfer.com |
| Network indicators | 203.0.113.77 (auth source); 203.0.113.200 / 203.0.113.201 (destinations) |
| Anti-forensic tools | wevtutil; PowerShell SetFileTime; sdelete; 7z.exe |
| Time window (UTC) | 2026-11-18 23:38:05Z to 2026-11-19 00:16:00Z |

## 6. Decoys and alternative hypotheses

Every plausible benign explanation was explicitly tested. Decoy findings are excluded from the verdict and are not counted as independent sources.

| Account | Observed | Why it is NOT the incident | Evidence IDs |
|---|---|---|---|
| maria.gomez | cloud_file_share_visit | Cloud/file-share browsing without any restricted-file access or external transfer by this account | browser.csv:2 |
| alice.chen | restricted_file_activity | Authorised pricing analyst, business hours, read-only, no USB/network exfiltration | file_activity.csv:2, file_activity.csv:3 |
| alice.chen | cloud_file_share_visit | Cloud/file-share browsing without any restricted-file access or external transfer by this account | browser.csv:3 |
| bob.martin | approved_usb_write | Approved USB device on the corporate allow-list; non-restricted file | usb.csv:2, usb.csv:3 |
| svc_backup | bulk_backup, large_internal_transfer, scheduled_log_rotation, service_login | Scheduled service account / approved backup job to internal backup destination | authentication.csv:8, file_activity.csv:11, forensic_artifacts.csv:5, network.csv:7 |

### 6.1 Alternative hypotheses
| Hypothesis | Disposition | Reasoning | Evidence |
|---|---|---|---|
| Authorised analyst doing normal pricing review | Rejected | alice.chen is the authorised pricing analyst; access was business-hours and read-only with no USB/network egress. dana.lee is not on the allow-list and performed copy/archive/USB/cloud actions. | F-002..F-004 |
| Scheduled backup job | Rejected | svc_backup copied finance data at 02:00 UTC to backup.acme-internal.com over internal SMB. Separate account/host, scheduled, internal destination. | F-024..F-026 |
| Approved USB use | Rejected | bob.martin used USB-APPR-1140 for a non-restricted roadmap file during business hours. dana.lee used unapproved USB-UNK-9F3C for the restricted archive. | F-005..F-006, F-013..F-015 |
| Benign cloud synchronisation | Rejected | Cloud visits were followed by 46 MB and 12 MB outbound transfers to mega.nz/wetransfer.com, immediately after the archive and USB copy. | F-016..F-019 |
| Routine log maintenance | Rejected | svc_backup logrotate on SRV-BACKUP01 at 00:00 America/Los_Angeles is scheduled and outside the incident host. dana.lee cleared Security logs on WS-0207 inside the window. | F-020, F-027 |
| Compromised credentials / account takeover | Unresolved | The account used a new device and new IP. Logs cannot distinguish an insider from an external actor using stolen credentials; identity attribution requires EDR, VPN, MFA and HR evidence. | Gap |

The compromised-credentials hypothesis is deliberately left unresolved. The logs establish what the account did, not who was at the keyboard. Resolving it requires MFA logs, VPN/ZTNA telemetry, EDR process ancestry, badge/HR records and, if appropriate, an interview.

## 7. Verdict and confidence

**Verdict: CONFIRMED.** Six independent source types (authentication, file_activity, usb, browser, network, forensic_artifacts) corroborate the same account `dana.lee`, endpoint `WS-0207` and restricted file `FY26_Pricing_Model_RESTRICTED.xlsx` within the window. Multiple strong indicators are present, including archive creation, unapproved USB write, external large transfers and anti-forensics.

| Question | Finding |
|---|---|
| **Who** | Account `dana.lee` on endpoint `WS-0207`. Identity attribution beyond the account is unresolved. |
| **What** | Restricted workbook `FY26_Pricing_Model_RESTRICTED.xlsx` read, copied, archived, written to unapproved USB, and uploaded to external cloud/file-share services. |
| **When** | 2026-11-18 23:38:05Z to 2026-11-19 00:16:00Z UTC. |
| **How** | USB copy + cloud upload via mega.nz, wetransfer.com, USB-UNK-9F3C. |
| **Confidence** | CONFIRMED under the >=3-source rule; 6 sources and strong indicators. |

**Confidence boundary.** Confidence in the observed activity is high because six independent sources agree and the sequence is internally consistent. Confidence in intent and actor identity is lower: the evidence cannot distinguish insider theft from account takeover, and it cannot confirm that the destination received or opened the archive.

## 8. Response actions and rollback

**Ordering control:** the evidence package was created and hashed before any containment record. `respond.execute_playbook()` refuses to run if the package is absent or if integrity failed.

**Mode:** executed with `--approve`; all adapters are **simulated**. No real endpoint, account, firewall or USB policy was changed. Incident record: `INC-4613` (`incident_INC-4613.json`).

| # | Action | Target | Status | Rollback |
|---|---|---|---|---|
| A-01 | isolate_endpoint | WS-0207 | SIMULATED_OK | unisolate_endpoint(host='WS-0207') |
| A-02 | revoke_sessions | dana.lee | SIMULATED_OK | restore_sessions(user='dana.lee') |
| A-03 | disable_account | dana.lee | SIMULATED_OK | enable_account(user='dana.lee') |
| A-04 | block_destination | mega.nz | SIMULATED_OK | unblock_destination(domain='mega.nz') |
| A-05 | block_destination | wetransfer.com | SIMULATED_OK | unblock_destination(domain='wetransfer.com') |
| A-06 | block_usb | USB-UNK-9F3C | SIMULATED_OK | unblock_usb(device_id='USB-UNK-9F3C') |
| A-07 | open_incident_record | INC-4613 | SIMULATED_OK | close_incident(incident_id='INC-4613') |

**Approval gate.** The default is DRY-RUN. Execution requires `--approve` or an interactive `y`. Actions that could alter evidence or production state are refused when preservation or integrity fails. The package SHA-256 is embedded in every action record for traceability.

## 9. Recommendations

### 9.1 Immediate (0-24 hours)
- Preserve the endpoint before remediation: memory image, disk image, EDR process tree, USB device history, browser downloads and cloud session artefacts.
- Confirm whether the USB device is physically available and whether the archive or copies exist on it.
- Reset the account password, revoke all sessions/tokens (simulated here), and review MFA enrollment and recovery methods.
- Notify the data owner, Legal/Privacy and HR; determine contractual and regulatory notification obligations.
- Block `mega.nz` and `wetransfer.com` at egress and deny `USB-UNK-9F3C` by device control (simulated here).
- Review cloud-provider logs for the two destinations if lawful access is available; do not rely on the endpoint alone.

### 9.2 Short term (1-7 days)
- Add a high-severity alert for the sequence: restricted-file read -> archive -> unapproved USB -> cloud domain -> large outbound transfer within 30 minutes.
- Enforce least privilege on the restricted finance share; separate pricing access from general finance access.
- Validate that log clearing and timestomping generate immutable, forwarded alerts (e.g., WEF/syslog) so endpoint log deletion does not erase the evidence trail.
- Review backup service-account scope and ensure backup destinations cannot be repurposed for interactive exfiltration.
- Verify that DLP covers archive creation and removable media, not only raw file copies.

### 9.3 Long term
- Move from threshold rules to behaviour analytics for account/endpoint/file triples, while keeping the explainable rules as a baseline.
- Sign the evidence manifest with an external key and store the signature separately from the evidence.
- Re-seal or append a signed delta to the custody log after response actions; the current package is a point-in-time snapshot.
- Run tabletop exercises for USB and cloud exfiltration, including legal/HR hand-offs and chain-of-custody rehearsal.

## 10. Assumptions and limitations

### 10.1 Assumptions
- The target was identified from the data by classification and filename heuristics plus the dictionary hint, not by a hardcoded path.
- Naive timestamps are local to the timezone declared in the data dictionary; timezone-aware values are converted directly. Local times are retained for readability.
- Exact duplicate rows are export artefacts and are counted once. Corroboration counts source types, not volume.
- 'External' means a non-internal domain/IP outside the approved SaaS/backup allow-list. Domain attribution comes from the log; DNS was not independently resolved.
- The manifest is treated as the trust anchor for this exercise.

### 10.2 Limitations and gaps
- **Synthetic evidence:** the fixture demonstrates method and controls, not a real breach.
- **No content inspection:** the logs do not show what was inside the archive, whether it was encrypted, or whether the destination received/opened it.
- **No endpoint telemetry:** process ancestry, injected code, clipboard, screen capture and memory artefacts are unavailable.
- **Identity attribution:** insider versus compromised credentials cannot be determined from these logs.
- **Time zone fallback:** if the host lacks IANA tzdata, the code falls back to the fixed offsets declared in the dictionary; DST transitions would then need manual review.
- **Correlation window:** the three-hour window around the first restricted-file event is a design choice. A patient actor spacing actions wider would reduce the source count and lower confidence.
- **Manifest trust:** if the manifest and data share a compromised source, hashes alone do not establish provenance. Sign the manifest externally in production.
- **Custody start:** the chain starts at preservation, not acquisition; it proves post-collection integrity, not who collected the data before this tool ran.
- **Point-in-time package:** response entries are appended to the live custody log after the package is sealed. A production workflow should re-package or append a signed delta.
- **No legal conclusion:** this is a technical report, not a legal finding of guilt or attribution.

## 11. Reproducibility and test evidence

**Environment:** Python 3.10+, pandas, standard library only. No network calls, credentials or real systems.

```bash
python run.py --data ./data            # verify + analyse + DRY-RUN
python run.py --data ./data --approve  # execute SIMULATED containment
python tests.py                        # regression tests
```

**Regression tests (last run: 5 tests, OK):**

| Test | What it proves |
|---|---|
| `test_tampered_hash_detected_and_excluded` | A one-byte change to `browser.csv` is marked UNTRUSTED, excluded from the timeline/findings, and the custody chain remains valid. |
| `test_decoys_not_flagged` | Authorised user, approved USB, scheduled backup and benign cloud browse are decoys, not linked to the verdict. |
| `test_verdict_requires_three_sources_for_confirmed` | Three sources -> CONFIRMED; two strong sources -> HIGH_CONFIDENCE; two weak sources -> SUSPICIOUS; none -> INCONCLUSIVE. |
| `test_containment_refused_without_package` | No `actions.jsonl` is written when the evidence package is missing. |
| `test_end_to_end_package_then_actions` | Package -> actions -> incident ordering, zip contents, sidecar hash, rollback presence, and `block_usb` targeting `USB-UNK-9F3C`. |

**Tamper demonstration.** A temporary copy of the data with one appended newline to `browser.csv` produced `UNTRUSTED browser.csv`, `integrity_ok=False`, and `Response=REFUSED`; no incident record was created. The real run remains fully trusted.

## 12. Appendices

### Appendix A - Full merged timeline
34 de-duplicated events. `time_local` is the source-local time; `source_tz` identifies the zone.

| UTC | Local | Source | User | Host | Event | Object | Evidence ID |
|---|---|---|---|---|---|---|---|
| 2026-11-18 13:55:12Z | 2026-11-18 08:55:12 -0500 | authentication | alice.chen | WS-0142 | login | DEV-ALICE-01 | authentication.csv:2 |
| 2026-11-18 14:02:44Z | 2026-11-18 09:02:44 -0500 | authentication | maria.gomez | WS-0188 | login | DEV-MARIA-01 | authentication.csv:3 |
| 2026-11-18 14:10:03Z | 2026-11-18 09:10:03 -0500 | authentication | bob.martin | WS-0207 | login | DEV-BOB-01 | authentication.csv:4 |
| 2026-11-18 14:30:00Z | 2026-11-18 14:30:00 +0000 | browser | maria.gomez | WS-0188 | nan | https://onedrive.live.com/ | browser.csv:2 |
| 2026-11-18 15:10:22Z | 2026-11-18 15:10:22 +0000 | file_activity | alice.chen | WS-0142 | read | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:2 |
| 2026-11-18 15:12:00Z | 2026-11-18 15:12:00 +0000 | network | alice.chen | WS-0142 | nan | sharepoint.com | network.csv:2 |
| 2026-11-18 15:20:00Z | 2026-11-18 15:20:00 +0000 | browser | alice.chen | WS-0142 | nan | https://outlook.office.com/mail/ | browser.csv:3 |
| 2026-11-18 15:42:10Z | 2026-11-18 15:42:10 +0000 | file_activity | alice.chen | WS-0142 | read | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:3 |
| 2026-11-18 16:00:00Z | 2026-11-18 16:00:00 +0000 | browser | bob.martin | WS-0207 | nan | https://github.com/ | browser.csv:4 |
| 2026-11-18 16:05:00Z | 2026-11-18 16:05:00 +0000 | file_activity | bob.martin | WS-0207 | read | \\fileserver\public\Q4_roadmap.pptx | file_activity.csv:5 |
| 2026-11-18 16:10:00Z | 2026-11-18 16:10:00 +0000 | network | bob.martin | WS-0207 | nan | github.com | network.csv:3 |
| 2026-11-18 16:20:00Z | 2026-11-18 16:20:00 +0000 | file_activity | bob.martin | WS-0207 | copy | E:\Q4_roadmap.pptx | file_activity.csv:6 |
| 2026-11-18 16:24:30Z | 2026-11-18 21:54:30 +0530 | usb | bob.martin | WS-0207 | connect | USB-APPR-1140 | usb.csv:3 |
| 2026-11-18 16:25:00Z | 2026-11-18 21:55:00 +0530 | usb | bob.martin | WS-0207 | write | E:\Q4_roadmap.pptx | usb.csv:2 |
| 2026-11-18 23:38:05Z | 2026-11-18 18:38:05 -0500 | authentication | dana.lee | WS-0207 | failed_login | DEV-UNKNOWN-77 | authentication.csv:5 |
| 2026-11-18 23:40:27Z | 2026-11-18 18:40:27 -0500 | authentication | dana.lee | WS-0207 | login | DEV-UNKNOWN-77 | authentication.csv:6 |
| 2026-11-18 23:47:33Z | 2026-11-18 23:47:33 +0000 | file_activity | dana.lee | WS-0207 | read | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:7 |
| 2026-11-18 23:49:10Z | 2026-11-18 23:49:10 +0000 | file_activity | dana.lee | WS-0207 | copy | C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx | file_activity.csv:8 |
| 2026-11-18 23:52:18Z | 2026-11-18 23:52:18 +0000 | file_activity | dana.lee | WS-0207 | archive | C:\Users\dana.lee\AppData\Local\Temp\pricing_export_2026.zip | file_activity.csv:9 |
| 2026-11-18 23:55:00Z | 2026-11-19 05:25:00 +0530 | usb | dana.lee | WS-0207 | connect | USB-UNK-9F3C | usb.csv:4 |
| 2026-11-18 23:57:00Z | 2026-11-19 05:27:00 +0530 | usb | dana.lee | WS-0207 | write | F:\pricing_export_2026.zip | usb.csv:5 |
| 2026-11-19 00:01:00Z | 2026-11-19 05:31:00 +0530 | usb | dana.lee | WS-0207 | disconnect | USB-UNK-9F3C | usb.csv:6 |
| 2026-11-19 00:03:12Z | 2026-11-19 00:03:12 +0000 | browser | dana.lee | WS-0207 | nan | https://mega.nz/fm/abc123 | browser.csv:5 |
| 2026-11-19 00:04:05Z | 2026-11-19 00:04:05 +0000 | browser | dana.lee | WS-0207 | nan | https://wetransfer.com/ | browser.csv:7 |
| 2026-11-19 00:06:44Z | 2026-11-19 00:06:44 +0000 | network | dana.lee | WS-0207 | nan | mega.nz | network.csv:4 |
| 2026-11-19 00:08:10Z | 2026-11-19 00:08:10 +0000 | network | dana.lee | WS-0207 | nan | wetransfer.com | network.csv:6 |
| 2026-11-19 00:12:00Z | 2026-11-18 16:12:00 -0800 | forensic_artifacts | dana.lee | WS-0207 | nan | wevtutil cl Security (Security log cleared) | forensic_artifacts.csv:2 |
| 2026-11-19 00:14:00Z | 2026-11-18 16:14:00 -0800 | forensic_artifacts | dana.lee | WS-0207 | nan | SetFileTime on pricing_export_2026.zip | forensic_artifacts.csv:3 |
| 2026-11-19 00:14:40Z | 2026-11-19 00:14:40 +0000 | file_activity | dana.lee | WS-0207 | delete | C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx | file_activity.csv:10 |
| 2026-11-19 00:16:00Z | 2026-11-18 16:16:00 -0800 | forensic_artifacts | dana.lee | WS-0207 | nan | sdelete -p 3 pricing_copy.xlsx | forensic_artifacts.csv:4 |
| 2026-11-19 02:00:00Z | 2026-11-18 21:00:00 -0500 | authentication | svc_backup | SRV-BACKUP01 | service_login | SRV-BACKUP01 | authentication.csv:8 |
| 2026-11-19 02:00:00Z | 2026-11-19 02:00:00 +0000 | file_activity | svc_backup | SRV-BACKUP01 | backup | \\backup\daily\finance_20261119 | file_activity.csv:11 |
| 2026-11-19 02:00:00Z | 2026-11-19 02:00:00 +0000 | network | svc_backup | SRV-BACKUP01 | nan | backup.acme-internal.com | network.csv:7 |
| 2026-11-19 08:00:00Z | 2026-11-19 00:00:00 -0800 | forensic_artifacts | svc_backup | SRV-BACKUP01 | nan | scheduled log rotation (retention policy) | forensic_artifacts.csv:5 |

### Appendix B - Full findings register
27 findings, including decoys. Disposition is LINKED (counted toward the verdict) or DECOY (excluded).

| ID | Rule | Source | Severity | User | Host | UTC | Object | Evidence | Disposition |
|---|---|---|---|---|---|---|---|---|---|
| F-001 | cloud_file_share_visit | browser | MEDIUM | maria.gomez | WS-0188 | 2026-11-18 14:30:00Z | https://onedrive.live.com/ | browser.csv:2 | DECOY |
| F-002 | restricted_file_activity | file_activity | MEDIUM | alice.chen | WS-0142 | 2026-11-18 15:10:22Z | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:2 | DECOY |
| F-003 | cloud_file_share_visit | browser | MEDIUM | alice.chen | WS-0142 | 2026-11-18 15:20:00Z | https://outlook.office.com/mail/ | browser.csv:3 | DECOY |
| F-004 | restricted_file_activity | file_activity | MEDIUM | alice.chen | WS-0142 | 2026-11-18 15:42:10Z | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:3 | DECOY |
| F-005 | approved_usb_write | usb | LOW | bob.martin | WS-0207 | 2026-11-18 16:24:30Z | USB-APPR-1140 | usb.csv:3 | DECOY |
| F-006 | approved_usb_write | usb | LOW | bob.martin | WS-0207 | 2026-11-18 16:25:00Z | E:\Q4_roadmap.pptx | usb.csv:2 | DECOY |
| F-007 | failed_login | authentication | MEDIUM | dana.lee | WS-0207 | 2026-11-18 23:38:05Z | DEV-UNKNOWN-77 | authentication.csv:5 | LINKED |
| F-008 | anomalous_login | authentication | HIGH | dana.lee | WS-0207 | 2026-11-18 23:40:27Z | DEV-UNKNOWN-77 | authentication.csv:6 | LINKED |
| F-009 | restricted_file_activity | file_activity | MEDIUM | dana.lee | WS-0207 | 2026-11-18 23:47:33Z | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:7 | LINKED |
| F-010 | restricted_file_activity | file_activity | HIGH | dana.lee | WS-0207 | 2026-11-18 23:49:10Z | C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx | file_activity.csv:8 | LINKED |
| F-011 | restricted_file_activity | file_activity | HIGH | dana.lee | WS-0207 | 2026-11-18 23:52:18Z | C:\Users\dana.lee\AppData\Local\Temp\pricing_export_2026.zip | file_activity.csv:9 | LINKED |
| F-012 | restricted_archive_created | file_activity | HIGH | dana.lee | WS-0207 | 2026-11-18 23:52:18Z | C:\Users\dana.lee\AppData\Local\Temp\pricing_export_2026.zip | file_activity.csv:9 | LINKED |
| F-013 | unapproved_usb | usb | MEDIUM | dana.lee | WS-0207 | 2026-11-18 23:55:00Z | USB-UNK-9F3C | usb.csv:4 | LINKED |
| F-014 | unapproved_usb | usb | HIGH | dana.lee | WS-0207 | 2026-11-18 23:57:00Z | F:\pricing_export_2026.zip | usb.csv:5 | LINKED |
| F-015 | usb_restricted_copy | usb | HIGH | dana.lee | WS-0207 | 2026-11-18 23:57:00Z | F:\pricing_export_2026.zip | usb.csv:5 | LINKED |
| F-016 | cloud_file_share_visit | browser | MEDIUM | dana.lee | WS-0207 | 2026-11-19 00:03:12Z | https://mega.nz/fm/abc123 | browser.csv:5 | LINKED |
| F-017 | cloud_file_share_visit | browser | MEDIUM | dana.lee | WS-0207 | 2026-11-19 00:04:05Z | https://wetransfer.com/ | browser.csv:7 | LINKED |
| F-018 | external_large_transfer | network | HIGH | dana.lee | WS-0207 | 2026-11-19 00:06:44Z | mega.nz | network.csv:4 | LINKED |
| F-019 | external_large_transfer | network | HIGH | dana.lee | WS-0207 | 2026-11-19 00:08:10Z | wetransfer.com | network.csv:6 | LINKED |
| F-020 | anti_forensics | forensic_artifacts | HIGH | dana.lee | WS-0207 | 2026-11-19 00:12:00Z | wevtutil cl Security (Security log cleared) | forensic_artifacts.csv:2 | LINKED |
| F-021 | anti_forensics | forensic_artifacts | HIGH | dana.lee | WS-0207 | 2026-11-19 00:14:00Z | SetFileTime on pricing_export_2026.zip | forensic_artifacts.csv:3 | LINKED |
| F-022 | evidence_cleanup | file_activity | MEDIUM | dana.lee | WS-0207 | 2026-11-19 00:14:40Z | C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx | file_activity.csv:10 | LINKED |
| F-023 | anti_forensics | forensic_artifacts | HIGH | dana.lee | WS-0207 | 2026-11-19 00:16:00Z | sdelete -p 3 pricing_copy.xlsx | forensic_artifacts.csv:4 | LINKED |
| F-024 | service_login | authentication | LOW | svc_backup | SRV-BACKUP01 | 2026-11-19 02:00:00Z | SRV-BACKUP01 | authentication.csv:8 | DECOY |
| F-025 | bulk_backup | file_activity | LOW | svc_backup | SRV-BACKUP01 | 2026-11-19 02:00:00Z | \\backup\daily\finance_20261119 | file_activity.csv:11 | DECOY |
| F-026 | large_internal_transfer | network | LOW | svc_backup | SRV-BACKUP01 | 2026-11-19 02:00:00Z | backup.acme-internal.com | network.csv:7 | DECOY |
| F-027 | scheduled_log_rotation | forensic_artifacts | LOW | svc_backup | SRV-BACKUP01 | 2026-11-19 08:00:00Z | scheduled log rotation (retention policy) | forensic_artifacts.csv:5 | DECOY |

### Appendix C - Chain of custody entries
26 entries; chain verification: (True, 'chain valid').

| Timestamp | Actor | Action | File | SHA-256 | Prev hash |
|---|---|---|---|---|---|
| 2026-11-20T09:47:26Z | system:preservation | preserve_copy | authentication.csv | 446a08b7085caa2517f6 | GENESIS |
| 2026-11-20T09:47:26Z | system:preservation | verify_hash | authentication.csv | 446a08b7085caa2517f6 | ffcc2b61dc12dc286775 |
| 2026-11-20T09:47:26Z | system:preservation | preserve_copy | browser.csv | 79c906f9b1c5d2c5abd9 | dfd1b9aa9fddfe800b53 |
| 2026-11-20T09:47:26Z | system:preservation | verify_hash | browser.csv | 79c906f9b1c5d2c5abd9 | 68048221b6b4d89dda9d |
| 2026-11-20T09:47:26Z | system:preservation | preserve_copy | data_dictionary.md | 585bb2b0ecc2f5cb1932 | 56d3830f86bf5e4c21db |
| 2026-11-20T09:47:26Z | system:preservation | verify_hash | data_dictionary.md | 585bb2b0ecc2f5cb1932 | f703441f1f3e1a20e674 |
| 2026-11-20T09:47:26Z | system:preservation | preserve_copy | evidence_manifest.csv | eba7c864dc21f47d6eec | e8fc77274212d6a482ac |
| 2026-11-20T09:47:26Z | system:preservation | verify_hash | evidence_manifest.csv | eba7c864dc21f47d6eec | e14cf200809fb8b5b867 |
| 2026-11-20T09:47:26Z | system:preservation | preserve_copy | file_activity.csv | 4ab2e1807eebec01f29a | b7e98c8e5eb2b9fd51a6 |
| 2026-11-20T09:47:26Z | system:preservation | verify_hash | file_activity.csv | 4ab2e1807eebec01f29a | 8a28b7fad5823907d789 |
| 2026-11-20T09:47:26Z | system:preservation | preserve_copy | forensic_artifacts.csv | 5a292bb315114264765b | d955cfba2fb8b7e63ef2 |
| 2026-11-20T09:47:26Z | system:preservation | verify_hash | forensic_artifacts.csv | 5a292bb315114264765b | 8a49ffc21820a8d157ee |
| 2026-11-20T09:47:26Z | system:preservation | preserve_copy | network.csv | e6fe8f3a18434151eb5f | 2956f9de75f36299b240 |
| 2026-11-20T09:47:26Z | system:preservation | verify_hash | network.csv | e6fe8f3a18434151eb5f | a8a5ffe73b83a40b022d |
| 2026-11-20T09:47:26Z | system:preservation | preserve_copy | usb.csv | d2ff624607e86e7bb8a1 | edfc544cb0058262ab83 |
| 2026-11-20T09:47:26Z | system:preservation | verify_hash | usb.csv | d2ff624607e86e7bb8a1 | 063c0a639b8ecf7ef337 |
| 2026-11-20T09:47:26Z | system:preservation | preservation_summary |  |  | 144da1a7bdace67c18ca |
| 2026-11-20T09:47:26Z | system:packaging | evidence_package_created | evidence_package.zip | f980fc3b95e818b111c8 | 189e1f81615c8348595f |
| 2026-11-20T09:47:26Z | analyst:cli | response:isolate_endpoint | WS-0207 |  | abfde8925e3fae03237d |
| 2026-11-20T09:47:26Z | analyst:cli | response:revoke_sessions | dana.lee |  | e6ba97a288b3ca625663 |
| 2026-11-20T09:47:26Z | analyst:cli | response:disable_account | dana.lee |  | 7674a87e412d3d411033 |
| 2026-11-20T09:47:26Z | analyst:cli | response:block_destination | mega.nz |  | 77078ed72bc7021530d0 |
| 2026-11-20T09:47:26Z | analyst:cli | response:block_destination | wetransfer.com |  | 02cb6943d71921d947f5 |
| 2026-11-20T09:47:26Z | analyst:cli | response:block_usb | USB-UNK-9F3C |  | 4078fbff198190c3d846 |
| 2026-11-20T09:47:26Z | analyst:cli | response:open_incident_record | INC-4613 |  | 15e5b1fc8a72caeeee9d |
| 2026-11-20T09:47:26Z | analyst:cli | incident_record_created | incident_INC-4613.json | 4263f7a531177ef15fd9 | 74dd9532f423d5237de5 |

### Appendix D - Evidence manifest

| File | SHA-256 | Size (bytes) |
|---|---|---|
| authentication.csv | 446a08b7085caa2517f607ba364edf7de2aaaa411551e218982443ac9d3ff4d6 | 712 |
| browser.csv | 79c906f9b1c5d2c5abd937c16494958d294fc157fc4207b204f426ea00e8617c | 604 |
| data_dictionary.md | 585bb2b0ecc2f5cb19323b2ccdfcf9860e6f655d07b2ef33ed2ce1b7de6f5e7a | 2082 |
| file_activity.csv | 4ab2e1807eebec01f29ae39eb2b4b8d4be589161dbc6258f094d79a1726c3b0f | 1710 |
| forensic_artifacts.csv | 5a292bb315114264765bcd9fb68ac4c2f93afffb70e24196c4da869de8ccc4ed | 444 |
| network.csv | e6fe8f3a18434151eb5fc62511fe515a49baa288e438845253fa0fb636cc48d6 | 616 |
| usb.csv | d2ff624607e86e7bb8a1be0545879ab8c62965dd0d976d13f4770a7d5201b923 | 486 |

### Appendix E - Evidence package contents

| Member | Uncompressed size (bytes) |
|---|---|
| originals/authentication.csv | 712 |
| originals/browser.csv | 604 |
| originals/data_dictionary.md | 2082 |
| originals/evidence_manifest.csv | 631 |
| originals/file_activity.csv | 1710 |
| originals/forensic_artifacts.csv | 444 |
| originals/network.csv | 616 |
| originals/usb.csv | 486 |
| evidence_manifest.csv | 631 |
| timeline.csv | 4845 |
| findings.json | 37779 |
| chain_of_custody.jsonl | 8608 |
| package_manifest.json | 2157 |

### Appendix F - Detection rule catalogue

| Rule | Logic | Source | Severity | Findings |
|---|---|---|---|---|
| restricted_file_activity | File action read/copy/rename/archive/delete references the target workbook | file_activity | MEDIUM/HIGH | F-009..F-011 |
| restricted_archive_created | Archive output derived from restricted pricing data | file_activity | HIGH | F-012 |
| evidence_cleanup | Deletion of a staged restricted copy | file_activity | MEDIUM | F-022 |
| unapproved_usb | USB connect/write with approved=false or device outside allow-list | usb | MEDIUM/HIGH | F-013..F-014 |
| usb_restricted_copy | Restricted archive filename written to USB | usb | HIGH | F-015 |
| cloud_file_share_visit | Browser category cloud_storage/file_share/webmail or known cloud domain | browser | MEDIUM | F-016..F-017 |
| external_large_transfer | Outbound >=10 MB to non-internal, non-allow-listed destination | network | HIGH | F-018..F-019 |
| failed_login | Failed authentication from a new/unknown source | authentication | MEDIUM | F-007 |
| anomalous_login | Successful login from a new device or deep off-hours | authentication | HIGH | F-008 |
| anti_forensics | Log clear, timestomp, wipe tool, or destructive deletion on the endpoint | forensic_artifacts | HIGH | F-020..F-023 |
| bulk_backup / large_internal_transfer | Large transfer to an internal/backup destination by a service account | file_activity / network | LOW | F-025..F-026 |
| approved_usb_write | Write to an allow-listed USB device | usb | LOW | F-005..F-006 |
| service_login / scheduled_log_rotation | Service-account login or scheduled log maintenance | authentication / forensic | LOW | F-024, F-027 |

### Appendix G - Data dictionary controls used

| Control | Value used by the detector |
|---|---|
| Timezones | authentication.csv = America/New_York (UTC-05:00); file_activity.csv = UTC; usb.csv = Asia/Kolkata (UTC+05:30); browser.csv = Europe/London (UTC+00:00); network.csv = UTC; forensic_artifacts.csv = America/Los_Angeles (UTC-08:00) |
| Business hours | 09:00-18:00 America/New_York, Monday-Friday |
| Authorised pricing user | alice.chen (bob.martin explicitly NOT authorised) |
| Approved USB devices | USB-APPR-1140, USB-APPR-2210 |
| Backup schedule | svc_backup daily 02:00 UTC to backup.acme-internal.com; logrotate on SRV-BACKUP01 |
| Target hint | FY26_Pricing_Model_RESTRICTED.xlsx on \\fileserver\finance\Restricted |

---

**End of report.** This report is a technical DFIR product. It separates observed facts with evidence IDs from assumptions and gaps, and it does not assert legal guilt or identity beyond the account and endpoint shown.
