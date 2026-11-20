# Digital Evidence Detective - Investigation Report

**Generated:** 2026-11-20T09:54:20Z  
**Case:** Suspected theft of restricted pricing data  
**Data set:** `C:\Users\Asus\OneDrive\Desktop\TCS Hackathon\data`  
**Report mode:** SIMULATED EXECUTION

> **Evidence notice:** the supplied evidence set is synthetic training data. All identities, hosts and destinations are fictional.

## 1. Executive summary

**Verdict: CONFIRMED**  
**Account:** `dana.lee`  
**Endpoint:** `WS-0207`  
**File:** `FY26_Pricing_Model_RESTRICTED.xlsx`  
**Incident window:** 2026-11-18 23:38:05Z to 2026-11-19 00:16:00Z UTC; local: 2026-11-18 18:38:05 -0500 (America/New_York) -> 2026-11-18 16:16:00 -0800 (America/Los_Angeles)  
**Method:** USB copy + cloud upload  
**Destination / device:** mega.nz, wetransfer.com, USB-UNK-9F3C  
**Independent corroborating sources:** 6 (authentication, browser, file_activity, forensic_artifacts, network, usb)  
**Response:** EXECUTED - see actions table

The evidence independently shows the account `dana.lee` on `WS-0207` accessing and staging the restricted workbook, writing it to an unapproved USB device, uploading data to external cloud/file-share destinations, and then attempting to destroy artifacts on the endpoint. 6 independent source types agree, so the verdict is CONFIRMED and the simulated containment playbook is authorised.

## 2. Integrity results

**Preservation succeeded:** True  
**Integrity verified:** True  
**Custody chain:** True (chain valid)  
**Raw files copied read-only to:** `C:\Users\Asus\OneDrive\Desktop\TCS Hackathon\evidence/original`  
**Exact duplicate rows suppressed:** 4  
**Timestamp parse failures (excluded):** 0

| File | Source | Expected SHA-256 | Actual SHA-256 | Status | Reason | Included |
|---|---|---|---|---|---|---|
| authentication.csv | authentication | 446a08b7085c | 446a08b7085c | TRUSTED | SHA-256 matches manifest | True |
| browser.csv | browser | 79c906f9b1c5 | 79c906f9b1c5 | TRUSTED | SHA-256 matches manifest | True |
| data_dictionary.md | - | 585bb2b0ecc2 | 585bb2b0ecc2 | TRUSTED | SHA-256 matches manifest | False |
| evidence_manifest.csv | - |  | eba7c864dc21 | REFERENCE | manifest is the trust anchor (not self-hashed) | False |
| file_activity.csv | file_activity | 4ab2e1807eeb | 4ab2e1807eeb | TRUSTED | SHA-256 matches manifest | True |
| forensic_artifacts.csv | forensic_artifacts | 5a292bb31511 | 5a292bb31511 | TRUSTED | SHA-256 matches manifest | True |
| network.csv | network | e6fe8f3a1843 | e6fe8f3a1843 | TRUSTED | SHA-256 matches manifest | True |
| usb.csv | usb | d2ff624607e8 | d2ff624607e8 | TRUSTED | SHA-256 matches manifest | True |

**Duplicate rows (kept first occurrence):**

| Source | Kept evidence_id | Dropped evidence_id |
|---|---|---|
| authentication | authentication.csv:2 | authentication.csv:7 |
| file_activity | file_activity.csv:2 | file_activity.csv:4 |
| browser | browser.csv:5 | browser.csv:6 |
| network | network.csv:4 | network.csv:5 |

## 3. Timeline

All six sources are normalized to UTC and also shown in each source's local timezone (`timeline.csv`, 34 de-duplicated events).

### 3.1 Correlated incident window

| UTC | Local (source tz) | Source | User | Host | Event | Object | Evidence |
|---|---|---|---|---|---|---|---|
| 2026-11-18 23:38:05Z | 2026-11-18 18:38:05 -0500 | authentication | dana.lee | WS-0207 | failed_login | DEV-UNKNOWN-77 | authentication.csv:5 |
| 2026-11-18 23:40:27Z | 2026-11-18 18:40:27 -0500 | authentication | dana.lee | WS-0207 | anomalous_login | DEV-UNKNOWN-77 | authentication.csv:6 |
| 2026-11-18 23:47:33Z | 2026-11-18 23:47:33 +0000 | file_activity | dana.lee | WS-0207 | restricted_file_activity | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:7 |
| 2026-11-18 23:49:10Z | 2026-11-18 23:49:10 +0000 | file_activity | dana.lee | WS-0207 | restricted_file_activity | C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx | file_activity.csv:8 |
| 2026-11-18 23:52:18Z | 2026-11-18 23:52:18 +0000 | file_activity | dana.lee | WS-0207 | restricted_file_activity | C:\Users\dana.lee\AppData\Local\Temp\pricing_export_2026.zip | file_activity.csv:9 |
| 2026-11-18 23:52:18Z | 2026-11-18 23:52:18 +0000 | file_activity | dana.lee | WS-0207 | restricted_archive_created | C:\Users\dana.lee\AppData\Local\Temp\pricing_export_2026.zip | file_activity.csv:9 |
| 2026-11-18 23:55:00Z | 2026-11-19 05:25:00 +0530 | usb | dana.lee | WS-0207 | unapproved_usb | USB-UNK-9F3C | usb.csv:4 |
| 2026-11-18 23:57:00Z | 2026-11-19 05:27:00 +0530 | usb | dana.lee | WS-0207 | unapproved_usb | F:\pricing_export_2026.zip | usb.csv:5 |
| 2026-11-18 23:57:00Z | 2026-11-19 05:27:00 +0530 | usb | dana.lee | WS-0207 | usb_restricted_copy | F:\pricing_export_2026.zip | usb.csv:5 |
| 2026-11-19 00:03:12Z | 2026-11-19 00:03:12 +0000 | browser | dana.lee | WS-0207 | cloud_file_share_visit | https://mega.nz/fm/abc123 | browser.csv:5 |
| 2026-11-19 00:04:05Z | 2026-11-19 00:04:05 +0000 | browser | dana.lee | WS-0207 | cloud_file_share_visit | https://wetransfer.com/ | browser.csv:7 |
| 2026-11-19 00:06:44Z | 2026-11-19 00:06:44 +0000 | network | dana.lee | WS-0207 | external_large_transfer | mega.nz | network.csv:4 |
| 2026-11-19 00:08:10Z | 2026-11-19 00:08:10 +0000 | network | dana.lee | WS-0207 | external_large_transfer | wetransfer.com | network.csv:6 |
| 2026-11-19 00:12:00Z | 2026-11-18 16:12:00 -0800 | forensic_artifacts | dana.lee | WS-0207 | anti_forensics | wevtutil cl Security (Security log cleared) | forensic_artifacts.csv:2 |
| 2026-11-19 00:14:00Z | 2026-11-18 16:14:00 -0800 | forensic_artifacts | dana.lee | WS-0207 | anti_forensics | SetFileTime on pricing_export_2026.zip | forensic_artifacts.csv:3 |
| 2026-11-19 00:14:40Z | 2026-11-19 00:14:40 +0000 | file_activity | dana.lee | WS-0207 | evidence_cleanup | C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx | file_activity.csv:10 |
| 2026-11-19 00:16:00Z | 2026-11-18 16:16:00 -0800 | forensic_artifacts | dana.lee | WS-0207 | anti_forensics | sdelete -p 3 pricing_copy.xlsx | forensic_artifacts.csv:4 |

### 3.2 Other events and ruled-out context

| UTC | Source | User | Host | Event | Object | Evidence |
|---|---|---|---|---|---|---|
| 2026-11-18 14:30:00Z | browser | maria.gomez | WS-0188 | cloud_file_share_visit | https://onedrive.live.com/ | browser.csv:2 |
| 2026-11-18 15:10:22Z | file_activity | alice.chen | WS-0142 | restricted_file_activity | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:2 |
| 2026-11-18 15:20:00Z | browser | alice.chen | WS-0142 | cloud_file_share_visit | https://outlook.office.com/mail/ | browser.csv:3 |
| 2026-11-18 15:42:10Z | file_activity | alice.chen | WS-0142 | restricted_file_activity | \\fileserver\finance\Restricted\FY26_Pricing_Model_RESTRICTED.xlsx | file_activity.csv:3 |
| 2026-11-18 16:24:30Z | usb | bob.martin | WS-0207 | approved_usb_write | USB-APPR-1140 | usb.csv:3 |
| 2026-11-18 16:25:00Z | usb | bob.martin | WS-0207 | approved_usb_write | E:\Q4_roadmap.pptx | usb.csv:2 |
| 2026-11-19 02:00:00Z | authentication | svc_backup | SRV-BACKUP01 | service_login | SRV-BACKUP01 | authentication.csv:8 |
| 2026-11-19 02:00:00Z | file_activity | svc_backup | SRV-BACKUP01 | bulk_backup | \\backup\daily\finance_20261119 | file_activity.csv:11 |
| 2026-11-19 02:00:00Z | network | svc_backup | SRV-BACKUP01 | large_internal_transfer | backup.acme-internal.com | network.csv:7 |
| 2026-11-19 08:00:00Z | forensic_artifacts | svc_backup | SRV-BACKUP01 | scheduled_log_rotation | scheduled log rotation (retention policy) | forensic_artifacts.csv:5 |

Full merged timeline (including non-finding events) is in `timeline.csv`.

## 4. Verdict and reasoning

**Confidence rule:** >=3 independent source types => CONFIRMED; 2 source types with a strong indicator => HIGH_CONFIDENCE; otherwise SUSPICIOUS/INCONCLUSIVE with no containment. This case has **6** independent sources and **a strong indicator**.

| Independent source | Linked events | Evidence IDs | Rules |
|---|---|---|---|
| authentication | 2 | authentication.csv:5, authentication.csv:6 | anomalous_login; failed_login |
| browser | 2 | browser.csv:5, browser.csv:7 | cloud_file_share_visit |
| file_activity | 5 | file_activity.csv:10, file_activity.csv:7, file_activity.csv:8, file_activity.csv:9 | evidence_cleanup; restricted_archive_created; restricted_file_activity |
| forensic_artifacts | 3 | forensic_artifacts.csv:2, forensic_artifacts.csv:3, forensic_artifacts.csv:4 | anti_forensics |
| network | 2 | network.csv:4, network.csv:6 | external_large_transfer |
| usb | 3 | usb.csv:4, usb.csv:5 | unapproved_usb; usb_restricted_copy |

### 4.1 Who / What / When / How

| Question | Answer |
|---|---|
| Who | `dana.lee` on endpoint `WS-0207` |
| What | Restricted workbook `FY26_Pricing_Model_RESTRICTED.xlsx` read, copied/archived, then moved out |
| When | 2026-11-18 23:38:05Z to 2026-11-19 00:16:00Z UTC; local: 2026-11-18 18:38:05 -0500 (America/New_York) -> 2026-11-18 16:16:00 -0800 (America/Los_Angeles) |
| How | USB copy + cloud upload via mega.nz, wetransfer.com, USB-UNK-9F3C |

## 5. Decoys ruled out

Each alternative explanation was explicitly tested. These events are **not** counted toward the verdict.

| Account | Observed | Why it is NOT the incident | Evidence IDs |
|---|---|---|---|
| maria.gomez | cloud_file_share_visit | Cloud/file-share browsing without any restricted-file access or external transfer by this account | browser.csv:2 |
| alice.chen | restricted_file_activity | Authorised pricing analyst, business hours, read-only, no USB/network exfiltration | file_activity.csv:2, file_activity.csv:3 |
| alice.chen | cloud_file_share_visit | Cloud/file-share browsing without any restricted-file access or external transfer by this account | browser.csv:3 |
| bob.martin | approved_usb_write | Approved USB device on the corporate allow-list; non-restricted file | usb.csv:2, usb.csv:3 |
| svc_backup | bulk_backup, large_internal_transfer, scheduled_log_rotation, service_login | Scheduled service account / approved backup job to internal backup destination | authentication.csv:8, file_activity.csv:11, forensic_artifacts.csv:5, network.csv:7 |

## 6. Facts vs assumptions

### 6.1 FACTS (each cites evidence)

- **F-007 / failed_login** (MEDIUM, 2026-11-18 23:38:05Z) - failed login from 203.0.113.77 (Unknown) `[authentication.csv:5]`
- **F-008 / anomalous_login** (HIGH, 2026-11-18 23:40:27Z) - login from new device 203.0.113.77 at 2026-11-18 18:40:27 -0500 (off-hours/new-device) `[authentication.csv:6]`
- **F-009 / restricted_file_activity** (MEDIUM, 2026-11-18 23:47:33Z) - read of restricted workbook FY26_Pricing_Model_RESTRICTED.xlsx `[file_activity.csv:7]`
- **F-010 / restricted_file_activity** (HIGH, 2026-11-18 23:49:10Z) - copy of restricted workbook FY26_Pricing_Model_RESTRICTED.xlsx `[file_activity.csv:8]`
- **F-011 / restricted_file_activity** (HIGH, 2026-11-18 23:52:18Z) - archive of restricted workbook FY26_Pricing_Model_RESTRICTED.xlsx `[file_activity.csv:9]`
- **F-012 / restricted_archive_created** (HIGH, 2026-11-18 23:52:18Z) - restricted data archived to C:\Users\dana.lee\AppData\Local\Temp\pricing_export_2026.zip `[file_activity.csv:9]`
- **F-013 / unapproved_usb** (MEDIUM, 2026-11-18 23:55:00Z) - unapproved USB USB-UNK-9F3C connect on WS-0207 `[usb.csv:4]`
- **F-014 / unapproved_usb** (HIGH, 2026-11-18 23:57:00Z) - unapproved USB USB-UNK-9F3C write on WS-0207 `[usb.csv:5]`
- **F-015 / usb_restricted_copy** (HIGH, 2026-11-18 23:57:00Z) - restricted archive written to USB USB-UNK-9F3C: F:\pricing_export_2026.zip `[usb.csv:5]`
- **F-016 / cloud_file_share_visit** (MEDIUM, 2026-11-19 00:03:12Z) - cloud_storage visit to mega.nz `[browser.csv:5]`
- **F-017 / cloud_file_share_visit** (MEDIUM, 2026-11-19 00:04:05Z) - file_share visit to wetransfer.com `[browser.csv:7]`
- **F-018 / external_large_transfer** (HIGH, 2026-11-19 00:06:44Z) - 46.0 MB outbound to mega.nz (203.0.113.200) `[network.csv:4]`
- **F-019 / external_large_transfer** (HIGH, 2026-11-19 00:08:10Z) - 12.0 MB outbound to wetransfer.com (203.0.113.201) `[network.csv:6]`
- **F-020 / anti_forensics** (HIGH, 2026-11-19 00:12:00Z) - log_cleared on WS-0207: wevtutil cl Security (Security log cleared) `[forensic_artifacts.csv:2]`
- **F-021 / anti_forensics** (HIGH, 2026-11-19 00:14:00Z) - timestomp on WS-0207: SetFileTime on pricing_export_2026.zip `[forensic_artifacts.csv:3]`
- **F-022 / evidence_cleanup** (MEDIUM, 2026-11-19 00:14:40Z) - staged copy deleted: C:\Users\dana.lee\AppData\Local\Temp\pricing_copy.xlsx `[file_activity.csv:10]`
- **F-023 / anti_forensics** (HIGH, 2026-11-19 00:16:00Z) - wipe_tool on WS-0207: sdelete -p 3 pricing_copy.xlsx `[forensic_artifacts.csv:4]`

### 6.2 ASSUMPTIONS and GAPS

- **Assumption:** the target file was identified from the data (classification/name heuristic) as `FY26_Pricing_Model_RESTRICTED.xlsx`; its evidence rows are `file_activity.csv:2, file_activity.csv:3, file_activity.csv:7, file_activity.csv:8, file_activity.csv:9`.
- **Assumption:** naive timestamps are local to the timezone declared in `data_dictionary.md`; timezone-aware values are converted directly. Local times are displayed alongside UTC.
- **Assumption:** exact duplicate rows are export artifacts and are counted once; corroboration counts source *types*, not event volume.
- **Assumption:** 'external' means a non-internal domain/IP outside the approved SaaS/backup allow-list; DNS/domain attribution is taken from the log, not independently resolved.
- **Gap:** no EDR process lineage, DLP content inspection, VPN, mail or cloud-provider logs; the exact bytes transferred and whether the archive was opened at the destination are unknown.
- **Gap:** IP geolocation and device ownership are not independently verified; insider theft vs. compromised credentials cannot be distinguished from these logs alone.
- **Gap:** the evidence package and its custody snapshot are point-in-time; response actions are simulated and do not alter any real system.
- **Gap:** this run uses a synthetic evidence fixture, so findings demonstrate the method rather than a real incident.

## 7. Actions taken and rollback

**Order enforced:** evidence package created first (`evidence_package.zip`), then containment. Package SHA-256: `54795f5357358a5f37ad14c15071272e783627e0cb4528cd8df8fb1b26901e88`.  
**Mode:** execute - simulated adapters executed.

| # | Action | Target | Status | Rollback |
|---|---|---|---|---|
| A-01 | isolate_endpoint | WS-0207 | SIMULATED_OK | unisolate_endpoint(host='WS-0207') |
| A-02 | revoke_sessions | dana.lee | SIMULATED_OK | restore_sessions(user='dana.lee') |
| A-03 | disable_account | dana.lee | SIMULATED_OK | enable_account(user='dana.lee') |
| A-04 | block_destination | mega.nz | SIMULATED_OK | unblock_destination(domain='mega.nz') |
| A-05 | block_destination | wetransfer.com | SIMULATED_OK | unblock_destination(domain='wetransfer.com') |
| A-06 | block_usb | USB-UNK-9F3C | SIMULATED_OK | unblock_usb(device_id='USB-UNK-9F3C') |
| A-07 | open_incident_record | INC-4613 | SIMULATED_OK | close_incident(incident_id='INC-4613') |

**Incident record:** `incident_INC-4613.json` (INC-4613)

**Approval gate:** any action that could alter evidence or production state requires `--approve` or an interactive `y`; default is DRY-RUN. Containment is refused if preservation or integrity fails.

## 8. Limitations

- Rule-based detection is explainable but not behavioural; a novel exfiltration path may be missed.
- Corroboration uses a 3-hour window around the first restricted-file event; a patient attacker spacing actions beyond that window would reduce the source count.
- Simulated adapters prove orchestration and rollback design, not integration with EDR/IAM/firewall APIs.
- `evidence_manifest.csv` is treated as the trust anchor; if the manifest and data share a compromised source, hashes alone cannot establish provenance. Sign the manifest externally in production.
- The custody chain starts at preservation, not at acquisition; it proves post-collection integrity, not who collected the data before this tool ran.
- The package is written before response so response logs are appended to the live custody log after packaging; a production workflow would re-package or seal the log.