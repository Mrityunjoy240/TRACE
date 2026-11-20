# Data Dictionary - Meridian Analytics Evidence Set

Synthetic training evidence for the Digital Evidence Detective prototype.
All people, hosts, IPs and domains are fictional. Destinations use TEST-NET ranges.

## Timezones
authentication.csv: America/New_York (UTC-05:00)
file_activity.csv: UTC
usb.csv: Asia/Kolkata (UTC+05:30)
browser.csv: Europe/London (UTC+00:00)
network.csv: UTC
forensic_artifacts.csv: America/Los_Angeles (UTC-08:00)

## Field definitions
| file | field | meaning | allowed values |
|---|---|---|---|
| authentication.csv | event_type | authentication outcome | login, failed_login, service_login, logout |
| authentication.csv | is_new_device | device not previously seen for account | true, false |
| file_activity.csv | action | file operation | read, copy, rename, archive, delete, backup |
| file_activity.csv | classification | data sensitivity label | RESTRICTED, INTERNAL, PUBLIC |
| usb.csv | action | USB lifecycle | connect, write, disconnect |
| usb.csv | approved | device is on the corporate allow-list | true, false |
| browser.csv | category | site category | cloud_storage, file_share, webmail, developer, news |
| network.csv | direction | flow direction | outbound, inbound |
| forensic_artifacts.csv | artifact_type | anti-forensic technique observed | log_cleared, timestomp, wipe_tool, deleted_file |

## Authorized users
- alice.chen - Pricing analyst, authorised for RESTRICTED pricing workbook
- bob.martin - Product manager, NOT authorised for RESTRICTED finance data

## Approved USB devices
- USB-APPR-1140
- USB-APPR-2210

## Backup schedule
- svc_backup daily 02:00 UTC to backup.acme-internal.com (robocopy, internal SMB)
- logrotate on SRV-BACKUP01 daily 00:00 America/Los_Angeles

## Business hours
- 09:00-18:00 America/New_York, Monday-Friday

## Notes
- Target asset: FY26_Pricing_Model_RESTRICTED.xlsx on \\fileserver\finance\Restricted
- Duplicate rows may exist in exports and must be de-duplicated.
- Usernames may vary in case and surrounding whitespace across sources.
