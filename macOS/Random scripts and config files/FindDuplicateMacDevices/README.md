# Find-DuplicateMacDevices.ps1

🍎 𝗡𝗼𝘁𝗲: This script is macOS only (for now… 👀)

Scan Microsoft Entra ID and Intune for macOS devices with **duplicate registrations**, **orphaned device records**, and **Intune-side duplicates**. Identifies cleanup candidates using heuristic scoring, generates CSV reports, and creates a ready-to-run cleanup helper script.

> **Blog post:** [The Hidden Life of Duplicate macOS Device Records in Entra ID](https://allthingscloud.blog/duplicate-macos-device-records-entra-id/)

---

## Disclaimer

**THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.** The author and contributors are not liable for any damage, data loss, or unintended changes resulting from the use of this script.

**Before running this script:**

- **Test in a non-production environment first.** Run against a test tenant or a small device group before scanning your entire production tenant.
- **The script is read-only by default.** Scanning and reporting do not modify any device records. Only the generated `cleanup_helper.ps1` can delete devices, and it requires explicit opt-in per device (`-DeleteDevice $true`) or the `-DeleteAll` switch with manual confirmation.
- **Review every flagged device** in `recommended_cleanup.csv` and `recommended_intune_cleanup.csv` before enabling deletions. The orphan scoring heuristics are designed to be conservative, but automated recommendations are not a substitute for human review.
- **Deleted device records cannot be recovered.** Once a device is removed from Entra ID or Intune, it cannot be restored. Ensure you have verified each record before proceeding with cleanup.
- **You are solely responsible** for any actions taken using this script or its generated cleanup helper.

**Use at your own risk.**

---

## How It Works

1. **Queries Intune** for all macOS managed devices — serial numbers are the stable anchor (the only physical device identifier that doesn't change across registrations, renames, or OS upgrades).
2. **Queries Entra ID** for all Mac-related device records (`MacMDM` + `macOS` operating system types).
3. **Correlates records** by serial number (Intune to Entra via `azureADDeviceId`) and display name.
4. **Scores each record** using orphan heuristics to identify likely duplicates and orphaned records.
5. **Classifies device ownership** using tiered scoring (Intune enrollment signals + Entra TrustType) to distinguish Corporate, BYOD, and Indeterminate devices.
6. **Detects Intune-side duplicates** — multiple Intune managed device records per serial number (caused by re-enrollment without cleanup).
7. **Exports reports** with cleanup recommendations and a ready-to-run helper script.

---

## Prerequisites

- **PowerShell 7+** (Windows, macOS, or Linux)
- **Microsoft.Graph module** — Install with:
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
- **Microsoft Graph permissions:**

  | Permission | Required | Purpose |
  |---|---|---|
  | `Device.Read.All` | Yes | Read Entra ID device records |
  | `DeviceManagementManagedDevices.Read.All` | Yes | Read Intune managed devices |
  | `User.Read.All` | Optional | User status checks (skip with `-SkipUserLookup`) |
  | `Device.ReadWrite.All` | Only for cleanup | Required by `cleanup_helper.ps1` to delete Entra devices |

---

## Quick Start

```powershell
# Basic scan (30-day stale threshold, default settings)
.\Find-DuplicateMacDevices.ps1

# Custom stale threshold
.\Find-DuplicateMacDevices.ps1 -StaleThresholdDays 60

# Skip user lookups (no User.Read.All needed)
.\Find-DuplicateMacDevices.ps1 -SkipUserLookup

# Use existing Graph session
.\Find-DuplicateMacDevices.ps1 -SkipConnect

# Large tenant — increase delay between API calls
.\Find-DuplicateMacDevices.ps1 -ThrottleDelayMs 200

# Show more items in console output
.\Find-DuplicateMacDevices.ps1 -MaxDisplayItems 50
```

The script will connect to Microsoft Graph, scan your tenant, and create a timestamped output folder on your Desktop (e.g., `MacOS_DuplicateReport_20260213_143022/`).

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-StaleThresholdDays` | int | 30 | Days since last sign-in to consider a device record stale |
| `-OutputPath` | string | Desktop (auto) | Output directory for CSV results |
| `-SkipConnect` | switch | false | Use existing Graph session instead of reconnecting |
| `-ThrottleDelayMs` | int | 100 | Delay in ms between API requests (increase for large tenants) |
| `-SkipUserLookup` | switch | false | Skip user status lookups, removes `User.Read.All` requirement |
| `-MaxDisplayItems` | int | 25 | Maximum items shown per console detail section (full data always in CSV) |

---

## Orphan Scoring (Entra Records)

Each Entra device record is scored to estimate how likely it is to be an orphan. Higher score = more likely orphan.

| Points | Signal | Notes |
|---|---|---|
| +3 | No MDM binding (`mdmAppId` is null) | Strong signal — healthy records always have MDM |
| +3 | Primary user account deleted | Skipped with `-SkipUserLookup` |
| +2 | Stale device (no sign-in within threshold) | Based on `-StaleThresholdDays` |
| +2 | Device account disabled | |
| +2 | Primary user account disabled | Skipped with `-SkipUserLookup` |
| +1 | Both user AND device are stale | Reinforced staleness; skipped with `-SkipUserLookup` |
| +1 | `operatingSystem = "macOS"` alongside `"MacMDM"` | PSSO-created record next to MDM record |
| +1 | Simplified OS version format | `"15.7.0"` vs `"15.7 (24G222)"` — PSSO origin |
| +1 | Not compliant (when sibling is compliant) | |
| +1 | No matching Intune managed device | |

**Thresholds:**
- The record with the **lowest** score per serial number is marked `KEEP (Primary)`.
- Score >= 5: `REMOVE (High confidence)`
- Score >= 3: `REVIEW (Likely orphan)`
- Score < 3: `REVIEW (Low confidence)`

---

## Orphan Scoring (Intune Records)

When multiple Intune managed device records exist for the same serial number, each is scored independently.

| Points | Signal |
|---|---|
| +3 | Stale sync (last sync exceeds threshold) |
| +3 | Primary user account deleted (skipped with `-SkipUserLookup`) |
| +2 | No matching Entra device record |
| +2 | Primary user account disabled (skipped with `-SkipUserLookup`) |
| +1 | Not compliant |
| +1 | Older enrollment date (not the most recent) |

Same thresholds apply: >= 5 REMOVE, >= 3 REVIEW.

---

## Ownership Classification

Devices are classified as **Corporate**, **BYOD**, or **Indeterminate** using a tiered scoring model. BYOD devices are **never** flagged for deletion.

| Tier | Signal | Corporate | BYOD |
|---|---|---|---|
| 1 (Definitive) | `deviceEnrollmentType` | ADE enrollment: -10 | User enrollment: +10 |
| 2 (Admin-set) | `managedDeviceOwnerType` | company: -5 | personal: +5 |
| 2 (Admin-set) | `enrollmentProfileName` | Present: -4 | |
| 3 (Supporting) | `isSupervised` | true: -3 | |
| 3 (Supporting) | Entra `TrustType` | AzureAD: -2 | Workplace: +2 |

**Classification thresholds:**
- Score <= -3: Corporate
- Score >= +3: BYOD
- Score -2 to +2: Indeterminate (treated as Corporate for safety)

**Admin override:** If `managedDeviceOwnerType = "company"`, the device is always classified as Corporate regardless of score.

---

## Output Files

All files are created in the output folder (Desktop by default).

| File | Description |
|---|---|
| `all_mac_device_records.csv` | Every analyzed Entra record, including healthy single-record devices |
| `duplicate_and_orphan_records.csv` | Only records where duplicates or detached orphans exist |
| `recommended_cleanup.csv` | Entra records flagged for REMOVE or REVIEW |
| `intune_duplicate_records.csv` | All Intune records for serials with >1 managed device |
| `recommended_intune_cleanup.csv` | Intune records flagged for REMOVE or REVIEW |
| `cleanup_helper.ps1` | Ready-to-run cleanup script with per-device safety flags |
| `scan_transcript.log` | Full console output for audit trail |

**Note:** `intune_duplicate_records.csv` and `recommended_intune_cleanup.csv` are only created when Intune-side duplicates are found.

---

## Cleanup Workflow

### Step 1: Review the reports

Open `recommended_cleanup.csv` (and `recommended_intune_cleanup.csv` if present). Review each flagged device:
- Check the `Recommendation` column (REMOVE vs REVIEW)
- Check the `RecommendReason` column for why it was flagged
- Cross-reference with Entra audit logs if needed

### Step 2: Connect with write permissions

```powershell
Connect-MgGraph -Scopes "Device.ReadWrite.All" -NoWelcome
```

### Step 3: Run the cleanup helper

**Option A: Selective deletion (recommended)**

Edit `cleanup_helper.ps1` and change `-DeleteDevice $false` to `$true` for each verified device:

```powershell
Remove-OrphanDevice `
    -ObjectId 'abc123...' `
    -DisplayName 'MacBook-Pro' `
    -DeleteDevice $true  # <-- Enable deletion for this device
```

Then run:
```powershell
.\cleanup_helper.ps1
```

**Option B: Delete ALL flagged devices**

If you've reviewed every record in the CSV:
```powershell
.\cleanup_helper.ps1 -DeleteAll
```
You'll be prompted to type `DELETE ALL` to confirm.

**Preview mode:**
```powershell
.\cleanup_helper.ps1 -WhatIf            # Preview selective deletions
.\cleanup_helper.ps1 -DeleteAll -WhatIf  # Preview what -DeleteAll would delete
```

### Step 4: Verify

Re-run the scanner to confirm cleanup:
```powershell
.\Find-DuplicateMacDevices.ps1 -SkipConnect
```

---

## Security Notes

- **BYOD devices are never flagged for deletion.** Personal devices registered with Entra ID (TrustType = "Workplace" or ownership score >= +3) are explicitly protected.
- **Indeterminate devices are treated as Corporate.** When ownership can't be determined, the script errs on the side of caution.
- **The cleanup helper is safe by default.** Every device has `-DeleteDevice $false` — you must explicitly opt-in per device or use `-DeleteAll` with confirmation.
- **Rate limiting is built in.** The script includes automatic retry with exponential backoff on HTTP 429 responses.

---

## Part of the PSSO Troubleshooting Toolkit

This script is part of a broader toolkit for diagnosing Platform SSO issues on macOS. See the [main README](README.md) for the full toolkit, including:

- `capture-local-logs-v1.2.sh` — Local Mac log capture during PSSO tests
- `Monitor-GraphDeviceType-v1.8.ps1` — Real-time Graph API monitoring during tests
- `audit_timeline.html` — Interactive audit log visualization

---

## Changelog

See [CHANGELOG-FD.md](CHANGELOG.md) for the full version history.

---

## Author

**Oktay Sari** | [allthingscloud.blog](https://allthingscloud.blog) | Microsoft MVP (Security & Intune)
