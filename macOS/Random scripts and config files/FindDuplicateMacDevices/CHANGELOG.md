# Changelog — Find-DuplicateMacDevices.ps1

All notable changes to the **Find-DuplicateMacDevices** duplicate scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.13] - 2026-02-12

### Added
- **Intune-side duplicate detection** — Multiple Intune managed device records for the same serial number (caused by re-enrollment without cleanup) are now detected, scored, and reported. Previously, only Entra-side duplicates were flagged; Intune duplicates were grouped but silently ignored.
- **`HasIntuneDuplicates` field in correlation map** — Non-breaking addition alongside existing `HasDuplicates` (Entra-only); enables independent tracking of Intune-side and Entra-side duplicates per serial number.
- **`Get-IntuneRecordAnalysis` function** — Analyzes individual Intune records with status (compliance, last sync, enrollment date, Entra match), ownership classification, and user info from cache.
- **`Get-IntuneCleanupRecommendation` function** — Scores Intune records using Intune-specific heuristics: +3 stale sync, +3 user deleted (skipped with `-SkipUserLookup`), +2 no Entra match, +2 user disabled (skipped with `-SkipUserLookup`), +1 non-compliant, +1 older enrollment. Same thresholds as Entra scoring (>=5 REMOVE, >=3 REVIEW). BYOD never flagged.
- **New CSV exports** (only when Intune duplicates exist):
  - `intune_duplicate_records.csv` — All records for serials with >1 Intune device
  - `recommended_intune_cleanup.csv` — Subset flagged REMOVE/REVIEW, BYOD excluded
- **Intune section in cleanup helper** — `cleanup_helper.ps1` now has a separate `# === INTUNE ORPHAN CLEANUP ===` section with `Remove-IntuneOrphanDevice` function (same pattern: `SupportsShouldProcess`, `-DeleteDevice $false`, respects `-DeleteAll` and `-WhatIf`). Uses `Remove-MgDeviceManagementManagedDevice`. Summary shows separate Entra and Intune counters.
- **`INTUNE DUPLICATE DEVICE DETAILS` console section** — Shows per-serial breakdown with recommendation, compliance, last sync, enrolled date, and Entra match.
- **Intune duplicate stats** in scan summary: `IntuneDuplicateSerials`, `IntuneOrphanRecords`, `IntuneRecommendedCleanup`.
- **`-MaxDisplayItems` parameter** (default 25, range 1-1000) — Caps all four console detail sections (Entra duplicates, detached records, Intune duplicates, BYOD devices) to prevent console flood in large tenants. Overflow warning directs to the relevant CSV file for full data.

### Changed
- Cleanup helper header updated to document both Entra and Intune sections, permissions, and module requirements.
- Cleanup helper `#Requires` directive now includes `Microsoft.Graph.DeviceManagement` when Intune cleanup targets exist.
- "Next steps" at scan completion now mentions `recommended_intune_cleanup.csv` when Intune duplicates are found.
- Startup banner shows console display cap setting.

---

## [1.12] - 2026-02-12

### Added
- **`-SkipUserLookup` switch parameter** — Skips all user status lookups (batch API calls, orphan scoring based on user state, user info in console output). Removes the `User.Read.All` permission requirement, making the script usable by admins who only have device-level Graph permissions. User-related CSV columns are still present (show N/A) so the export format stays consistent.

### Changed
- **`User.Read.All` scope now conditional** — Graph connection only requests `User.Read.All` when user lookup is enabled (the default). With `-SkipUserLookup`, only `Device.Read.All` and `DeviceManagementManagedDevices.Read.All` are required.
- **Orphan scoring adapts to user lookup state** — Three user-based scoring rules (+3 user deleted, +2 user disabled, +1 user+device both stale) are skipped when `-SkipUserLookup` is set. Remaining device-based signals still provide solid orphan detection.
- **Startup banner shows user lookup status** — New "User lookup: Enabled/Disabled" line in the configuration summary at startup.

---

## [1.11] - 2026-02-12

### Changed
- **Batch user lookups via Graph `$batch` API** — Replaced sequential per-UPN HTTP calls with batched requests (20 UPNs per `$batch` call). In a 284-device / 259-user tenant, this reduces ~259 sequential round-trips (~4 min 44 sec) to ~15 batch calls (~15 sec). Two-phase approach: Phase 1 resolves active users, Phase 2 checks `/directory/deletedItems` for UPNs not found in Phase 1.
- **`Invoke-UserStatusBatch` function** — New function accepts an array of UPNs, builds Graph `$batch` payloads, and populates `$script:UserCache` with the same Status/IsDeleted/IsDisabled/LastSignIn/DaysSinceSignIn values as the previous sequential implementation.
- **`Get-UserStatus` simplified to cache reader** — Now only reads from `$script:UserCache` (populated by `Invoke-UserStatusBatch` before the analysis loop). No API calls, no behavior change for callers.
- **Batch pre-pass in Step 5** — Before analyzing individual device records, the script collects all unique UPNs from Intune records into a HashSet and resolves them in bulk. The per-record analysis loop is unchanged.
- **Progress reporting during batch phase** — DarkGray status lines show `Batch N/M: X of Y users resolved...` instead of a silent multi-minute wait.
- **Throttle handling for batch calls** — Reuses the existing exponential backoff pattern (60s, 120s, 180s) from `Invoke-MgGraphPaginatedRequest` for 429/503/504 errors.

---

## [1.10] - 2026-02-11

### Added
- **Tiered BYOD ownership scoring** — Replaced single-signal BYOD detection (`TrustType = Workplace`) with a multi-signal scoring model using Intune enrollment data as the primary signal and Entra TrustType as a fallback. This fixes misclassification of corporate Macs that haven't completed PSSO registration (which temporarily show `TrustType = Workplace`).
- **`Get-OwnershipClassification` function** — New scoring function that evaluates signals across three tiers:
  - Tier 1 (definitive): `deviceEnrollmentType` — ADE enrollment (-10) vs user enrollment (+10)
  - Tier 2 (admin-set): `managedDeviceOwnerType` (-5/+5), `enrollmentProfileName` (-4 if present)
  - Tier 3 (supporting): `isSupervised` (-3), Entra `TrustType` (-2/+2)
- **Admin override rule** — If `managedDeviceOwnerType = "company"` and the raw score would not classify as Corporate, the classification is forced to Corporate (admin intent respected).
- **Indeterminate safety default** — Scores between -2 and +2 are classified as "Indeterminate" and treated as Corporate for safety (better to protect a BYOD device from deletion than accidentally delete a corporate one).
- **New output fields** in CSV exports: `OwnershipScore`, `OwnershipClassification`, `OwnershipSignals`, `DeviceEnrollmentType`, `ManagedDeviceOwnerType`, `IntuneEnrollmentProfile`, `IsSupervised`.
- **Enhanced Intune API query** — Added `managedDeviceOwnerType`, `enrollmentProfileName`, `isSupervised` to the `$select` parameter.

### Changed
- BYOD section console output now shows ownership score and classification alongside each device, plus the scoring signals.
- `recommended_cleanup.csv` now includes `OwnershipClassification`, `OwnershipScore`, `OwnershipSignals` columns.
- Detached Entra records (no Intune backing) now use ownership scoring with only Tier 3 signals, instead of raw TrustType check.

---

## [1.9.2] - 2026-02-11

### Added
- **Pre-flight module check** — Script now checks if `Microsoft.Graph.Authentication` is installed before attempting any Graph calls. Shows a clear `[FAIL]` message with install instructions instead of a cryptic "Get-MgContext is not recognized" error. Works on both Windows and macOS.

---

## [1.9.1] - 2026-02-09

### Fixed
- **User status query failing with "Get By Key only supports UserId"** — Some tenants reject direct user lookup by UPN via `/users/{upn}` endpoint. Changed to use filter query (`/users?$filter=userPrincipalName eq '...'`) which is more reliable across all tenants.
- **Unused variable warning** — Removed unused `$userStatus` variable assignment in `Get-UserStatusForDuplicateDevice`.

---

## [1.9.0] - 2026-02-09

### Added
- **User status checks for duplicate devices** — When duplicates are detected, the script now queries the primary user's account status (Active, Disabled, Deleted) and last sign-in date.
- **Tenant compliance validity period query** — Automatically queries the tenant's compliance status validity period setting (deviceComplianceCheckinThresholdDays) at startup.
- **Stale threshold mismatch warning** — If the script's `-StaleThresholdDays` parameter differs from the tenant's compliance validity period, a configuration mismatch warning is displayed with guidance to align the values.
- **`User.Read.All` permission** — New required scope for querying user account status and sign-in activity.
- **New output fields** in CSV exports: `PrimaryUser`, `PrimaryUserStatus`, `PrimaryUserLastSignIn`, `PrimaryUserDaysSinceSignIn`, `PrimaryUserIsStale`.
- **User status in cleanup helper** — Generated `cleanup_helper.ps1` now includes primary user status in the device comments for easier review.
- **User status caching** — User queries are cached to avoid duplicate API calls when the same user owns multiple devices.

### Changed
- **Enhanced orphan scoring heuristics**: +3 points for primary user deleted, +2 points for primary user disabled, +1 point for both user AND device stale.
- `recommended_cleanup.csv` now includes user status columns.
- Version displayed in startup header.

---

## [1.8.3] - 2026-02-09

### Fixed
- **`-DeleteAll -WhatIf` still prompting for confirmation** — When using `-WhatIf` with `-DeleteAll`, the script was still asking to type "DELETE ALL" to confirm. Now checks `$WhatIfPreference` and skips the confirmation prompt in WhatIf mode, showing a cyan "WHATIF: -DeleteAll MODE (Preview Only)" banner instead.

---

## [1.8.2] - 2026-02-09

### Fixed
- **`-WhatIf` not working on cleanup helper script** — The generated `cleanup_helper.ps1` had `[CmdletBinding()]` but needed `[CmdletBinding(SupportsShouldProcess)]` at the script level for `-WhatIf` to work. The function inside had it, but PowerShell requires it on the script's param block for script-level `-WhatIf` support.

---

## [1.8.1] - 2026-02-09

### Fixed
- **Empty response objects added to results** — When Graph API returned a page with an empty `.value` array, the pagination function incorrectly added the raw response object (containing `@odata.context` metadata) to results. This appeared as a detached device record with all empty/null properties. Fixed by checking for `$null` explicitly instead of truthiness (empty arrays are falsy in PowerShell).

---

## [1.8.0] - 2026-02-09

### Added
- **Rate limiting and throttle detection** — New `Invoke-MgGraphPaginatedRequest` function handles Graph API pagination with built-in rate limit detection, exponential backoff retry (60s, 120s, 180s), and configurable delays between requests.
- **`-ThrottleDelayMs` parameter** — Configure delay between API requests (default: 100ms). Increase for large tenants to avoid throttling. Example: `-ThrottleDelayMs 200`.
- **Automatic retry on HTTP 429** — When Graph API returns "Too Many Requests", the script waits and retries up to 3 times with increasing delays.
- **Raw API for Entra queries** — Switched from `Get-MgDevice -All` cmdlet to raw `Invoke-MgGraphRequest` for consistent throttle handling across all API calls.

### Changed
- Both Intune and Entra device queries now use the same paginated request function for consistent behavior.
- Throttle delay is displayed in the startup summary.
- Property access updated to use camelCase (matching raw API response format).

---

## [1.7.0] - 2026-02-09

### Added
- **BYOD device detection** — Devices with `TrustType = Workplace` (Entra ID registered / personal devices) are now detected and explicitly protected from deletion.
- **`IsBYOD` field** — New boolean field in all CSV exports indicates whether a device is a BYOD device.
- **BYOD section in console output** — New "BYOD DEVICES (Excluded from Cleanup)" section shows all detected BYOD devices.
- **BYOD counter in summary** — Summary now shows count of BYOD devices excluded from cleanup.

### Security
- BYOD devices (personal devices registered with Entra ID) are **NEVER** flagged for deletion, preventing accidental removal of legitimate user devices.

---

## [1.6.0] - 2026-02-09

### Added
- **`-WhatIf` support for cleanup helper** — Generated `cleanup_helper.ps1` now supports PowerShell's standard `-WhatIf` parameter. Run `.\cleanup_helper.ps1 -WhatIf` to preview which devices would be deleted without actually removing them.
- **`SupportsShouldProcess` attribute** — `Remove-OrphanDevice` function now uses `[CmdletBinding(SupportsShouldProcess)]` and `$PSCmdlet.ShouldProcess()` for proper PowerShell state-changing function compliance.

---

## [1.5.0] - 2026-02-09

### Fixed
- **PSScriptAnalyzer compliance for generated cleanup helper** — The auto-generated `cleanup_helper.ps1` now passes PSScriptAnalyzer with only expected Write-Host warnings: removed unused parameters, all `Write-Host`/`Read-Host` calls now use named parameters, added CODE QUALITY header.

---

## [1.4.0] - 2026-02-09

### Added
- **`-DeleteAll` switch for cleanup helper** — Generated `cleanup_helper.ps1` now supports a `-DeleteAll` switch to delete all flagged devices at once, instead of manually editing each `-DeleteDevice $false` to `$true`.
- **Safety confirmation for -DeleteAll** — When using `-DeleteAll`, user must type `DELETE ALL` (exact match) to confirm. Prevents accidental mass deletion.

---

## [1.3.0] - 2026-02-09

### Added
- **Overwrite warning for existing output folder** — When the specified output folder already exists, the script now prompts for confirmation before overwriting. Prevents accidental loss of previous scan results.

---

## [1.2.0] - 2026-02-09

### Changed
- **Enhanced cleanup helper script** — Complete rewrite of generated `cleanup_helper.ps1` with `Remove-OrphanDevice` function, per-device `-DeleteDevice $false` safety flags, try/catch error handling, success/failed/skipped counters, and color-coded summary report.

---

## [1.1.0] - 2026-02-09

### Added
- **O(1) DisplayName index** — Entra devices indexed by DisplayName hashtable for faster correlation.
- **Transcript logging** — `Start-Transcript`/`Stop-Transcript` captures all console output to `scan_transcript.log`.
- **Ctrl+C graceful handling** — `try`/`finally` wrapping exports partial results if interrupted.
- **ISO 8601 DateTime formatting** — Explicit format strings to avoid .NET 7+ ICU Unicode mojibake.
- **HashSet-based stale tracking** — Prevents double-counting stale records across duplicates.

### Fixed
- **Stale record double-counting** — Devices with multiple stale duplicates were counted multiple times. Now tracked by unique serial number.

---

## [1.0.0] - 2026-02-09

### Added
- Initial release.
- **Serial number-based correlation** — Uses Intune serial numbers as the stable physical device identifier.
- **Dual-source scanning** — Queries both Intune managed devices (beta API) and Entra ID device records.
- **Correlation map** — Links physical devices (by serial) to all their Intune and Entra records.
- **Detached orphan detection** — Identifies Entra records with no Intune backing at all.
- **Orphan scoring heuristics** — Scores each record to identify likely orphans: +3 no MDM, +2 stale, +2 disabled, +1 macOS alongside MacMDM, +1 simplified OS version, +1 non-compliant, +1 no Intune match.
- **Cleanup recommendations** — Lowest-scoring record per device marked as "KEEP (Primary)", others flagged as "REMOVE" or "REVIEW" based on confidence.
- **CSV exports**: `all_mac_device_records.csv`, `duplicate_and_orphan_records.csv`, `recommended_cleanup.csv`.
- **Cleanup helper script** — Auto-generated `cleanup_helper.ps1` with commented-out removal commands.
- **Cross-platform support** — Works on Windows, macOS, and Linux with automatic Desktop path detection.
- **Console summary** — Color-coded output with scan statistics, duplicate details, and detached orphan warnings.
- **Configurable parameters**: `-StaleThresholdDays`, `-OutputPath`, `-SkipConnect`.
- Required Graph API scopes: `Device.Read.All`, `DeviceManagementManagedDevices.Read.All`.

---

## References

- [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
- [PSSO Troubleshooting Toolkit](README.md)
