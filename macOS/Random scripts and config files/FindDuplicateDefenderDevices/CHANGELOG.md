# Changelog

All notable changes to Find-DuplicateDefenderDevices.ps1 will be documented in this file.

## [2.4.1] - 2026-02-19

### Documentation
- **Security caveats documented** in README Security section:
  - Memory scrubbing is best-effort: .NET string immutability means nulled variables are not zero'd until GC reclaims the page; short-lived OAuth tokens limit practical exposure
  - PSReadLine history file on disk is not cleared (only in-memory buffer is); low risk when using guided setup since secrets are read from clipboard, not typed
  - Passing secrets as command-line parameters (`-AppSecret`, `-CertificatePassword`) writes them to shell history permanently — guided setup avoids this
- **Large tenant limitations documented** in script header (`KNOWN LIMITATIONS`) and README:
  - Advanced Hunting hard limit of 10,000 rows per query (no pagination support); devices beyond this limit fall back to staleness-only analysis
  - Rate limit retry cap: 3 attempts max (60s + 120s + 180s = 6 min); recommendation to increase `-ThrottleDelayMs` for large tenants
  - Intune pagination uses 1,000 records per page; recommendation to use `-SkipIntune` if cross-reference is not needed in large environments
  - `-Platform All` note: combined device counts can be very large; recommendation to run off-peak with higher throttle delay
- Expanded inline warning when Advanced Hunting 10,000-row limit is hit with actionable context and pointer to script header
- README Limitations section restructured: large tenant concerns in a table (with impact and mitigation columns), general limitations listed separately
- README Usage section restructured: guided setup promoted as recommended entry point with its own subsection; command-line examples moved to a sub-section below
- README: added blog post placeholder link at top

## [2.4.0] - 2026-02-17

### Added
- **MDVM exclusion script generator** (`-GenerateExclusionScript`): after scanning, generates a self-contained `Invoke-ExcludeDevices.ps1` helper script that bulk-excludes flagged devices from Microsoft Defender Vulnerability Management
  - Uses XDRInternals module for portal authentication (ESTSAUTHPERSISTENT cookie flow)
  - Clipboard-based cookie input with no-echo keypress confirmation (prevents terminal flooding)
  - Pre-flight exclusion status check: detects already-excluded devices before processing
  - Comprehensive exclusion report: table + CSV with per-device results (Excluded/AlreadyExcluded/Failed)
  - Batch processing with configurable batch size and throttle delay
  - `MinOrphanScore` filter (default 5) to target only high-confidence orphans
  - `GetStatus` action to check current exclusion state without making changes
  - Runtime risk acceptance gate (type 'YES' to proceed)
  - Secure cleanup: clears cookies, clipboard, PSReadLine history, and forces GC in `finally` block
  - Transcript logging (started after auth to avoid capturing sensitive data)
- Guided setup prompt: interactive `Generate exclusion helper script? [y/N]` when running without parameters
- Disclaimer in script header about undocumented portal APIs

### Changed
- **Clipboard-based credential input**: guided setup prompts for client secret and .pfx password now use clipboard + no-echo keypress instead of Read-Host, preventing secrets from appearing on screen
- **Memory cleanup on exit**: `finally` block scrubs `AppSecret`, `CertificatePassword`, OAuth tokens, and Graph tokens from memory, then forces garbage collection
- **Exclusion helper auth recommendation**: sccauth + XSRF is now the recommended method (more reliable than ESTSAUTHPERSISTENT); XDRay extension instructions added as the easiest capture method
- "Next steps" section is context-aware: shows helper script run commands if generated, otherwise shows manual steps with a TIP about the flag
- Version bumped to 2.4

## [2.3.0] - 2026-02-15

### Added
- **IMEI fallback for mobile devices**: when `HardwareUuid` is unavailable (common for iOS/Android), IMEI from Intune is used as the grouping identifier for duplicate detection
- `IMEI` field in enriched device records and CSV exports

### Changed
- **Intune cross-reference is now enabled by default** — automatically attempts Intune collection and gracefully skips if Graph permissions are unavailable
- Replaced `-CrossReferenceIntune` switch with `-SkipIntune` (opt-out instead of opt-in)
- **Platform-specific device tags**: `-TagStaleDevices` now tags each device based on its actual platform (e.g. `StaleOrphan_macOS`, `StaleOrphan_Windows`) instead of using the scan parameter
- Devices with unknown platform get the base tag without suffix (`StaleOrphan`)
- Console summary uses `$script:intuneAvailable` flag instead of parameter check
- Version bumped to 2.3

## [2.2.0] - 2026-02-14

### Added
- **Certificate-based authentication**: more secure alternative to client secrets
  - `-CertificateThumbprint`: load certificate from local certificate store (CurrentUser\My)
  - `-CertificatePath`: load certificate from .pfx file
  - `-CertificatePassword`: optional password for .pfx file
  - JWT client assertion with RS256 signing (no external modules required)
  - Works for both MDE and Microsoft Graph token endpoints

### Changed
- `-AppSecret` is no longer mandatory — supply either a secret OR a certificate
- Console config display shows authentication method (Secret or Certificate)
- Pre-flight validation updated: requires TenantId, AppId, and one of AppSecret/CertificateThumbprint/CertificatePath
- Help text updated with certificate auth setup instructions and examples
- Version bumped to 2.2

## [2.1.0] - 2026-02-14

### Added
- **Multi-platform support**: `-Platform` parameter (macOS, Windows, iOS, Android, Linux, All). Default: macOS
- Platform-to-API mapping: REST API, KQL, and Intune filters auto-adjust per platform
- Output folder includes platform name for easy identification

### Changed
- **Graduated inactivity scoring**: replaces binary Inactive (+3) and Stale (+3) signals
  - 8-14 days: +1 (recently inactive — could be holiday/travel)
  - 15d to StaleThreshold: +2 (extended absence)
  - StaleThreshold to 3×threshold: +3 (stale)
  - Beyond 3×threshold: +4 (long-term stale)
  - Eliminates false positives for users on vacation (7-day auto-Inactive no longer scores +3)
- Renamed `Get-MdeMacDevices` → `Get-MdeDevices`, `Get-IntuneMacDevices` → `Get-IntuneDevices`
- Script description broadened from macOS-specific to multi-platform
- Console output shows selected platform and host OS separately

## [2.0.0] - 2026-02-14

### Added
- **Tier 1 scoring** — 6 new signals from existing REST API data:
  - +3: Confirmed ghost (group leader active within 7d, this record has >7d lastSeen gap)
  - +2: No `aadDeviceId` (no Entra registration link)
  - +1: Same `aadDeviceId` as group leader (ghost shares Entra identity with real device)
  - +1: Oldest `agentVersion` in group (stale sensor)
  - +1: `defenderAvStatus` = notUpdated or disabled
  - -1: Newest `agentVersion` in group (actively updating sensor)
- **Tier 2 scoring** — DeviceLogonEvents activity check via second Advanced Hunting query:
  - +2: No logon events in last 30 days while sibling has logon activity
  - -1: Has recent logon activity (user actively using device)
- **Tier 3 scoring** — Intune cross-reference via Microsoft Graph (`-CrossReferenceIntune`):
  - +2: No Intune enrollment while sibling is enrolled
  - +1: Intune enrolled but non-compliant
  - -2: Active Intune enrollment with recent sync (within 30 days)
  - Matches MDE devices to Intune by `AadDeviceId` (primary) and `SerialNumber` (fallback)
  - Requires `DeviceManagementManagedDevices.Read.All` Graph API permission
- `AgentVersion` field in enriched device record and CSV exports
- `LastLogonDate`, `RecentLogonCount` fields from logon activity query
- `IntuneDeviceId`, `IntuneCompliance`, `IntuneLastSync`, `IntuneEnrolled` fields
- Microsoft Graph token management and API request wrapper
- `-CrossReferenceIntune` switch parameter
- `-IncludeIntunePermission` switch on `New-MdeAppRegistration.ps1` to add `DeviceManagementManagedDevices.Read.All` Graph permission

### Changed
- Scoring heuristics expanded from 10 to 21 signals (score range -8 to +27)
- Group leader concept: device with most recent `lastSeen` used as reference for gap and identity signals
- `Build-MdeCorrelationMap` now accepts logon activity and Intune data for enrichment
- `tag_recommendations.csv` includes logon activity and Intune columns
- Console summary shows logon activity availability and Intune match stats
- Version bumped to 2.0 (multi-source analysis with optional Intune integration)

## [1.1.0] - 2026-02-14

### Changed
- KQL query: `HardwareUuid` now resolved via `coalesce(column_ifexists(), AdditionalFields)` to handle both direct column and JSON extraction depending on tenant configuration
- Scoring: `ImpairedCommunication` added as standalone health status (+2 points)
- Description: broadened duplicate causes to include reimaging and offboard/re-onboard cycles

### Added
- `SerialNumber` extraction from Advanced Hunting `AdditionalFields` (often empty for macOS, captured when available)
- `ExclusionAdvice` column in `tag_recommendations.csv` with recommended portal action, justification, and notes
- Cleanup workflow guidance in console next steps: directs admins to portal exclusion with justification "Inactive device" and notes "Stale or Orphan device"

## [1.0.0] - 2026-02-14

### Added

- Initial release
- **`New-MdeAppRegistration.ps1`** setup helper: automates App Registration creation with required WindowsDefenderATP permissions, client secret generation, and admin consent grant. Requires `Microsoft.Graph` module and admin role. Parameters: `-AppName`, `-IncludeWritePermission` (Machine.ReadWrite.All for tagging), `-SecretValidityYears` (1-2 years)
- OAuth 2.0 client credentials authentication (TenantId/AppId/AppSecret)
- REST API collection of all macOS devices with pagination (`GET /api/machines`)
- Advanced Hunting KQL query for `HardwareUuid`, `MergedToDeviceId`, `MergedDeviceIds`, `Model`
- Correlation engine: merges REST + Advanced Hunting data, groups by `HardwareUuid`
- Orphan scoring heuristics (10 signals, range -4 to +15):
  - +3: stale (last seen > threshold), health Inactive, merged to another device
  - +2: onboarding InsufficientInfo, health NoSensorData
  - +1: older firstSeen, no tags when sibling has tags
  - -2: survivor record (has MergedDeviceIds)
  - -1: health Active, most recent lastSeen
- Recommendation thresholds: TAG (>=5), REVIEW Moderate (>=3), REVIEW Low (<3), KEEP (lowest in group)
- Unresolved device analysis: staleness-only mode for devices without `HardwareUuid`
- Graceful degradation: falls back to staleness-only if Advanced Hunting fails
- Optional device tagging: `-TagStaleDevices` adds tag via `POST /api/machines/{id}/tags`
- Configurable tag text: `-TagValue` (default: "StaleOrphan")
- Token auto-refresh with 5-minute buffer before expiry
- HTTP 429/503/504 retry with exponential backoff (60s/120s/180s)
- Ctrl+C handling: exports partial results in `finally` block
- Transcript logging for audit trail
- Cross-platform support (Windows, macOS, Linux)
- Color-coded console summary with configurable display limits
- 4 CSV exports:
  - `all_mde_mac_devices.csv` — all macOS devices with full detail
  - `duplicate_device_records.csv` — duplicate groups only
  - `tag_recommendations.csv` — flagged records with scores and reasons
  - `unresolved_devices.csv` — devices without HardwareUuid match
- PSScriptAnalyzer clean (all suppressions justified)
- ISO 8601 DateTime formatting (avoids .NET 7+ ICU mojibake)
