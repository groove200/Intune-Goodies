# Find-DuplicateDefenderDevices

> **Blog post:** [coming soon](#)

Scans Microsoft Defender for Endpoint for devices with duplicate registrations.

Supports: **macOS**, **Windows**, **iOS**, **Android**, **Linux**, or **All** platforms.

## The Problem

Defender for Endpoint creates a new device record whenever a device's hostname changes, is reimaged, or is offboarded and re-onboarded. The old record persists for up to 180 days, consuming a license. MDE has built-in deduplication, but it doesn't catch everything. This script identifies the duplicates that slip through.

## How It Works

1. Authenticates to the MDE API using OAuth 2.0 client credentials (secret or certificate)
2. Pulls all macOS devices from the MDE REST API (paginated)
3. Queries Advanced Hunting for `HardwareUuid` — the stable hardware identifier
4. Groups device records by `HardwareUuid` to find duplicates
5. Queries DeviceLogonEvents for recent user activity per device
6. Scores each record in a duplicate group using 21 heuristic signals
7. Cross-references Intune for enrollment status and IMEI (automatic, graceful degradation)
8. Uses IMEI as fallback identifier for mobile devices without HardwareUuid
9. Optionally tags high-confidence orphans in the MDE portal
10. Exports CSV reports for admin review

## Requirements

- PowerShell 7+
- Azure App Registration with `WindowsDefenderATP` permissions:
  - `Machine.Read.All` — read device records
  - `AdvancedQuery.Read.All` — Advanced Hunting for hardware identifiers + logon activity
  - `Machine.ReadWrite.All` — tag stale devices (optional)
- Authentication: **client secret** or **certificate** (choose one)
  - Client secret: create under Certificates & secrets > Client secrets
  - Certificate: upload public key (.cer/.pem) under Certificates & secrets > Certificates, keep .pfx locally
- `Microsoft Graph` permissions (for Intune cross-reference, enabled by default):
  - `DeviceManagementManagedDevices.Read.All` — read Intune managed devices + IMEI for mobile
  - If not available, Intune data is skipped automatically
- Microsoft Defender for Endpoint P1 or P2 license

### Automated Setup

Use `New-MdeAppRegistration.ps1` to create the App Registration automatically instead of the manual steps above:

```powershell
# Basic setup (read-only permissions + client secret)
./New-MdeAppRegistration.ps1

# Custom app name
./New-MdeAppRegistration.ps1 -AppName "My MDE Scanner"

# Include tagging permission (Machine.ReadWrite.All)
./New-MdeAppRegistration.ps1 -IncludeWritePermission

# Include Intune cross-reference permission (DeviceManagementManagedDevices.Read.All)
./New-MdeAppRegistration.ps1 -IncludeIntunePermission

# All permissions (tagging + Intune)
./New-MdeAppRegistration.ps1 -IncludeWritePermission -IncludeIntunePermission

# Custom secret validity (default: 1 year, max: 2 years)
./New-MdeAppRegistration.ps1 -SecretValidityYears 2
```

**Requires:** PowerShell 7+, `Microsoft.Graph` module (`Install-Module Microsoft.Graph -Scope CurrentUser`), and Global Administrator or Application Administrator role.

The script will:
1. Connect to Microsoft Graph (interactive sign-in)
2. Create the App Registration with the required API permissions
3. Create a client secret
4. Grant admin consent automatically
5. Display the TenantId, AppId, and AppSecret ready to copy

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `AppName` | string | MDE Duplicate Scanner | Display name for the App Registration |
| `IncludeWritePermission` | switch | off | Add `Machine.ReadWrite.All` for device tagging |
| `IncludeIntunePermission` | switch | off | Add `DeviceManagementManagedDevices.Read.All` for Intune cross-reference |
| `SecretValidityYears` | int | 1 | Client secret validity period (1-2 years) |

> **Note:** Save the AppSecret immediately — it cannot be retrieved again after the setup screen. For certificate-based auth, create the app manually or upload the certificate after running this script.

## Usage

### Guided setup (recommended)

Run the script with no parameters to launch the interactive guided setup:

```powershell
./Find-DuplicateDefenderDevices.ps1
```

The guided setup walks you through:

1. **Platform** — choose macOS, Windows, iOS, Android, Linux, or All
2. **Authentication** — enter Tenant ID and App ID, then choose between client secret (read from clipboard), certificate thumbprint, or .pfx file
3. **Options** — optionally enable device tagging (with custom tag name and score threshold), generate the exclusion helper script, and set a custom stale threshold

Secrets and .pfx passwords are read from the clipboard — nothing is typed or displayed on screen.

### Command-line usage

```powershell
# Basic scan — macOS (default), client secret auth
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>"

# Certificate auth — from local certificate store (thumbprint)
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -CertificateThumbprint "<thumbprint>"

# Certificate auth — from .pfx file
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -CertificatePath "cert.pfx"

# Certificate auth — .pfx with password
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -CertificatePath "cert.pfx" -CertificatePassword "pass"

# Scan Windows devices
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -Platform Windows

# Scan all platforms
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -Platform All

# Custom stale threshold
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -StaleThresholdDays 60

# Tag stale devices in MDE portal
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -TagStaleDevices

# Skip Intune cross-reference (if Graph permissions are not available)
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -SkipIntune

# Generate MDVM exclusion helper script after scan
./Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -GenerateExclusionScript
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Platform` | string | macOS | Platform to scan: macOS, Windows, iOS, Android, Linux, or All |
| `TenantId` | string | (required) | Azure AD tenant ID |
| `AppId` | string | (required) | App registration application (client) ID |
| `AppSecret` | string | — | App registration client secret (use this OR certificate) |
| `CertificateThumbprint` | string | — | Certificate thumbprint (loads from local certificate store) |
| `CertificatePath` | string | — | Path to .pfx certificate file |
| `CertificatePassword` | string | — | Password for .pfx certificate file (omit if no password) |
| `StaleThresholdDays` | int | 30 | Days since last seen to consider a record stale |
| `OutputPath` | string | Desktop (auto) | Output directory for CSV results |
| `TagStaleDevices` | switch | off | Tag high-confidence orphans in MDE portal |
| `TagValue` | string | StaleOrphan | Tag text to apply to stale devices |
| `ThrottleDelayMs` | int | 100 | Delay in ms between API requests (0-5000) |
| `MaxDisplayItems` | int | 25 | Max items shown per console section (1-1000) |
| `SkipIntune` | switch | off | Skip Intune cross-reference (enabled by default, graceful degradation) |
| `GenerateExclusionScript` | switch | off | Generate a helper script to bulk-exclude TAG/REVIEW devices from MDVM |
| `TagThreshold` | int | 5 | Minimum OrphanScore for TAG recommendation (1-15) |
| `WhatIf` | switch | off | Preview tagging actions without applying changes |

## Orphan Scoring

Each record in a duplicate group is scored using these signals:

### Tier 1 — MDE REST API signals (always active)

| Score | Signal |
|-------|--------|
| +1 to +4 | Graduated inactivity: +1 (8-14d), +2 (15-threshold), +3 (threshold-3x), +4 (>3x threshold) |
| +3 | Has `MergedToDeviceId` (absorbed by MDE dedup) |
| +3 | Confirmed ghost: group leader active within 7d, this record has >7d gap |
| +2 | `onboardingStatus` = InsufficientInfo |
| +2 | `healthStatus` = NoSensorData / ImpairedCommunication |
| +2 | No `aadDeviceId` (no Entra registration) |
| +1 | Older `firstSeen` (not newest in group) |
| +1 | No `machineTags` while sibling has tags |
| +1 | Same `aadDeviceId` as group leader (ghost shares Entra identity) |
| +1 | Oldest `agentVersion` in group |
| +1 | `defenderAvStatus` = notUpdated / disabled |
| -2 | Has `MergedDeviceIds` (survivor record) |
| -1 | `healthStatus` = Active |
| -1 | Most recent `lastSeen` in group |
| -1 | Newest `agentVersion` in group |

### Tier 2 — Advanced Hunting logon activity (automatic)

| Score | Signal |
|-------|--------|
| +2 | No logon events in last 30d while sibling has logon activity |
| -1 | Has recent logon activity |

### Tier 3 — Intune cross-reference (automatic, use `-SkipIntune` to disable)

| Score | Signal |
|-------|--------|
| +2 | No Intune enrollment while sibling is enrolled |
| +1 | Intune enrolled but non-compliant |
| -2 | Active Intune enrollment with recent sync (within 30d) |

**Thresholds:** >= 5 TAG, >= 3 REVIEW (Moderate), < 3 REVIEW (Low), lowest score KEEP

## Output Files

| File | Contents |
|------|----------|
| `all_mde_{platform}_devices.csv` | All devices with full analysis detail |
| `duplicate_{platform}_records.csv` | Only duplicate groups (2+ records per HardwareUuid) |
| `tag_{platform}_recommendations.csv` | Flagged records with scores, reasons, exclusion advice, and tag status |
| `unresolved_{platform}_devices.csv` | Devices without HardwareUuid (staleness-only analysis) |
| `Invoke-ExcludeDevices.ps1` | Generated helper script for MDVM exclusion (when `-GenerateExclusionScript` is used) |
| `scan_transcript.log` | Full session transcript for audit trail |

## Recommended Cleanup Workflow

### Option A: Automated exclusion (recommended)

1. Run the scanner with `-TagStaleDevices -GenerateExclusionScript`
2. Review `tag_recommendations.csv` — each row includes scores, reasons, and exclusion advice
3. Run the generated `Invoke-ExcludeDevices.ps1` to bulk-exclude flagged devices from MDVM
4. The helper script performs pre-flight checks (skips already-excluded devices) and produces an exclusion report

### Option B: Manual exclusion

1. Run this script with `-TagStaleDevices` to auto-tag high-confidence orphans
2. Review `tag_recommendations.csv` — each row includes an `ExclusionAdvice` column
3. In security.microsoft.com > Device inventory, filter by tag to find tagged devices
4. Select stale devices and choose **Exclude** with justification "Inactive device" and notes "Stale or Orphan device"

In both cases, the 180-day retention handles final removal of excluded records.

### About the exclusion helper script

The generated `Invoke-ExcludeDevices.ps1` uses the **XDRInternals** PowerShell module to authenticate to the Microsoft Defender XDR portal via browser session cookies. This uses undocumented portal APIs (`UpdateExclusionState`) since Microsoft does not provide a public REST API for device exclusion.

> **Important:** The exclusion helper requires a separate authentication flow (portal session cookie) from the scanner's OAuth credentials. See the generated script's built-in instructions for details.

## Security

- **Credential input**: In guided setup mode, client secrets and .pfx passwords are read from the clipboard (not typed). Nothing is displayed on screen.
- **Memory cleanup**: On exit (normal or interrupted), the script scrubs secrets, OAuth tokens, and Graph tokens from memory and forces garbage collection.
- **Transcript safety**: The scan transcript does not capture credential prompts.
- **Exclusion helper**: Cookie values are read via clipboard with no-echo keypress. All sensitive variables, clipboard contents, and PSReadLine history are scrubbed on exit.

### Security caveats

- **Memory scrubbing is best-effort**: PowerShell strings are immutable .NET objects. Nulling a variable removes the reference but does not zero the underlying memory — the data remains until the garbage collector reclaims and overwrites that page. A memory dump taken immediately after exit could theoretically still recover token values. OAuth tokens are short-lived (1 hour), which limits the practical exposure window.
- **PSReadLine history file is not cleared**: The in-memory history buffer is cleared on exit, but the history file on disk (`~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt` on macOS/Linux, `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\` on Windows) is not modified. Since guided setup reads secrets from the clipboard rather than the keyboard, nothing sensitive is written to the history file during normal use.
- **Passing secrets as command-line parameters**: If `-AppSecret` or `-CertificatePassword` are passed directly on the command line (instead of using guided setup), the values will appear in your shell history (`~/.zsh_history`, `~/.bash_history`, or the PSReadLine history file) and cannot be removed by the script. **Use guided setup to avoid this.**

## Limitations

### Large tenant considerations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **Advanced Hunting returns a maximum of 10,000 rows** (API hard limit, no pagination) | Devices beyond the limit have no `HardwareUuid` and cannot be grouped by hardware. Duplicate detection for those devices falls back to staleness-only analysis. This is a known API constraint — there is no workaround. | Split scans by platform instead of using `-Platform All` to reduce the result set per query |
| **Rate limit retries cap at 3 attempts** (6 minutes max: 60s + 120s + 180s) | A 4th consecutive HTTP 429 failure aborts the scan | Increase `-ThrottleDelayMs` (e.g. 500–1000) to reduce throttling frequency, especially for large tenants |
| **Intune pagination uses 1,000 records per page** | Increases Graph API call count for large Intune environments | Use `-SkipIntune` if Intune cross-reference is not needed |
| **`-Platform All` fetches all platforms in a single query** | Device counts can be very large, increasing scan time and throttling risk | Run during off-peak hours and use `-ThrottleDelayMs 500` or higher |

### General limitations

- Cannot delete or offboard macOS/mobile devices via API (Windows-only feature)
- Device exclusion uses undocumented portal APIs via XDRInternals (no official REST API)
- Serial numbers are often empty in Advanced Hunting for macOS (captured when available)
- `HardwareUuid` requires Advanced Hunting (not available via REST API alone); may be empty for mobile platforms — IMEI from Intune is used as fallback
- Advanced Hunting has a 30-day lookback; very stale devices may lack HardwareUuid data
- MDE has built-in deduplication (on by default) — this script catches what it misses

## Author

Oktay Sari (Microsoft MVP - Security & Intune)
