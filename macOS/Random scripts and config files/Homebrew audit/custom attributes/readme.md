# Homebrew Security Custom Attributes for Intune

8 custom attribute scripts that read from the Homebrew Security Audit state file.

## Blog

For the full story behind this script and more macOS security content for Intune, check out [allthingscloud.blog](https://allthingscloud.blog/auditing-homebrew-security-intune-mac-fleet).

## Prerequisites

Deploy `homebrew_security_check_intune_v3_0_2.sh` first. These scripts read from the state file it generates.

## Installation

1. Save each script as a `.sh` file
2. In Intune: Devices → macOS → Custom attributes → Add
3. Upload the script
4. Set the correct **Data Type** (see table below)
5. Assign to your device groups

## Scripts and Data Types

| Script | Data Type | Description |
|--------|-----------|-------------|
| `HomeBrew_Installed.sh` | String | Yes / No / Unknown / Error |
| `HomeBrew_Security_Score.sh` | String | SECURE / CRITICAL / HIGH_RISK / MEDIUM_RISK / LOW_RISK / INCOMPLETE / N/A |
| `HomeBrew_Critical_Issues.sh` | Integer | Count of critical findings |
| `HomeBrew_World_Writable_Found.sh` | Integer | Count of world-writable files (bad!) |
| `HomeBrew_Git_Remote_Risk.sh` | Integer | Count of suspicious git remotes |
| `HomeBrew_TapRisk.sh` | String | Low / Medium / High |
| `HomeBrew_Last_Scan.sh` | String | Timestamp of last scan |
| `HomeBrew_Issues_Summary.sh` | String | Human-readable summary |

## Key Filters for Dashboards

| Alert | Filter |
|-------|--------|
| Critical findings | `HomeBrew_Security_Score` equals `CRITICAL` |
| Supply chain risk | `HomeBrew_Git_Remote_Risk` greater than `0` |
| World-writable binaries | `HomeBrew_World_Writable_Found` greater than `0` |
| Stale scan | `HomeBrew_Last_Scan` older than 7 days |

## State File Location

All scripts read from:
```
/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json
```

If the file is missing or invalid, scripts return safe defaults.
