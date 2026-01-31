# Homebrew Security Check Script v3.0.2 - Testing & Deployment Guide

## Blog

For the full story behind this script and more macOS security content for Intune, check out [allthingscloud.blog](https://allthingscloud.blog/auditing-homebrew-security-intune-mac-fleet).

## Quick Reference

| Item | Value |
|------|-------|
| Script Version | 3.0.2 |
| Run As | System (root) |
| Frequency | Daily recommended |
| Output | 24 key=value attributes (stdout) + state.json for custom attributes |
| Log Location | `/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/scan.log` |
| State File | `/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json` |
| Max Log Size | 500KB (rotates with 3 backups, ~16 days history) |
| Recommended Attributes | 8 (minimal core) |

---

## What's New in v3.0.2

| Change | Details |
|--------|---------|
| **Log rotation** | Max 500KB per log file, keeps 3 backup files (~16 days of scan history) |
| **Changelog location** | Moved to dedicated `Changelog - Homebrew Security Audit Script.txt` file |
| **Cleaner script** | No changelog comments cluttering the main script |

---

## Design Rules (Non-Negotiable)

- Intune shell script runs as **System**
- Script **never runs `brew` as root**
- Script writes **ONLY** `key=value` lines to **stdout**
- All diagnostics go to **stderr** and/or the log file
- Exit code is **always 0** (Intune "Success"); security status is derived from attributes and `state.json`
- If no GUI console user is logged in, brew-level checks are skipped; filesystem checks still run

---

## Pre-Deployment Testing

Run these tests on at least one Apple Silicon and one Intel Mac if possible.

### 1. Basic Execution Test (as root)

```bash
sudo /bin/bash homebrew_security_check_intune_v3_0_2.sh
```

**Expected:**
- stdout contains only key=value lines
- log file is updated
- state.json is written

### 2. Verify stdout is 100% Clean

This test flags any line that is not a valid key=value pair:

```bash
sudo /bin/bash homebrew_security_check_intune_v3_0_2.sh 2>/dev/null \
  | awk 'NF && $0 !~ /^[^=]+=.*/ {print "BAD:", $0}'
```

**Expected:** No output.

### 3. Test Without Console User (loginwindow scenario)

Run at loginwindow or after logging out the GUI user:

```bash
sudo /bin/bash homebrew_security_check_intune_v3_0_2.sh
```

**Expected:**
- `HomeBrew_User_Context=Unavailable`
- `HomeBrew_BrewChecks=Skipped_NoUser`
- `HomeBrew_Security_Score=INCOMPLETE` (unless filesystem issues produce CRITICAL/HIGH)

### 4. Test Homebrew Not Installed

On a Mac without Homebrew:

```bash
sudo /bin/bash homebrew_security_check_intune_v3_0_2.sh
```

**Expected:**
- `HomeBrew_Installed=No`
- `HomeBrew_Security_Score=N/A`
- state.json exists with `status=not_installed`

### 5. Validate state.json is Valid JSON

```bash
sudo python3 -m json.tool /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json >/dev/null \
  && echo "OK: JSON valid" || echo "FAIL: Invalid JSON"
```

**Expected:** `OK: JSON valid`

### 6. Confirm state.json Contains Required Keys

```bash
sudo python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
required = [
  "installed", "security_score", "status", "summary", "last_scan", "script_version",
  "critical_issues", "high_issues", "medium_issues", "low_issues", "total_issues",
  "critical_outdated", "world_writable_found",
  "taps_total", "taps_official", "taps_thirdparty", "taps_thirdparty_list", "tap_policy", "tap_risk",
  "git_remote_risk", "git_remote_unknown", "env_overrides", "casks_installed"
]
try:
  d=json.load(open(p))
  missing=[k for k in required if k not in d]
  print("Missing:", missing if missing else "None")
except Exception as e:
  print("FAIL:", e)
PY
```

**Expected:** `Missing: None`

### 7. Verify Log File Updates

```bash
sudo tail -50 /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/scan.log
```

**Expected:** Timestamped entries showing check progression.

### 8. Verify Log Rotation Settings

```bash
# Check current log file size
sudo ls -lh /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/scan.log

# Check for rotated backup files
sudo ls -la /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/*.old
```

**Expected:** Log files under 500KB, maximum 3 .old backup files.

---

### Edge Case Testing

| Scenario | How to Test | Expected Result |
|----------|-------------|-----------------|
| World-writable brew binary | `sudo chmod o+w /opt/homebrew/bin/brew` then run | `CRITICAL` score, `WORLD_WRITABLE_FOUND=1` |
| Third-party tap | `brew tap hashicorp/tap` then run | `TAP_RISK=Medium`, tap listed |
| Critical package outdated | Have outdated openssl/curl/git | `CRITICAL_OUTDATED >= 1` |
| No taps returned | Rare; simulate by breaking brew context | `TAP_RISK=Medium`, anomaly in log |
| Mobile account HOME | Test with AD/Entra mobile account | HOME resolves correctly |

**Restore permissions after testing:**

```bash
sudo chmod 755 /opt/homebrew/bin/brew 2>/dev/null || true
sudo chmod 755 /usr/local/bin/brew 2>/dev/null || true
```

---

## Intune Deployment

### A. Deploy the Main Shell Script

**Path:** Intune admin center → Devices → macOS → Shell scripts → Add

| Setting | Value |
|---------|-------|
| Name | `Homebrew Security Audit v3.0.2` |
| Script | Upload `homebrew_security_check_intune_v3_0_2.sh` |
| Run script as signed-in user | **No** |
| Hide script notifications | Yes |
| Script frequency | Daily |
| Max retries | 3 |

**Important:**
- The first execution must complete before custom attributes have meaningful values.
- Expect up to 24 hours delay depending on Intune check-in cadence.

---

### B. Custom Attributes Setup

**Path:** Devices → macOS → Custom attributes → Add

**File format:** Save each custom attribute script as a `.sh` file (e.g., `HomeBrew_Security_Score.sh`). Even though they call Python inline, Intune only accepts shell scripts. The data type you select in Intune depends on the information being collected: use **String** for text values and **Integer** for counts. See the data type tables in each section below.

#### Why Minimal Core?

All 24 data points are persisted in `state.json` on each device. Custom attributes are a "push to dashboard" mechanism. Creating all 24 means 24 scripts to maintain with diminishing returns.

**Recommended: 8 attributes that cover 90% of use cases.**

For deep investigation, SSH to the device and read `state.json` or the log file.

#### Parsing with Python (Recommended)

Regex parsing with `grep` is fragile. Use Python JSON parsing for reliability.

All scripts read from:
`/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json`

If the file is missing or invalid, scripts return a safe default.

---

### Minimal Core Attributes (8 Scripts)

#### Data Types for Minimal Core

| Attribute | Data Type | Values |
|-----------|-----------|--------|
| `HomeBrew_Installed` | String | Yes / No / Unknown / Error |
| `HomeBrew_Security_Score` | String | SECURE / LOW_RISK / MEDIUM_RISK / HIGH_RISK / CRITICAL / INCOMPLETE / N/A / ERROR |
| `HomeBrew_Critical_Issues` | Integer | Count (0, 1, 2...) |
| `HomeBrew_World_Writable_Found` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Git_Remote_Risk` | Integer | Count (0, 1, 2...) |
| `HomeBrew_TapRisk` | String | Low / Medium / High |
| `HomeBrew_Last_Scan` | String | Timestamp (e.g., 2025-01-30 14:30:00) |
| `HomeBrew_Issues_Summary` | String | Human-readable summary text |

#### 1. HomeBrew_Installed

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("installed","Unknown"))
except Exception:
  print("Unknown")
PY
```

#### 2. HomeBrew_Security_Score

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("security_score","Unknown"))
except Exception:
  print("Unknown")
PY
```

#### 3. HomeBrew_Critical_Issues

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("critical_issues",0))
except Exception:
  print(0)
PY
```

#### 4. HomeBrew_World_Writable_Found

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("world_writable_found",0))
except Exception:
  print(0)
PY
```

#### 5. HomeBrew_Git_Remote_Risk

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("git_remote_risk",0))
except Exception:
  print(0)
PY
```

#### 6. HomeBrew_TapRisk

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("tap_risk","Low"))
except Exception:
  print("Low")
PY
```

#### 7. HomeBrew_Last_Scan

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("last_scan","Never"))
except Exception:
  print("Never")
PY
```

#### 8. HomeBrew_Issues_Summary

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("summary","No data"))
except Exception:
  print("No data")
PY
```

---

### What the Minimal Core Gives You

| Attribute | What It Tells You |
|-----------|-------------------|
| `HomeBrew_Installed` | Basic inventory: is Homebrew present? |
| `HomeBrew_Security_Score` | Rolled-up verdict: SECURE, CRITICAL, etc. |
| `HomeBrew_Critical_Issues` | Count of critical findings |
| `HomeBrew_World_Writable_Found` | Scariest filesystem finding |
| `HomeBrew_Git_Remote_Risk` | Supply chain compromise indicator |
| `HomeBrew_TapRisk` | Third-party tap sprawl signal |
| `HomeBrew_Last_Scan` | Staleness detection |
| `HomeBrew_Issues_Summary` | Human-readable "why" without SSH |

---

## Dashboard Filters (Minimal Core)

### High Priority Alerts

| Filter | Condition |
|--------|-----------|
| Critical findings | `HomeBrew_Security_Score` equals `CRITICAL` |
| World-writable binaries | `HomeBrew_World_Writable_Found` greater than `0` |
| Supply chain risk | `HomeBrew_Git_Remote_Risk` greater than `0` |

### Compliance Overview

| Filter | Condition |
|--------|-----------|
| Fully compliant | `HomeBrew_Security_Score` equals `SECURE` |
| Partial scan only | `HomeBrew_Security_Score` equals `INCOMPLETE` |
| Homebrew not installed | `HomeBrew_Installed` equals `No` |
| Stale scan (>7 days) | `HomeBrew_Last_Scan` older than 7 days |

---

## Troubleshooting

### No Data in Custom Attributes

Most common causes:
1. Main script has not run yet (wait for next check-in)
2. state.json is missing or invalid
3. Path mismatch between script and attributes

**Checks:**

```bash
sudo ls -la /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/
sudo python3 -m json.tool /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json
sudo tail -50 /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/scan.log
```

### INCOMPLETE When User is Logged In

Common reasons:
- FileVault pre-boot or loginwindow context
- Fast User Switching
- Remote sessions (SSH) do not create a console user

**Validate:**

```bash
/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | head -50
```

### Log Files Growing Too Large

The v3.0.2 script automatically rotates logs at 500KB and keeps 3 backups. If you're still seeing issues:

```bash
# Check log sizes
sudo du -sh /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/*

# Manual cleanup if needed
sudo rm /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/scan.log.*.old
```

---

## Security Score Reference

| Score | Meaning | Action |
|-------|---------|--------|
| `SECURE` | All checks passed | None |
| `LOW_RISK` | Minor issues only | Review when convenient |
| `MEDIUM_RISK` | Third-party taps or override signals | Review taps and RC overrides |
| `HIGH_RISK` | Ownership issues or tap sprawl | Investigate promptly |
| `CRITICAL` | World-writable or supply chain compromise | Immediate response |
| `INCOMPLETE` | Brew checks skipped | Re-run when user logged in |
| `N/A` | Homebrew not installed | None |
| `ERROR` | Script failed | Check logs and state |

---

## Rollout Strategy

### Phase 1: Pilot (Week 1)
- 5-10 devices
- Confirm state.json creation and attribute population
- Validate no false CRITICAL findings

### Phase 2: IT Team (Week 2)
- Expand to IT department Macs
- Build dashboards and filters
- Tune thresholds if needed

### Phase 3: Production (Week 3+)
- Gradual rollout by department
- Monitor support tickets
- Confirm attribute update cadence meets expectations

---

## Extended Attributes (Optional)

For teams needing granular reporting or automated remediation workflows, deploy additional attributes beyond the minimal core.

#### Data Types for Extended Attributes

| Attribute | Data Type | Values |
|-----------|-----------|--------|
| `HomeBrew_User_Context` | String | Available / Unavailable |
| `HomeBrew_BrewChecks` | String | Ran / Skipped_NoUser |
| `HomeBrew_High_Issues` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Medium_Issues` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Low_Issues` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Total_Issues` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Taps_Total` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Taps_Official` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Taps_ThirdParty_Count` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Taps_ThirdParty_List` | String | Comma-separated tap names |
| `HomeBrew_TapPolicy` | String | Compliant / NeedsReview / Unknown |
| `HomeBrew_Git_Remote_Unknown` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Env_Overrides` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Casks_Installed` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Critical_Packages_Outdated` | Integer | Count (0, 1, 2...) |
| `HomeBrew_Script_Version` | String | Version number (e.g., 3.0.2) |

### User Context (2)

#### HomeBrew_User_Context

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  status=d.get("status","")
  print("Available" if status=="completed" else "Unavailable")
except Exception:
  print("Unavailable")
PY
```

#### HomeBrew_BrewChecks

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  status=d.get("status","")
  print("Ran" if status=="completed" else "Skipped_NoUser")
except Exception:
  print("Skipped_NoUser")
PY
```

### Issue Counts (4)

#### HomeBrew_High_Issues

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("high_issues",0))
except Exception: print(0)
PY
```

#### HomeBrew_Medium_Issues

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("medium_issues",0))
except Exception: print(0)
PY
```

#### HomeBrew_Low_Issues

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("low_issues",0))
except Exception: print(0)
PY
```

#### HomeBrew_Total_Issues

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("total_issues",0))
except Exception: print(0)
PY
```

### Tap Details (5)

#### HomeBrew_Taps_Total

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("taps_total",0))
except Exception: print(0)
PY
```

#### HomeBrew_Taps_Official

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("taps_official",0))
except Exception: print(0)
PY
```

#### HomeBrew_Taps_ThirdParty_Count

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("taps_thirdparty",0))
except Exception: print(0)
PY
```

#### HomeBrew_Taps_ThirdParty_List

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("taps_thirdparty_list",""))
except Exception: print("")
PY
```

#### HomeBrew_TapPolicy

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("tap_policy","Unknown"))
except Exception: print("Unknown")
PY
```

### Supply Chain (3)

#### HomeBrew_Git_Remote_Unknown

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("git_remote_unknown",0))
except Exception: print(0)
PY
```

#### HomeBrew_Env_Overrides

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("env_overrides",0))
except Exception: print(0)
PY
```

#### HomeBrew_Casks_Installed

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("casks_installed",0))
except Exception: print(0)
PY
```

### Metadata (2)

#### HomeBrew_Critical_Packages_Outdated

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("critical_outdated",0))
except Exception: print(0)
PY
```

#### HomeBrew_Script_Version

```bash
#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try: print(json.load(open(p)).get("script_version","Unknown"))
except Exception: print("Unknown")
PY
```

---

## Summary: Attribute Count by Approach

| Approach | Attributes | Use Case |
|----------|------------|----------|
| **Minimal Core** | 8 | Most teams; 90% of value, minimal overhead |
| **Extended** | 24 | Granular compliance reporting, automated remediation |

---

## Resources

- [Intune Shell Scripts Documentation](https://learn.microsoft.com/en-us/mem/intune/apps/macos-shell-scripts)
- [Intune Custom Attributes](https://learn.microsoft.com/en-us/mem/intune/apps/macos-custom-attributes)
- [Homebrew Security Best Practices](https://docs.brew.sh/Security)
- `Changelog - Homebrew Security Audit Script.txt` (full version history)
