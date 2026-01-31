# Changelog: Homebrew Security Audit Script (Intune Edition)

**Author:** Oktay Sari

---

## v3.0.2

### Changed
- Max logfile size set to 500KB, keeping 3 logfiles for backup (~16 days of history)

### Removed
- Changelog has been removed from script to a dedicated file

---

## v3.0.1

### Fixed
- **TAPS_OFFICIAL double-zero bug causing invalid JSON**
  - `grep -c` outputs "0" on no match but exits with code 1
  - Previous: `|| echo 0` appended second "0" → "0\n0" in variable
  - JSON had `"taps_official": 0\n0`, breaking state.json parsing
  - Now: fallback assignment only triggers on actual pipeline failure

---

## v3.0.0

### Refactored
- **Complete code reorganization for maintainability**
  - Functions logically grouped with clear section headers
  - Reduced line count from 1203 to 947 (21% reduction)

### Added
- **DEBUG_MODE toggle** (default: false)
  - Set to true for verbose stderr output during troubleshooting
  - Production runs stay quiet
- **Modular user context setup** via `setup_user_context()`
  - Consolidates scattered global user detection code
  - Cleaner HOME resolution via `resolve_user_home()`
- **Dynamic RC file path building** via `build_rc_files()`
  - RC_FILES array built after HOME is determined
  - No more hardcoded paths with potential wrong HOME
- **`detect_homebrew()` function** with proper return codes
  - Returns 1 if not found (no early exit bypassing wrapper)
  - Sets BREW_PREFIX and BREW_BIN cleanly
- **State file includes additional fields**
  - `installed` field (Yes/No/Error)
  - `console_user` and `actual_user` for troubleshooting

### Removed
- **Non-security checks** for cleaner security focus:
  - `check_cleanup_needed` (hygiene, not security)
  - `check_auto_update` (hygiene, not security)
  - `check_auto_update_disabled` (hygiene, not security)
  - `check_analytics` (privacy, not security)
  - `check_doctor` (diagnostics, not security)
- Unconditional stderr diagnostics at script start (now controlled by DEBUG_MODE)
- `trap ERR` (unreliable without `set -e`, DEBUG logging preferred)

### Fixed
- **Stdout now 100% clean key=value only**
  - All diagnostics to stderr or log file
  - Intune parsing guaranteed clean
- Homebrew not-installed case handled via function return (no longer exits early, wrapper handles output)

### Style
- Bash 3 compatible (no associative arrays)

---

## v2.9.5

### Fixed
- **Removed accidental `set -e` from error wrapper**
  - v2.9.4 wrapper did `set +e` then `set -e` after main
  - This contradicted design goal of never using errexit
  - Now wrapper stays in +e mode until exit 0
- **`exec_git_origin()` pre-computes quoted path** before `su -c`
  - Avoids nested command substitution inside `su -c` string
  - Cleaner and more predictable shell evaluation
- **`trap ERR` documented as "best effort only"**
  - Without `set -e`, trap ERR is inconsistent (won't fire in conditionals)
  - Kept for extra debug info but not relied upon
  - Primary diagnostics are DEBUG logging and log file
- **Log rotation `old_count` now strips whitespace** from `wc -l`
  - `wc -l` can return leading spaces on some systems
  - Added `tr -d ' '` for consistent arithmetic evaluation
- **Error wrapper uses local variable** for sanitized summary
  - Avoids nested quotes in echo statement
  - Cleaner and more maintainable

---

## v2.9.4

### Critical Fixes
- **`main()` now returns instead of exits**
  - Previous: `exit 0` in main() bypassed the error wrapper entirely
  - Now: `return 0` allows wrapper to handle unexpected failures
  - Error wrapper actually works now for catastrophic failures
- **Wrapper runs main under `set +e`**
  - Guarantees key=value output even if something escapes `|| true`
  - Captures return code and handles failure gracefully
  - Belt-and-suspenders for Intune stdout hygiene
- **INCOMPLETE no longer masks CRITICAL/HIGH findings**
  - Previous: filesystem CRITICAL findings hidden by INCOMPLETE override
  - Now: only overrides SECURE/LOW_RISK/MEDIUM_RISK when checks skipped
  - World-writable brew binary still shows CRITICAL even at loginwindow

### Fixed
- **`sanitize_attr()` now normalizes whitespace and trims**
  - Collapses multiple spaces to single space
  - Removes leading/trailing whitespace
  - Prevents ugly dashboard displays and exact-match filter issues
- **Repo delimiter changed from `:` to `|`** in `check_brew_git_remotes`
  - Colons can appear in paths (rare but possible)
  - Pipe character will never appear in filesystem paths
- **`exec_git_origin()` uses `cd` instead of `-C`** for su compatibility
  - `-C` flag quoting through `su -c` was fragile
  - `cd` + git is more portable across shell implementations
- **Empty taps now logs MEDIUM** (was INFO)
  - "No taps returned" is anomalous and should appear in summary
  - Now bubbles up to HomeBrew_Issues_Summary
- **Log rotation uses `-print0` and while read loop**
  - Handles paths with spaces correctly
  - More robust xargs handling
- **JSON status field now "partial"** when BREW_USER_OK=false
  - Clearer for dashboard queries
  - "completed" only when all checks actually ran
- **Error wrapper summary also sanitized**
  - Consistent hygiene even in failure path

### Removed
- Unused `expected_owner` variable construction (was built but only used in log message, simplified ownership check logic)

---

## v2.9.3

### Added
- `sanitize_attr()` function for Intune parsing safety
- `HomeBrew_Git_Remote_Unknown` attribute

### Fixed
- Expanded git remote pattern for ssh:// colon form

### Changed
- Empty taps now sets `TAP_RISK="Medium"`

---

## Summary

**Total bugs fixed across all versions:** 41+
