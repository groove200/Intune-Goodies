#!/bin/bash

################################################################################
# Homebrew Security Audit Script - Intune Edition
# Version: 3.0.2
# Author: Oktay Sari
#
# Purpose:
# - Run under Intune as SYSTEM
# - NEVER run `brew` as root
# - Produce ONLY key=value lines on stdout (safe for Intune custom attributes)
# - Write a JSON state file for local troubleshooting/reporting
#
# Behavior:
# - If no GUI console user is logged in, brew-level checks are skipped
# - Filesystem-level checks still run
# - Exit code is always 0 (Intune success), status is in attributes/state.json
#
# DEPLOYMENT INSTRUCTIONS:
# ========================
# 1. Upload to Intune as Shell Script
# 2. Run as: System (NOT signed-in user)
# 3. Schedule: Daily
# 4. Create Custom Attributes (24 separate scripts)
#
# OUTPUT:
# - Emits 24 key=value attributes on stdout (single script)
#
# Core (9):
#   - HomeBrew_Installed
#   - HomeBrew_Security_Score
#   - HomeBrew_Critical_Issues
#   - HomeBrew_High_Issues
#   - HomeBrew_Medium_Issues
#   - HomeBrew_Low_Issues
#   - HomeBrew_Total_Issues
#   - HomeBrew_Critical_Packages_Outdated
#   - HomeBrew_World_Writable_Found
#
# User Context (2):
#   - HomeBrew_User_Context
#   - HomeBrew_BrewChecks
#
# Tap Policy (6):
#   - HomeBrew_Taps_Total
#   - HomeBrew_Taps_Official
#   - HomeBrew_Taps_ThirdParty_Count
#   - HomeBrew_Taps_ThirdParty_List
#   - HomeBrew_TapPolicy (Compliant|NeedsReview|Unknown)
#   - HomeBrew_TapRisk (Low|Medium|High)
#
# Supply Chain (4):
#   - HomeBrew_Git_Remote_Risk (count of non-Homebrew GitHub remotes)
#   - HomeBrew_Git_Remote_Unknown (count of repos where origin unreadable)
#   - HomeBrew_Env_Overrides (RC file overrides count)
#   - HomeBrew_Casks_Installed
#
# Metadata (3):
#   - HomeBrew_Issues_Summary
#   - HomeBrew_Last_Scan
#   - HomeBrew_Script_Version
#
# ERROR HANDLING STRATEGY:
# ========================
# We use set -u -o pipefail but NOT set -e.
# - set -e is too aggressive for "always output key=value" goal
# - One missed || true and the script dies before outputting anything
# - Instead, we check return codes explicitly where needed
# - The wrapper guarantees valid stdout even on unexpected failures
#
# All risky operations use || true or || echo "" for safety.
#
################################################################################

set -uo pipefail

########################################
# Configuration
########################################

readonly VERSION="3.0.2"
readonly SCRIPT_NAME="homebrew_security_check_intune"
readonly LOG_DIR="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity"
readonly LOG_FILE="${LOG_DIR}/scan.log"
readonly STATE_FILE="${LOG_DIR}/state.json"
readonly MAX_LOG_SIZE=512000  # 500KB is about 4 days of data. After that rotate the logfile and make backups

# Toggle extra diagnostics to stderr (never stdout)
# Set to true only when troubleshooting.
DEBUG_MODE=false

# Risk thresholds
readonly TAP_HIGH_RISK_THRESHOLD=5
readonly TAP_MEDIUM_RISK_THRESHOLD=1

# Security-critical packages to flag if outdated
CRITICAL_PACKAGES=(
  "openssl"
  "openssl@3"
  "openssl@1.1"
  "curl"
  "git"
  "gnupg"
  "ca-certificates"
)

# RC file basenames (expanded after HOME is set)
RC_FILE_BASENAMES=(
  ".zshrc"
  ".zshenv"
  ".zprofile"
  ".bashrc"
  ".bash_profile"
  ".profile"
)

# Required commands (brew is checked by absolute path detection)
REQUIRED_COMMANDS=(
  "stat"
  "scutil"
  "dscl"
  "id"
  "awk"
  "sed"
  "tr"
  "grep"
  "wc"
  "find"
  "xargs"
  "tail"
  "date"
)

########################################
# Global runtime state (Bash 3 compatible)
########################################

# User context
CONSOLE_USER=""
ACTUAL_USER="root"
BREW_USER_OK=false
BREW_PREFIX=""
BREW_BIN=""

# Expanded RC files list
RC_FILES=()

# Issue tracking
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0
TOTAL_ISSUES=0

CRITICAL_OUTDATED=0
WORLD_WRITABLE_FOUND=0

CRITICAL_DETAILS=""
HIGH_DETAILS=""
MEDIUM_DETAILS=""

# Tap policy
TAPS_TOTAL=0
TAPS_OFFICIAL=0
TAPS_THIRDPARTY=0
TAPS_THIRDPARTY_LIST=""
TAP_POLICY="Unknown"
TAP_RISK="Low"

# Supply chain
GIT_REMOTE_RISK=0
GIT_REMOTE_UNKNOWN=0
ENV_OVERRIDES=0
CASKS_INSTALLED=0

########################################
# Debug helper (stderr only)
########################################

dbg() {
  if [[ "$DEBUG_MODE" == true ]]; then
    echo "[DEBUG] $*" >&2
  fi
}

########################################
# Logging (file only, stderr only for ERROR/CRITICAL unless debug)
########################################

setup_logging() {
  # Create log directory
  if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR" 2>/dev/null || return 1
    chmod 755 "$LOG_DIR" 2>/dev/null || true
  fi

  # Ensure log file is writable
  touch "$LOG_FILE" 2>/dev/null || return 1

  # Rotate if needed
  local size
  size=$(stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
  if (( size > MAX_LOG_SIZE )); then
    mv "$LOG_FILE" "$LOG_FILE.$(date +%Y%m%d_%H%M%S).old" 2>/dev/null || true

    # Keep last 3 old logs
    local old_count
    old_count=$(find "$LOG_DIR" -name "*.old" -type f 2>/dev/null | wc -l | tr -d ' ')
    if (( old_count > 3 )); then
      find "$LOG_DIR" -name "*.old" -type f -print0 2>/dev/null \
        | xargs -0 ls -1t 2>/dev/null \
        | tail -n +4 \
        | while IFS= read -r f; do rm -f "$f" 2>/dev/null || true; done
    fi
  fi

  return 0
}

log_file() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$ts] [$level] $msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_stderr_if_needed() {
  local level="$1"; shift
  local msg="$*"

  case "$level" in
    "CRITICAL"|"ERROR")
      echo "[$level] $msg" >&2
      ;;
    *)
      dbg "$level: $msg"
      ;;
  esac
}

log_info()    { log_file "INFO" "$*";    log_stderr_if_needed "INFO" "$*"; }
log_success() { log_file "SUCCESS" "$*"; log_stderr_if_needed "SUCCESS" "$*"; }
log_error()   { log_file "ERROR" "$*";   log_stderr_if_needed "ERROR" "$*"; }

log_critical() {
  local msg="$*"
  log_file "CRITICAL" "$msg"
  log_stderr_if_needed "CRITICAL" "$msg"

  CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
  TOTAL_ISSUES=$((TOTAL_ISSUES + 1))

  if [[ -n "$CRITICAL_DETAILS" ]]; then
    CRITICAL_DETAILS="${CRITICAL_DETAILS}; ${msg}"
  else
    CRITICAL_DETAILS="$msg"
  fi
}

log_high() {
  local msg="$*"
  log_file "HIGH" "$msg"
  log_stderr_if_needed "HIGH" "$msg"

  HIGH_ISSUES=$((HIGH_ISSUES + 1))
  TOTAL_ISSUES=$((TOTAL_ISSUES + 1))

  if [[ -n "$HIGH_DETAILS" ]]; then
    HIGH_DETAILS="${HIGH_DETAILS}; ${msg}"
  else
    HIGH_DETAILS="$msg"
  fi
}

log_medium() {
  local msg="$*"
  log_file "MEDIUM" "$msg"
  log_stderr_if_needed "MEDIUM" "$msg"

  MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  TOTAL_ISSUES=$((TOTAL_ISSUES + 1))

  if [[ -z "$MEDIUM_DETAILS" ]]; then
    MEDIUM_DETAILS="$msg"
  fi
}

log_low() {
  local msg="$*"
  log_file "LOW" "$msg"
  log_stderr_if_needed "LOW" "$msg"

  LOW_ISSUES=$((LOW_ISSUES + 1))
  TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
}

########################################
# Sanitization and JSON helpers
########################################

sanitize_attr() {
  # Intune attribute safety:
  # - remove newlines/tabs/CR
  # - replace '=' to prevent parsing ambiguity
  # - normalize whitespace
  printf '%s' "$1" \
    | tr '\r\n\t' '   ' \
    | sed 's/=/ /g; s/[[:space:]]\{1,\}/ /g; s/^ *//; s/ *$//'
}

json_escape() {
  # Preferred: python3 JSON escaping
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])' 2>/dev/null || true
    return 0
  fi

  # Fallback: minimal escaping
  tr -d '\r\n\t' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

########################################
# Dependency checks
########################################

check_dependencies() {
  local missing=""
  local cmd

  for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing="${missing} ${cmd}"
    fi
  done

  if [[ -n "$missing" ]]; then
    log_error "Missing required commands:${missing}"
    return 1
  fi

  return 0
}

########################################
# User context detection
########################################

detect_console_user() {
  /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" \
    | awk '/Name :/ && $3 != "loginwindow" && $3 != "_mbsetupuser" {print $3; exit}'
}

resolve_user_home() {
  local user="$1"
  local home_path=""

  if [[ "$user" == "root" ]]; then
    echo "/var/root"
    return 0
  fi

  home_path=$(dscl . -read /Users/"$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
  if [[ -n "$home_path" ]]; then
    echo "$home_path"
  else
    echo "/Users/$user"
  fi
}

build_rc_files() {
  RC_FILES=()
  local base
  for base in "${RC_FILE_BASENAMES[@]}"; do
    RC_FILES+=("${HOME}/${base}")
  done
}

setup_user_context() {
  local cu=""

  # Intune runs as SYSTEM; SUDO_USER is typically empty. Still support it.
  if [[ -n "${SUDO_USER:-}" ]]; then
    cu="$SUDO_USER"
  else
    cu="$(detect_console_user 2>/dev/null || true)"
  fi

  # Validate console user exists
  if [[ -n "$cu" ]] && [[ "$cu" != "root" ]]; then
    if ! id "$cu" >/dev/null 2>&1; then
      log_error "Console user '$cu' not found on system; treating as none"
      cu=""
    fi
  fi

  CONSOLE_USER="$cu"
  if [[ -n "$CONSOLE_USER" ]]; then
    ACTUAL_USER="$CONSOLE_USER"
    BREW_USER_OK=true
  else
    ACTUAL_USER="root"
    BREW_USER_OK=false
  fi

  # IMPORTANT: Always set HOME based on ACTUAL_USER, even if HOME was already set
  export HOME
  HOME="$(resolve_user_home "$ACTUAL_USER")"

  build_rc_files

  log_info "Console user: ${CONSOLE_USER:-none}"
  log_info "Actual user: $ACTUAL_USER"
  log_info "Brew user OK: $BREW_USER_OK"
  log_info "HOME: $HOME"
}

########################################
# Homebrew detection (no readonly inside branches)
########################################

detect_homebrew() {
  local prefix=""
  local bin=""

  if [[ -x "/opt/homebrew/bin/brew" ]]; then
    prefix="/opt/homebrew"
    bin="/opt/homebrew/bin/brew"
  elif [[ -x "/usr/local/bin/brew" ]]; then
    prefix="/usr/local"
    bin="/usr/local/bin/brew"
  else
    return 1
  fi

  BREW_PREFIX="$prefix"
  BREW_BIN="$bin"

  readonly BREW_PREFIX
  readonly BREW_BIN

  log_info "Homebrew found: $BREW_BIN"
  return 0
}

########################################
# Safe brew and git execution
########################################

exec_brew() {
  # Never run brew without a safe GUI user context
  if [[ "$BREW_USER_OK" != true ]]; then
    log_error "brew execution disabled (no console user)"
    return 1
  fi

  # Build a safely quoted command
  local cmd
  cmd="$(printf '%q ' "$BREW_BIN" "$@")"

  # Intune runs as root
  if [[ "$(id -u)" -eq 0 ]]; then
    if [[ -z "${ACTUAL_USER:-}" ]] || [[ "$ACTUAL_USER" == "root" ]]; then
      log_error "Refusing to run brew as root"
      return 1
    fi
    su -l "$ACTUAL_USER" -c "$cmd"
    return $?
  fi

  # Non-root direct execution
  "$BREW_BIN" "$@"
}

exec_git_origin() {
  local repo_path="$1"
  local qpath
  qpath=$(printf '%q' "$repo_path")

  if [[ "$(id -u)" -eq 0 ]] && [[ "$BREW_USER_OK" == true ]] && [[ "$ACTUAL_USER" != "root" ]]; then
    su -l "$ACTUAL_USER" -c "cd $qpath && git remote get-url origin" 2>/dev/null || true
  else
    git -C "$repo_path" remote get-url origin 2>/dev/null || true
  fi
}

########################################
# Security checks (step-by-step)
########################################

check_brew_binary_security() {
  log_info "Check: brew binary security"

  if [[ ! -f "$BREW_BIN" ]]; then
    log_critical "Homebrew binary missing: $BREW_BIN"
    return 0
  fi

  local owner perms expected_user
  owner=$(stat -f "%Su" "$BREW_BIN" 2>/dev/null || echo "unknown")
  perms=$(stat -f "%Lp" "$BREW_BIN" 2>/dev/null || echo "0")
  expected_user="${CONSOLE_USER:-root}"

  if [[ "$owner" != "$expected_user" ]] && [[ "$owner" != "root" ]] && [[ "$owner" != "_homebrew" ]]; then
    if [[ "$BREW_USER_OK" == true ]]; then
      log_critical "Brew binary owner: $owner (expected: $expected_user/root/_homebrew)"
    else
      log_critical "Brew binary owner: $owner (expected: root/_homebrew)"
    fi
  else
    log_success "Brew binary owner OK: $owner"
  fi

  # perms is decimal string, but stat -f%Lp returns like 755 (octal-looking)
  if (( (8#$perms & 0002) != 0 )); then
    log_critical "Brew binary world-writable (perms: $perms)"
    WORLD_WRITABLE_FOUND=$((WORLD_WRITABLE_FOUND + 1))
  elif (( (8#$perms & 0020) != 0 )); then
    log_high "Brew binary group-writable (perms: $perms)"
  else
    log_success "Brew binary perms OK: $perms"
  fi

  return 0
}

check_brew_directories_security() {
  log_info "Check: brew directory security"

  local dirs=(
    "$BREW_PREFIX"
    "$BREW_PREFIX/bin"
    "$BREW_PREFIX/Cellar"
    "$BREW_PREFIX/Caskroom"
  )

  local dir owner perms expected_user
  expected_user="${CONSOLE_USER:-root}"

  for dir in "${dirs[@]}"; do
    [[ -d "$dir" ]] || continue

    owner=$(stat -f "%Su" "$dir" 2>/dev/null || echo "unknown")
    perms=$(stat -f "%Lp" "$dir" 2>/dev/null || echo "0")

    if [[ "$owner" != "$expected_user" ]] && [[ "$owner" != "root" ]] && [[ "$owner" != "_homebrew" ]]; then
      log_high "Directory owner suspicious: $dir owner=$owner"
    fi

    if (( (8#$perms & 0002) != 0 )); then
      log_critical "Directory world-writable: $dir perms=$perms"
      WORLD_WRITABLE_FOUND=$((WORLD_WRITABLE_FOUND + 1))
    fi
  done

  return 0
}

check_tap_policy() {
  log_info "Check: tap policy"

  if [[ "$BREW_USER_OK" != true ]]; then
    log_info "Skipping taps: no console user"
    TAP_POLICY="Unknown"
    TAP_RISK="Low"
    return 0
  fi

  local taps third_party
  taps=$(exec_brew tap 2>/dev/null || echo "")

  if [[ -z "$taps" ]]; then
    log_medium "No taps returned (unexpected, normally homebrew/core exists)"
    TAPS_TOTAL=0
    TAPS_OFFICIAL=0
    TAPS_THIRDPARTY=0
    TAPS_THIRDPARTY_LIST=""
    TAP_POLICY="Unknown"
    TAP_RISK="Medium"
    return 0
  fi

  TAPS_TOTAL=$(printf '%s\n' "$taps" | sed '/^$/d' | wc -l | tr -d ' ')
  # v3.0.1 FIX: grep -c outputs "0" on no match but exits 1, causing || echo 0 to
  # append another "0" → "0\n0". Use separate fallback assignment instead.
  TAPS_OFFICIAL=$(printf '%s\n' "$taps" | sed '/^$/d' | grep -c '^homebrew/' 2>/dev/null) || TAPS_OFFICIAL=0

  third_party=$(printf '%s\n' "$taps" | sed '/^$/d' | grep -v '^homebrew/' 2>/dev/null || true)
  if [[ -n "$third_party" ]]; then
    TAPS_THIRDPARTY=$(printf '%s\n' "$third_party" | sed '/^$/d' | wc -l | tr -d ' ')
    TAPS_THIRDPARTY_LIST=$(printf '%s\n' "$third_party" | sed '/^$/d' | tr '\n' ',' | sed 's/,$//' | cut -c1-150)
  else
    TAPS_THIRDPARTY=0
    TAPS_THIRDPARTY_LIST=""
  fi

  if (( TAPS_THIRDPARTY == 0 )); then
    TAP_POLICY="Compliant"
    TAP_RISK="Low"
    log_success "All taps official (total: $TAPS_TOTAL)"
  elif (( TAPS_THIRDPARTY >= TAP_HIGH_RISK_THRESHOLD )); then
    TAP_POLICY="NeedsReview"
    TAP_RISK="High"
    log_high "Tap sprawl: $TAPS_THIRDPARTY third-party taps ($TAPS_THIRDPARTY_LIST)"
  elif (( TAPS_THIRDPARTY >= TAP_MEDIUM_RISK_THRESHOLD )); then
    TAP_POLICY="NeedsReview"
    TAP_RISK="Medium"
    log_medium "Third-party taps present: $TAPS_THIRDPARTY ($TAPS_THIRDPARTY_LIST)"
  fi

  return 0
}

check_git_remotes() {
  log_info "Check: git remotes"

  if [[ "$BREW_USER_OK" != true ]]; then
    log_info "Skipping git remotes: no console user"
    GIT_REMOTE_RISK=0
    GIT_REMOTE_UNKNOWN=0
    return 0
  fi

  local brew_repo core_repo cask_repo
  brew_repo=$(exec_brew --repository 2>/dev/null || true)
  core_repo=$(exec_brew --repo homebrew/core 2>/dev/null || true)
  cask_repo=$(exec_brew --repo homebrew/cask 2>/dev/null || true)

  local bad=0
  local unknown=0

  local repos=(
    "brew|$brew_repo"
    "core|$core_repo"
    "cask|$cask_repo"
  )

  local item name path origin
  for item in "${repos[@]}"; do
    name="${item%%|*}"
    path="${item#*|}"

    [[ -n "$path" ]] || continue
    [[ -d "$path/.git" ]] || continue

    origin="$(exec_git_origin "$path")"

    if [[ -z "$origin" ]]; then
      log_medium "Origin unreadable: $name repo ($path)"
      unknown=$((unknown + 1))
      continue
    fi

    if ! printf '%s' "$origin" | grep -qiE '^(https://github\.com/Homebrew/|git@github\.com:Homebrew/|ssh://git@github\.com[/:]Homebrew/)'; then
      log_high "Non-Homebrew origin: $name -> $origin"
      bad=$((bad + 1))
    else
      log_success "Origin OK: $name -> Homebrew"
    fi
  done

  GIT_REMOTE_RISK=$bad
  GIT_REMOTE_UNKNOWN=$unknown

  return 0
}

check_env_overrides() {
  log_info "Check: RC env overrides (git remote overrides)"

  if [[ "$BREW_USER_OK" != true ]]; then
    log_info "Skipping RC checks: no console user"
    ENV_OVERRIDES=0
    return 0
  fi

  local risky_vars=(
    "HOMEBREW_BREW_GIT_REMOTE"
    "HOMEBREW_CORE_GIT_REMOTE"
    "HOMEBREW_CASK_GIT_REMOTE"
  )

  local rc var
  local found=0

  for rc in "${RC_FILES[@]}"; do
    [[ -f "$rc" ]] || continue
    for var in "${risky_vars[@]}"; do
      if grep -E "^[[:space:]]*(export[[:space:]]+)?${var}=" "$rc" 2>/dev/null | grep -vq '^[[:space:]]*#'; then
        log_medium "Override found: $var in $rc"
        found=$((found + 1))
      fi
    done
  done

  ENV_OVERRIDES=$found
  if (( found == 0 )); then
    log_success "No RC overrides found"
  fi

  return 0
}

check_casks_installed() {
  log_info "Check: cask inventory"

  if [[ "$BREW_USER_OK" != true ]]; then
    log_info "Skipping casks: no console user"
    CASKS_INSTALLED=0
    return 0
  fi

  local casks
  casks=$(exec_brew list --cask 2>/dev/null || echo "")
  if [[ -z "$casks" ]]; then
    CASKS_INSTALLED=0
    log_success "No casks installed"
  else
    CASKS_INSTALLED=$(printf '%s\n' "$casks" | sed '/^$/d' | wc -l | tr -d ' ')
    log_info "Casks installed: $CASKS_INSTALLED"
  fi

  return 0
}

check_outdated_packages() {
  log_info "Check: outdated packages (critical list)"

  if [[ "$BREW_USER_OK" != true ]]; then
    log_info "Skipping outdated: no console user"
    return 0
  fi

  local outdated
  outdated=$(exec_brew outdated --formula 2>/dev/null || echo "")
  if [[ -z "$outdated" ]]; then
    log_success "No outdated formulae"
    return 0
  fi

  local pkg
  local found_any=0
  local critical_found=()

  for pkg in "${CRITICAL_PACKAGES[@]}"; do
    if printf '%s\n' "$outdated" | awk '{print $1}' | grep -Fxq "$pkg" 2>/dev/null; then
      critical_found+=("$pkg")
      CRITICAL_OUTDATED=$((CRITICAL_OUTDATED + 1))
      found_any=1
    fi
  done

  if (( found_any == 1 )); then
    log_critical "Critical packages outdated: ${critical_found[*]}"
  fi

  return 0
}

########################################
# Output generation
########################################

calculate_security_score() {
  local score="UNKNOWN"

  if (( CRITICAL_ISSUES > 0 )); then
    score="CRITICAL"
  elif (( HIGH_ISSUES > 0 )); then
    score="HIGH_RISK"
  elif (( MEDIUM_ISSUES > 0 )); then
    score="MEDIUM_RISK"
  elif (( LOW_ISSUES > 0 )); then
    score="LOW_RISK"
  else
    score="SECURE"
  fi

  # INCOMPLETE should NOT mask CRITICAL/HIGH findings
  if [[ "$BREW_USER_OK" != true ]]; then
    if [[ "$score" == "SECURE" ]] || [[ "$score" == "LOW_RISK" ]] || [[ "$score" == "MEDIUM_RISK" ]]; then
      score="INCOMPLETE"
    fi
  fi

  echo "$score"
}

generate_summary() {
  local score="$1"
  local summary=""

  if [[ "$BREW_USER_OK" != true ]] && [[ "$score" == "INCOMPLETE" ]]; then
    summary="Brew checks skipped (no console user); filesystem checks only"
  elif [[ -n "$CRITICAL_DETAILS" ]]; then
    summary="CRITICAL: $CRITICAL_DETAILS"
  elif [[ -n "$HIGH_DETAILS" ]]; then
    summary="HIGH: $HIGH_DETAILS"
  elif [[ -n "$MEDIUM_DETAILS" ]]; then
    summary="MEDIUM: $MEDIUM_DETAILS"
  elif (( LOW_ISSUES > 0 )); then
    summary="Low: $LOW_ISSUES issue(s)"
  else
    summary="All checks passed"
  fi

  if (( ${#summary} > 200 )); then
    summary="${summary:0:197}..."
  fi

  echo "$summary"
}

write_state_file() {
  local installed="$1"
  local status="$2"
  local score="$3"
  local summary="$4"

  mkdir -p "$LOG_DIR" 2>/dev/null || true

  local sanitized_summary sanitized_taps_list
  sanitized_summary="$(sanitize_attr "$summary")"
  sanitized_taps_list="$(sanitize_attr "$TAPS_THIRDPARTY_LIST")"

  local escaped_summary escaped_taps_list
  escaped_summary="$(printf '%s' "$sanitized_summary" | json_escape)"
  escaped_taps_list="$(printf '%s' "$sanitized_taps_list" | json_escape)"

  cat > "$STATE_FILE" 2>/dev/null <<EOF || true
{
  "installed": "$installed",
  "security_score": "$score",
  "critical_issues": $CRITICAL_ISSUES,
  "high_issues": $HIGH_ISSUES,
  "medium_issues": $MEDIUM_ISSUES,
  "low_issues": $LOW_ISSUES,
  "total_issues": $TOTAL_ISSUES,
  "critical_outdated": $CRITICAL_OUTDATED,
  "world_writable_found": $WORLD_WRITABLE_FOUND,
  "taps_total": $TAPS_TOTAL,
  "taps_official": $TAPS_OFFICIAL,
  "taps_thirdparty": $TAPS_THIRDPARTY,
  "taps_thirdparty_list": "$escaped_taps_list",
  "tap_policy": "$TAP_POLICY",
  "tap_risk": "$TAP_RISK",
  "git_remote_risk": $GIT_REMOTE_RISK,
  "git_remote_unknown": $GIT_REMOTE_UNKNOWN,
  "env_overrides": $ENV_OVERRIDES,
  "casks_installed": $CASKS_INSTALLED,
  "summary": "$escaped_summary",
  "console_user": "$(sanitize_attr "${CONSOLE_USER:-}")",
  "actual_user": "$(sanitize_attr "$ACTUAL_USER")",
  "last_scan": "$(date '+%Y-%m-%d %H:%M:%S')",
  "script_version": "$VERSION",
  "status": "$status"
}
EOF
}

emit_intune_attributes() {
  local installed="$1"
  local score="$2"
  local summary="$3"

  local sanitized_summary sanitized_taps_list
  sanitized_summary="$(sanitize_attr "$summary")"
  sanitized_taps_list="$(sanitize_attr "$TAPS_THIRDPARTY_LIST")"

  # Stdout MUST be key=value only
  echo "HomeBrew_Installed=$installed"
  echo "HomeBrew_Security_Score=$score"

  echo "HomeBrew_Critical_Issues=$CRITICAL_ISSUES"
  echo "HomeBrew_High_Issues=$HIGH_ISSUES"
  echo "HomeBrew_Medium_Issues=$MEDIUM_ISSUES"
  echo "HomeBrew_Low_Issues=$LOW_ISSUES"
  echo "HomeBrew_Total_Issues=$TOTAL_ISSUES"

  echo "HomeBrew_Critical_Packages_Outdated=$CRITICAL_OUTDATED"
  echo "HomeBrew_World_Writable_Found=$WORLD_WRITABLE_FOUND"

  echo "HomeBrew_User_Context=$([[ "$BREW_USER_OK" == true ]] && echo Available || echo Unavailable)"
  echo "HomeBrew_BrewChecks=$([[ "$BREW_USER_OK" == true ]] && echo Ran || echo Skipped_NoUser)"

  echo "HomeBrew_Taps_Total=$TAPS_TOTAL"
  echo "HomeBrew_Taps_Official=$TAPS_OFFICIAL"
  echo "HomeBrew_Taps_ThirdParty_Count=$TAPS_THIRDPARTY"
  echo "HomeBrew_Taps_ThirdParty_List=$sanitized_taps_list"
  echo "HomeBrew_TapPolicy=$TAP_POLICY"
  echo "HomeBrew_TapRisk=$TAP_RISK"

  echo "HomeBrew_Git_Remote_Risk=$GIT_REMOTE_RISK"
  echo "HomeBrew_Git_Remote_Unknown=$GIT_REMOTE_UNKNOWN"
  echo "HomeBrew_Env_Overrides=$ENV_OVERRIDES"
  echo "HomeBrew_Casks_Installed=$CASKS_INSTALLED"

  echo "HomeBrew_Issues_Summary=$sanitized_summary"
  echo "HomeBrew_Last_Scan=$(date '+%Y-%m-%d %H:%M:%S')"
  echo "HomeBrew_Script_Version=$VERSION"
}

########################################
# Main workflow
########################################

main() {
  # Step 1: logging and dependencies (do not fail hard)
  setup_logging || true
  check_dependencies || true

  # Step 2: user context
  setup_user_context

  # Step 3: detect Homebrew
  if ! detect_homebrew; then
    local summary="Homebrew not installed"
    write_state_file "No" "not_installed" "N/A" "$summary"
    emit_intune_attributes "No" "N/A" "$summary"
    return 0
  fi

  # Step 4: filesystem checks (always safe)
  # Primary signal: filesystem integrity of Homebrew binary
  check_brew_binary_security
  # Primary signal: permissions and ownership of Homebrew directories
  check_brew_directories_security

  # Step 5: brew checks (only with console user)
  # Strong policy signal: tap provenance (official vs third-party)
  check_tap_policy
  # Strong supply-chain signal: git remotes for Homebrew repos
  check_git_remotes
  # Secondary signal: RC-file overrides of Homebrew git remotes
  check_env_overrides
  # Inventory signal: installed casks (exposure surface)
  check_casks_installed
  # Patch hygiene signal: outdated security-critical packages
  check_outdated_packages

  # Step 6: compute score + summary
  local score summary status
  score="$(calculate_security_score)"
  summary="$(generate_summary "$score")"
  status="completed"
  if [[ "$BREW_USER_OK" != true ]]; then
    status="partial"
  fi

  # Step 7: persist state + emit Intune attrs
  write_state_file "Yes" "$status" "$score" "$summary"
  emit_intune_attributes "Yes" "$score" "$summary"

  return 0
}

########################################
# Error handling wrapper (guaranteed output)
########################################

run_with_error_handling() {
  set +e
  main "$@"
  local rc=$?

  if (( rc != 0 )); then
    local summary score
    summary="$(sanitize_attr "Script execution failed. Check ${LOG_FILE} and ${STATE_FILE}")"
    score="ERROR"

    # Best-effort state file
    write_state_file "Error" "error" "$score" "$summary"

    # Minimal but valid stdout for Intune
    CRITICAL_ISSUES=0
    HIGH_ISSUES=0
    MEDIUM_ISSUES=0
    LOW_ISSUES=0
    TOTAL_ISSUES=0
    CRITICAL_OUTDATED=0
    WORLD_WRITABLE_FOUND=0
    TAPS_TOTAL=0
    TAPS_OFFICIAL=0
    TAPS_THIRDPARTY=0
    TAPS_THIRDPARTY_LIST=""
    TAP_POLICY="Unknown"
    TAP_RISK="Low"
    GIT_REMOTE_RISK=0
    GIT_REMOTE_UNKNOWN=0
    ENV_OVERRIDES=0
    CASKS_INSTALLED=0
    BREW_USER_OK=false

    emit_intune_attributes "Error" "$score" "$summary"
  fi

  exit 0
}

run_with_error_handling "$@"
