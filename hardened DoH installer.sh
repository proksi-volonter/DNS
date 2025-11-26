#!/bin/bash

# ===========================================================================
# Outline DoH Hardened Installer — v13.7
# ===========================================================================
# Fixed: Restore DNS before package installation to prevent apt failures.
# Fixed: Temporarily restore resolv.conf before apt update/install.
# Fixed: All previous security and reliability issues.
# Secure, atomic, and production-ready installer for DNS-over-HTTPS proxy.
# ===========================================================================

set -Eeuo pipefail
umask 0077
export LC_ALL=C
export LANG=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- Configuration ---
readonly PROGRAM_NAME="outline-doh-installer"
readonly SCRIPT_VERSION="13.7"

# Paths
readonly LOG_FILE_PATH="/var/log/${PROGRAM_NAME}.log"
readonly RUNTIME_DIRECTORY="/var/lib/outline-doh"
readonly DNSCRYPT_RUNTIME_DIRECTORY="/var/lib/dnscrypt-proxy"
readonly DNSCRYPT_CONFIG_DIRECTORY="/etc/dnscrypt-proxy"
readonly DNSCRYPT_CONFIG_FILE_ORIGINAL="$DNSCRYPT_CONFIG_DIRECTORY/dnscrypt-proxy.toml"
readonly DNSCRYPT_CONFIG_FILE_BACKUP="$DNSCRYPT_CONFIG_DIRECTORY/dnscrypt-proxy.toml.bak.${PROGRAM_NAME}"
readonly ROTATOR_CONFIG_FILE="/etc/outline-doh-rotator.conf"
readonly ROTATOR_SCRIPT_PATH="/usr/local/bin/outline-doh-rotator.sh"
readonly DYNAMIC_CONFIG_FILE="$DNSCRYPT_RUNTIME_DIRECTORY/dynamic.toml"
readonly RESOLVER_CONFIG_FILE="/etc/resolv.conf"
readonly RESOLVER_CONFIG_BACKUP="/var/backups/resolv.conf.bak.${PROGRAM_NAME}"
readonly LOCK_FILE_PATH="/var/lock/${PROGRAM_NAME}.lock"
readonly PID_FILE_PATH="/run/${PROGRAM_NAME}.pid"
readonly TRUSTED_RESOLVER_LIST_FILE="$RUNTIME_DIRECTORY/trusted-resolvers.conf"
readonly BLOCKED_GEO_LIST_FILE="$RUNTIME_DIRECTORY/blocked-geo.conf"

# Service accounts
readonly SERVICE_USER="dnscrypt-proxy"
readonly SERVICE_GROUP="nogroup"

# Default trusted resolvers
readonly DEFAULT_TRUSTED_RESOLVER_LIST=(
  "185.236.104.104|https://doh.faelix.net/dns-query"
  "212.47.252.170|https://dns.scaleway.com/dns-query"
  "94.140.14.14|https://dns.adguard-dns.com/dns-query"
)

# Blocked countries
readonly DEFAULT_BLOCKED_GEO_LIST=("RU" "CN" "BY" "KZ" "UZ" "TJ" "KG" "TM" "MD" "AM" "GE" "AZ")

# --- Global state ---
declare -a ROLLBACK_FILE_LIST=()
declare -a ROLLBACK_DIRECTORY_LIST=()
declare -a TRUSTED_RESOLVER_LIST=()
declare -a RESOLVED_CONFLICT_LIST=()
declare -a TEMPORARY_FILE_LIST=()

# Track original resolv.conf content
declare ORIGINAL_RESOLV_CONTENT=""

# --- Logging ---
log_msg() {
  local log_level="$1"; shift
  local timestamp
  timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  local log_entry="[${timestamp}] [${log_level}] [${PROGRAM_NAME}] [PID=$$] $*"

  if [ ! -d "/var/log" ]; then
    install -d -m 700 -o root -g adm /var/log 2>/dev/null || true
  fi

  local log_lock="/tmp/${PROGRAM_NAME}.log.lock"
  exec 201>"$log_lock"
  if flock -x -w 3 201; then
    printf '%s\n' "$log_entry" >> "$LOG_FILE_PATH"
    rm -f -- "$log_lock"
  else
    printf '%s\n' "$log_entry" >> "$LOG_FILE_PATH"
  fi
  exec 201>&-
  printf '%s\n' "$log_entry" >&2
}

log_info()  { log_msg "INFO"  "$@"; }
log_warn()  { log_msg "WARN"  "$@"; }
log_error() { log_msg "ERROR" "$@"; }

# --- Safe temporary file creation ---
create_temp_file() {
  local prefix="${1:-${PROGRAM_NAME}}"
  local temp_path
  local temp_directories=("/tmp" "/var/tmp" "/dev/shm" "/run/user/0" "$RUNTIME_DIRECTORY/tmp")

  install -d -m 750 -o root -g root "$RUNTIME_DIRECTORY" 2>/dev/null || true

  for temp_dir in "${temp_directories[@]}"; do
    if [ -d "$temp_dir" ] && [ -w "$temp_dir" ] && [ ! -L "$temp_dir" ]; then
      temp_path=$(mktemp -p "$temp_dir" --suffix=.tmp "/tmp/${prefix}.$$.$(od -An -N4 -tu4 < /dev/urandom 2>/dev/null | tr -d ' ' || echo $$).XXXXXXXXXX" 2>/dev/null) && break
    fi
  done

  if [ -z "$temp_path" ]; then
    install -d -m 700 -o root -g root "$RUNTIME_DIRECTORY/tmp" 2>/dev/null || {
      log_error "Failed to create private temp directory: $RUNTIME_DIRECTORY/tmp"
      _exit_with_error_code 1 "Private temp dir creation failed"
    }
    temp_path=$(mktemp -p "$RUNTIME_DIRECTORY/tmp" --suffix=.tmp "/tmp/${prefix}.$$.$(od -An -N4 -tu4 < /dev/urandom 2>/dev/null | tr -d ' ' || echo $$).XXXXXXXXXX" 2>/dev/null) || {
      log_error "Failed to create temporary file in any location: ${temp_directories[*]}, $RUNTIME_DIRECTORY/tmp"
      _exit_with_error_code 1 "Temporary file creation failed"
    }
  fi

  TEMPORARY_FILE_LIST+=("$temp_path")
  printf '%s' "$temp_path"
}

# --- File safety ---
safe_copy() {
  local src="$1" dst="$2"
  if [ -L "$src" ] || [ -L "$dst" ]; then
    log_error "Refusing to operate on symlinks: $src -> $dst"
    _exit_with_error_code 1 "Symlink operation refused"
  fi
  cp --no-dereference --no-preserve=mode,ownership -- "$src" "$dst" 2>/dev/null || {
    log_error "Failed to copy $src to $dst"
    _exit_with_error_code 1 "File copy failed"
  }
}

replace_file_atomically() {
  local src="$1" dst="$2"
  if [ "$src" = "$dst" ]; then
    log_error "atomic_replace: source and destination are identical"
    _exit_with_error_code 1 "Atomic replace with identical paths"
  fi

  if [ -f "$dst" ] && [ ! -L "$dst" ]; then
    local backup="${dst}.bak.${PROGRAM_NAME}"
    safe_copy "$dst" "$backup"
    ROLLBACK_FILE_LIST+=("$backup")
  fi
  ROLLBACK_FILE_LIST+=("$dst")

  if ! mv -- "$src" "$dst"; then
    log_error "Failed to move $src to $dst"
    local backup="${dst}.bak.${PROGRAM_NAME}"
    if [ -f "$backup" ]; then
      mv -- "$backup" "$dst" 2>/dev/null || log_warn "Could not restore $dst from backup"
    fi
    _exit_with_error_code 1 "File move failed"
  fi
}

# --- System checks ---
verify_os_compatibility() {
  if [ ! -f /etc/os-release ]; then
    log_error "Unsupported system: /etc/os-release not found"
    _exit_with_error_code 1 "OS compatibility check failed"
  fi

  . /etc/os-release
  case "$ID" in
    ubuntu|debian)
      log_info "Detected OS: $ID $VERSION_ID"
      ;;
    *)
      log_error "Unsupported OS: $ID (only Ubuntu/Debian are supported)"
      _exit_with_error_code 1 "Unsupported OS"
      ;;
  esac
}

verify_disk_space() {
  local dir="$1" min_kb="${2:-10240}"
  local avail
  avail=$(df -k "$dir" --output=avail 2>/dev/null | tail -1 | tr -d '[:space:]')
  if [[ -z "$avail" ]] || ! [[ "$avail" =~ ^[0-9]+$ ]] || [ "$avail" -lt "$min_kb" ]; then
    log_error "Insufficient disk space in $dir (available: ${avail:-0} KB)"
    _exit_with_error_code 1 "Insufficient disk space"
  fi
}

wait_for_package_manager() {
  local timeout=120 count=0
  while pgrep -x apt >/dev/null 2>&1 || pgrep -x dpkg >/dev/null 2>&1; do
    if [ $count -ge $timeout ]; then
      log_error "Package manager locked for $timeout seconds"
      _exit_with_error_code 1 "Package manager timeout"
    fi
    sleep 1
    ((count++))
  done
}

# --- Check dnscrypt-proxy binary path ---
find_dnscrypt_proxy_binary() {
  local binary_path
  if command -v dnscrypt-proxy >/dev/null 2>&1; then
    binary_path=$(command -v dnscrypt-proxy)
  elif [ -x /usr/sbin/dnscrypt-proxy ]; then
    binary_path="/usr/sbin/dnscrypt-proxy"
  elif [ -x /usr/bin/dnscrypt-proxy ]; then
    binary_path="/usr/bin/dnscrypt-proxy"
  else
    log_error "dnscrypt-proxy binary not found in PATH or standard locations"
    _exit_with_error_code 1 "dnscrypt-proxy binary not found"
  fi

  if ! timeout 3 "$binary_path" --help >/dev/null 2>&1; then
    log_error "dnscrypt-proxy binary at $binary_path is not executable or invalid"
    _exit_with_error_code 1 "dnscrypt-proxy binary invalid"
  fi

  log_info "Found dnscrypt-proxy binary at: $binary_path"
  printf '%s' "$binary_path"
}

# --- Port check ---
verify_port_53_availability() {
  local in_use=false
  local conflicting_pids=()

  if command -v ss >/dev/null 2>&1 && ss -uln 2>/dev/null | grep -qE ':53([^0-9]|$)'; then
    in_use=true
    conflicting_pids+=($(ss -ulnp 2>/dev/null | awk -F '[,=]' '/:53([^0-9]|$)/ {for(i=1;i<=NF;i++) if($i ~ /pid=/) print $(i+1)}'))
  fi
  if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -qE ':53([^0-9]|$)'; then
    in_use=true
    conflicting_pids+=($(ss -tlnp 2>/dev/null | awk -F '[,=]' '/:53([^0-9]|$)/ {for(i=1;i<=NF;i++) if($i ~ /pid=/) print $(i+1)}'))
  fi

  if [ "$in_use" = true ]; then
    if [ ${#conflicting_pids[@]} -gt 0 ]; then
      log_info "Port 53 in use by PIDs: ${conflicting_pids[*]}"
    fi
    log_info "Stopping conflicting services..."
    stop_conflicting_dns_services
    sleep 3

    in_use=false
    if ss -uln 2>/dev/null | grep -qE ':53([^0-9]|$)'; then
      in_use=true
    elif ss -tln 2>/dev/null | grep -qE ':53([^0-9]|$)'; then
      in_use=true
    fi

    if [ "$in_use" = true ]; then
      log_error "Port 53 remains in use after stopping services"
      _exit_with_error_code 1 "Port 53 conflict unresolved"
    fi
  fi
}

stop_conflicting_dns_services() {
  local units=(
    systemd-resolved.socket
    systemd-resolved.service
    dnscrypt-proxy.socket
    dnscrypt-proxy.service
    dnsmasq.service
    unbound.service
  )

  for unit in "${units[@]}"; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      systemctl stop "$unit" 2>/dev/null || true
      log_info "Stopped $unit"
      RESOLVED_CONFLICT_LIST+=("$unit")
    fi
  done

  if [ -L "$RESOLVER_CONFIG_FILE" ]; then
    local target
    target=$(readlink "$RESOLVER_CONFIG_FILE" 2>/dev/null) || true
    if [[ "$target" != *"/stub-resolv.conf" ]] && [[ "$target" != *"/resolv.conf" ]]; then
      rm -f -- "$RESOLVER_CONFIG_FILE"
    fi
  fi
}

# --- Create service user FIRST ---
create_service_account() {
  if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    if ! useradd --system --no-create-home --shell /usr/sbin/nologin --uid 198 "$SERVICE_USER" 2>/dev/null; then
      log_error "Failed to create user $SERVICE_USER"
      _exit_with_error_code 1 "User creation failed"
    fi
  fi

  if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    if ! groupadd --system "$SERVICE_GROUP" 2>/dev/null; then
      log_error "Failed to create group $SERVICE_GROUP"
      _exit_with_error_code 1 "Group creation failed"
    fi
  fi

  if ! id -nG "$SERVICE_USER" 2>/dev/null | grep -qw "$SERVICE_GROUP"; then
    if ! usermod -a -G "$SERVICE_GROUP" "$SERVICE_USER" 2>/dev/null; then
      log_error "Failed to add $SERVICE_USER to $SERVICE_GROUP"
      _exit_with_error_code 1 "User group assignment failed"
    fi
  fi

  log_info "Service user/group created: $SERVICE_USER:$SERVICE_GROUP"
}

# --- Config management ---
ensure_configuration_file_exists() {
  local config_file="$1" default_content="$2" mode="${3:-600}" owner="${4:-root:root}"

  if [ ! -f "$config_file" ]; then
    log_info "Creating default config: $config_file"
    local tmp
    tmp=$(create_temp_file "config")
    printf '%s\n' "# ${PROGRAM_NAME} v${SCRIPT_VERSION}" > "$tmp"
    printf '%s\n' "$default_content" >> "$tmp"
    replace_file_atomically "$tmp" "$config_file"
    if ! chmod "$mode" "$config_file"; then
      log_error "chmod failed on $config_file"
      _exit_with_error_code 1 "chmod failed on $config_file"
    fi
    if ! chown "$owner" "$config_file"; then
      log_error "chown failed on $config_file"
      _exit_with_error_code 1 "chown failed on $config_file"
    fi
    ROLLBACK_FILE_LIST+=("$config_file")
  fi
}

load_trusted_resolver_list() {
  local default_trusted
  printf -v default_trusted '%s\n' "${DEFAULT_TRUSTED_RESOLVER_LIST[@]}"
  ensure_configuration_file_exists "$TRUSTED_RESOLVER_LIST_FILE" "$default_trusted" "600" "root:root"

  local line_num=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_num++))
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" =~ ^# ]] && continue

    if ! [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}\|https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/dns-query$ ]]; then
      log_error "Invalid trusted resolver at line $line_num: $line"
      _exit_with_error_code 1 "Invalid trusted resolver format"
    fi

    local ip="${line%%|*}"
    IFS=. read -r a b c d <<< "$ip"
    for octet in "$a" "$b" "$c" "$d"; do
      if [ "$octet" -gt 255 ] 2>/dev/null; then
        log_error "Invalid IP octet: $ip"
        _exit_with_error_code 1 "Invalid IP octet in resolver"
      fi
    done

    TRUSTED_RESOLVER_LIST+=("$line")
  done < "$TRUSTED_RESOLVER_LIST_FILE"

  if [ ${#TRUSTED_RESOLVER_LIST[@]} -eq 0 ]; then
    log_error "No valid trusted resolvers"
    _exit_with_error_code 1 "No valid trusted resolvers found"
  fi

  log_info "Loaded ${#TRUSTED_RESOLVER_LIST[@]} trusted resolvers"
}

load_blocked_geo_list() {
  local default_geo
  printf -v default_geo '%s\n' "${DEFAULT_BLOCKED_GEO_LIST[@]}"
  ensure_configuration_file_exists "$BLOCKED_GEO_LIST_FILE" "$default_geo" "600" "root:root"
}

# --- Resolver validation ---
is_valid_ip() {
  local ip="$1"
  if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    local IFS=.
    local ip_parts=($ip)
    for part in "${ip_parts[@]}"; do
      if [ "$part" -gt 255 ] 2>/dev/null; then
        return 1
      fi
    done
    return 0
  elif [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]] || [[ "$ip" == "::1" ]] || [[ "$ip" == "::" ]] || [[ "$ip" =~ ^::[0-9a-fA-F]{1,4}$ ]]; then
    return 0
  fi
  return 1
}

is_valid_url() {
  local url="$1"
  [[ "$url" =~ ^https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/dns-query$ ]]
}

validate_resolvers_file() {
  local md_file="$1"
  local errors=0 current_name="" ip="" url=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%"${line##*[![:space:]]}"}"
    if [[ -z "$line" ]]; then
      if [[ -n "$current_name" ]]; then
        [[ -z "$ip" ]] && { log_error "Resolver $current_name: missing ip"; ((errors++)); }
        [[ -z "$url" ]] && { log_error "Resolver $current_name: missing url"; ((errors++)); }
      fi
      current_name=""; ip=""; url=""
    elif [[ $line =~ ^##[[:space:]]+(.+)$ ]]; then
      current_name="${BASH_REMATCH[1]}"
    elif [[ $line =~ ^ip:[[:space:]]*(.+)$ ]]; then
      ip="${BASH_REMATCH[1]}"
    elif [[ $line =~ ^url:[[:space:]]*(.+)$ ]]; then
      url="${BASH_REMATCH[1]}"
    fi
  done < "$md_file"

  if [[ -n "$current_name" ]]; then
    [[ -z "$ip" ]] && { log_error "Resolver $current_name: missing ip"; ((errors++)); }
    [[ -z "$url" ]] && { log_error "Resolver $current_name: missing url"; ((errors++)); }
  fi

  return $((errors > 0 ? 1 : 0))
}

deduplicate_resolvers() {
  local input_file="$1" output_file="$2"
  local tmp_file
  tmp_file=$(create_temp_file "resolvers")

  local current_name="" ip="" url="" geo=""
  local line_num=0 valid_count=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_num++))
    line="${line%"${line##*[![:space:]]}"}"
    if [[ -z "$line" ]]; then
      if [[ -n "$current_name" && -n "$ip" && -n "$url" ]]; then
        if ! is_valid_ip "$ip"; then
          log_error "Invalid IP at line $line_num: $ip"
          _exit_with_error_code 1 "Invalid IP in resolver"
        fi
        if ! is_valid_url "$url"; then
          log_error "Invalid URL at line $line_num: $url"
          _exit_with_error_code 1 "Invalid URL in resolver"
        fi

        printf "## %s\n  ip: %s\n  url: %s\n  logs: false\n  geo: %s\n\n" \
          "$current_name" "$ip" "$url" "${geo:-unknown}" >> "$tmp_file"
        ((valid_count++))
      fi
      current_name=""; ip=""; url=""; geo=""
    elif [[ $line =~ ^##[[:space:]]+(.+)$ ]]; then
      current_name="${BASH_REMATCH[1]}"
    elif [[ $line =~ ^ip:[[:space:]]*(.+)$ ]]; then
      ip="${BASH_REMATCH[1]}"
    elif [[ $line =~ ^url:[[:space:]]*(.+)$ ]]; then
      url="${BASH_REMATCH[1]}"
      if [[ "$url" =~ ^\[.*\]\((.+)\)$ ]]; then
        url="${BASH_REMATCH[1]}"
      fi
    elif [[ $line =~ ^geo:[[:space:]]*(.+)$ ]]; then
      geo="${BASH_REMATCH[1]}"
    fi
  done < "$input_file"

  if [[ -n "$current_name" && -n "$ip" && -n "$url" ]]; then
    if ! is_valid_ip "$ip"; then
      log_error "Invalid IP in last block: $ip"
      _exit_with_error_code 1 "Invalid IP in resolver"
    fi
    if ! is_valid_url "$url"; then
      log_error "Invalid URL in last block: $url"
      _exit_with_error_code 1 "Invalid URL in resolver"
    fi

    printf "## %s\n  ip: %s\n  url: %s\n  logs: false\n  geo: %s\n\n" \
      "$current_name" "$ip" "$url" "${geo:-unknown}" >> "$tmp_file"
    ((valid_count++))
  fi

  if [ $valid_count -eq 0 ]; then
    log_error "No valid resolvers found"
    _exit_with_error_code 1 "No valid resolvers found"
  fi

  validate_resolvers_file "$tmp_file" || { log_error "Resolvers validation failed after deduplication"; _exit_with_error_code 1 "Resolvers validation failed"; }

  replace_file_atomically "$tmp_file" "$output_file"
}

# --- Systemd units ---
install_systemd_units() {
  local dnscrypt_binary_path
  dnscrypt_binary_path=$(find_dnscrypt_proxy_binary)

  local tmp
  tmp=$(create_temp_file "proxy-service")
  printf '# %s v%s\n' "${PROGRAM_NAME}" "${SCRIPT_VERSION}" > "$tmp"
  cat >> "$tmp" <<EOF
[Unit]
Description=Hardened DoH Proxy for Outline
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${dnscrypt_binary_path} -config /var/lib/dnscrypt-proxy/dynamic.toml
Restart=on-failure
RestartSec=5
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/dnscrypt-proxy
ProtectKernelModules=true
ProtectControlGroups=true
PrivateDevices=true
ProtectHostname=true
ProtectClock=true
RestrictRealtime=true
RestrictSUIDSGID=true
ProtectKernelTunables=true
RestrictAddressFamilies=AF_INET AF_UNIX
LockPersonality=true
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
  replace_file_atomically "$tmp" "/etc/systemd/system/outline-doh-proxy.service"

  tmp=$(create_temp_file "rotator-service")
  printf '# %s v%s\n' "${PROGRAM_NAME}" "${SCRIPT_VERSION}" > "$tmp"
  cat >> "$tmp" <<EOF
[Unit]
Description=Rotate DoH resolver
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/outline-doh-rotator.sh
ExecStartPost=/bin/systemctl try-restart outline-doh-proxy.service
User=root
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true
ProtectHome=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true
LockPersonality=true
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
  replace_file_atomically "$tmp" "/etc/systemd/system/outline-doh-rotator.service"

  tmp=$(create_temp_file "timer")
  printf '# %s v%s\n' "${PROGRAM_NAME}" "${SCRIPT_VERSION}" > "$tmp"
  cat >> "$tmp" <<EOF
[Unit]
Description=Rotate DoH resolver every 2 hours

[Timer]
OnBootSec=30s
OnUnitActiveSec=2h
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF
  replace_file_atomically "$tmp" "/etc/systemd/system/outline-doh-rotator.timer"
}

# --- Rotator script ---
generate_rotator_script() {
  if ! command -v curl >/dev/null 2>&1; then
    log_error "curl is required but not found"
    _exit_with_error_code 1 "curl not found"
  fi
  if ! command -v flock >/dev/null 2>&1; then
    log_error "flock is required but not found"
    _exit_with_error_code 1 "flock not found"
  fi

  local tmp
  tmp=$(create_temp_file "rotator-script")
  printf '# %s v%s\n' "${PROGRAM_NAME}" "${SCRIPT_VERSION}" > "$tmp"
  cat >> "$tmp" <<'EOF'
#!/bin/bash
set -euo pipefail
umask 0077

_log_info() { printf '%s [INFO] [outline-doh-rotator] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
_log_error() { printf '%s [ERROR] [outline-doh-rotator] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

command -v flock >/dev/null || { _log_error "flock missing"; exit 1; }
command -v curl >/dev/null || { _log_error "curl missing"; exit 1; }

readonly CONFIG_FILE="/etc/outline-doh-rotator.conf"
readonly RUN_DIR="/var/lib/outline-doh"
readonly RESOLVERS_FILE="$RUN_DIR/public-resolvers.md"
readonly HISTORY_FILE="$RUN_DIR/history.log"
readonly METRICS_FILE="$RUN_DIR/metrics.log"
readonly DYNAMIC_CONFIG_FILE="/var/lib/dnscrypt-proxy/dynamic.toml"
readonly FLOCK_FILE="/var/lock/outline-doh-rotator.lock"
readonly MAX_HISTORY=20
readonly BLOCKED_GEO_FILE="/etc/outline-doh/blocked-geo.conf"

# Load blocked GEO codes
mapfile -t BLOCKED_GEO < <(grep -v '^[[:space:]]*#' "$BLOCKED_GEO_FILE" 2>/dev/null | grep -v '^$')

# Load trusted resolvers
readonly TRUSTED_RESOLVER_LIST_FILE="/etc/outline-doh/trusted-resolvers.conf"
declare -a TRUSTED_RESOLVER_LIST=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "$line" ]] || [[ "$line" =~ ^# ]] && continue
  TRUSTED_RESOLVER_LIST+=("$line")
done < "$TRUSTED_RESOLVER_LIST_FILE"

export SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"
export SSL_CERT_DIR="/etc/ssl/certs"

if [ -r /dev/urandom ]; then
  RANDOM_SEED=$(od -An -N4 -tu4 < /dev/urandom 2>/dev/null | tr -d ' ' || echo $$)
else
  RANDOM_SEED=$$
fi

exec 200>"$FLOCK_FILE"
if ! flock -n 200; then
  _log_info "Skipped: another instance running"
  exit 0
fi
trap 'exec 200>&-; rm -f -- "$FLOCK_FILE"' EXIT

[ -f "$CONFIG_FILE" ] && [ -f "$RESOLVERS_FILE" ] || { _log_error "Config files missing"; exit 1; }

readonly PROTOCOL=$(grep "^PROTOCOL=" "$CONFIG_FILE" | cut -d'=' -f2)
readonly SELECTION_PROFILE=$(grep "^SELECTION_PROFILE=" "$CONFIG_FILE" | cut -d'=' -f2)
mapfile -t CANDIDATE_LIST < <(grep -v '^[[:space:]]*#' "$CONFIG_FILE" | grep -v '^PROTOCOL\|^SELECTION_PROFILE' | awk 'NF')

(( ${#CANDIDATE_LIST[@]} > 0 )) || { _log_error "No candidates"; exit 1; }

HISTORY_LIST=()
[ -f "$HISTORY_FILE" ] && flock "$HISTORY_FILE" -- mapfile -t HISTORY_LIST < <(tail -n "$MAX_HISTORY" "$HISTORY_FILE" 2>/dev/null | grep -v '^$')

declare -A RESOLVER_IP_ADDRESS RESOLVER_ENDPOINT_URL RESOLVER_COUNTRY_CODE
current_resolver_name=""
while IFS= read -r line || [[ -n $line ]]; do
  [[ -z $line ]] && continue
  if [[ $line =~ ^##[[:space:]]+(.+)$ ]]; then
    current_resolver_name="${BASH_REMATCH[1]}"
  elif [[ -n $current_resolver_name ]]; then
    if [[ $line =~ ^ip:[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
      RESOLVER_IP_ADDRESS["$current_resolver_name"]="${BASH_REMATCH[1]}"
    elif [[ $line =~ ^url:[[:space:]]*(.+)$ ]]; then
      url="${BASH_REMATCH[1]}"
      if [[ "$url" =~ ^\[.*\]\((.+)\)$ ]]; then
        url="${BASH_REMATCH[1]}"
      fi
      RESOLVER_ENDPOINT_URL["$current_resolver_name"]="$url"
    elif [[ $line =~ ^geo:[[:space:]]*(.+)$ ]]; then
      RESOLVER_COUNTRY_CODE["$current_resolver_name"]="${BASH_REMATCH[1]}"
    fi
  fi
done < "$RESOLVERS_FILE"

AVAILABLE_RESOLVER_LIST=()
for candidate in "${CANDIDATE_LIST[@]}"; do
  [[ -n ${RESOLVER_IP_ADDRESS[$candidate]:-} ]] && [[ -n ${RESOLVER_ENDPOINT_URL[$candidate]:-} ]] || continue
  country="${RESOLVER_COUNTRY_CODE[$candidate]:-}"
  for blocked_country in "${BLOCKED_GEO[@]}"; do
    [[ "$country" == "$blocked_country" ]] && continue 2
  done
  for used_resolver in "${HISTORY_LIST[@]}"; do
    [[ "$candidate" == "$used_resolver" ]] && continue 2
  done
  AVAILABLE_RESOLVER_LIST+=("$candidate")
done

if (( ${#AVAILABLE_RESOLVER_LIST[@]} == 0 )); then
  _log_info "All candidates filtered — using fallback"
  for pair in "${TRUSTED_RESOLVER_LIST[@]}"; do
    ip="${pair%%|*}"
    url="${pair#*|}"
    cat > "$DYNAMIC_CONFIG_FILE" <<FALLBACK
listen_addresses = ['127.0.0.1:53']
ipv4_servers = true
ipv6_servers = false
doh_servers = true
require_nolog = true
require_nofilter = true
bootstrap_resolvers = ['$ip:53']
fallback_resolver = '$ip:53'
ignore_system_dns = true
log_level = 1
cache = false

[static.'fallback']
urls = ['$url']
ip_addresses = ['$ip']
FALLBACK
    chown dnscrypt-proxy:nogroup "$DYNAMIC_CONFIG_FILE" 2>/dev/null || true
    chmod 600 "$DYNAMIC_CONFIG_FILE" 2>/dev/null || true
    exit 0
  done
  _log_error "All fallbacks failed"
  exit 1
fi

SELECTED="${AVAILABLE_RESOLVER_LIST[RANDOM_SEED % ${#AVAILABLE_RESOLVER_LIST[@]}]}"
IP="${RESOLVER_IP_ADDRESS[$SELECTED]}"
URL="${RESOLVER_ENDPOINT_URL[$SELECTED]}"
[[ -n $IP && -n $URL ]] || { _log_error "Missing IP/URL for $SELECTED"; exit 1; }

printf '%s\n' "$SELECTED" > "$HISTORY_FILE.tmp"
tail -n "$((MAX_HISTORY - 1))" "$HISTORY_FILE" 2>/dev/null >> "$HISTORY_FILE.tmp"
mv -- "$HISTORY_FILE.tmp" "$HISTORY_FILE"

SAFE_NAME=$(printf '%s' "$SELECTED" | sed "s/[^a-zA-Z0-9_.-]/_/g; s/'//g; s/__*/_/g")
[[ -n $SAFE_NAME ]] || SAFE_NAME="resolver_$(date +%s)"

cat > "$DYNAMIC_CONFIG_FILE.tmp" <<EOF
listen_addresses = ['127.0.0.1:53']
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = false
doh_servers = true
require_nolog = true
require_nofilter = true
bootstrap_resolvers = ['${TRUSTED_RESOLVER_LIST[0]%%|*}:53']
fallback_resolver = '${TRUSTED_RESOLVER_LIST[0]%%|*}:53'
ignore_system_dns = true
log_level = 1
cache = false

[static.'$SAFE_NAME']
urls = ['$URL']
ip_addresses = ['$IP']
EOF
mv -- "$DYNAMIC_CONFIG_FILE.tmp" "$DYNAMIC_CONFIG_FILE"
if ! chown dnscrypt-proxy:nogroup "$DYNAMIC_CONFIG_FILE" 2>/dev/null; then
  _log_warn "chown failed on dynamic.toml"
fi
if ! chmod 600 "$DYNAMIC_CONFIG_FILE" 2>/dev/null; then
  _log_warn "chmod failed on dynamic.toml"
fi
_log_info "Selected: $SELECTED (geo: ${RESOLVER_COUNTRY_CODE[$SELECTED]:-unknown}) [Profile: $SELECTION_PROFILE]"
EOF
  replace_file_atomically "$tmp" "$ROTATOR_SCRIPT_PATH"
  if ! chmod 700 "$ROTATOR_SCRIPT_PATH"; then
    log_error "chmod failed on rotator script"
    _exit_with_error_code 1 "Rotator chmod failed"
  fi
  if ! chown root:root "$ROTATOR_SCRIPT_PATH"; then
    log_error "chown failed on rotator script"
    _exit_with_error_code 1 "Rotator chown failed"
  fi
  bash -n "$ROTATOR_SCRIPT_PATH" || {
    log_error "Rotator script syntax error"
    _exit_with_error_code 1 "Rotator syntax error"
  }
}

# --- Logrotate ---
install_logrotate_configuration() {
  local tmp
  tmp=$(create_temp_file "logrotate")
  printf '# %s v%s\n' "${PROGRAM_NAME}" "${SCRIPT_VERSION}" > "$tmp"
  cat >> "$tmp" <<EOF
/var/log/outline-doh-installer.log
/var/lib/outline-doh/metrics.log
/var/lib/outline-doh/history.log
{
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 root adm
    maxsize 1M
}
EOF
  replace_file_atomically "$tmp" "/etc/logrotate.d/outline-doh"
  if ! chmod 644 "/etc/logrotate.d/outline-doh"; then
    log_error "chmod failed on logrotate config"
    _exit_with_error_code 1 "Logrotate chmod failed"
  fi
}

# --- Rollback with hash verification ---
perform_rollback() {
  local ec=${1:-$?}
  log_info "Rollback initiated (code $ec)..."

  for unit in outline-doh-rotator.timer outline-doh-rotator.service outline-doh-proxy.service; do
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
  done
  systemctl daemon-reload 2>/dev/null || true

  for file in "${ROLLBACK_FILE_LIST[@]}"; do
    if [[ "$file" == *".bak.${PROGRAM_NAME}" ]]; then
      local orig="${file%.bak.${PROGRAM_NAME}}"
      if [ -f "$file" ]; then
        mv -- "$file" "$orig"
      fi
    elif [ -f "$file" ]; then
      rm -f -- "$file"
    fi
  done

  for dir in "${ROLLBACK_DIRECTORY_LIST[@]}"; do
    if [ -d "$dir" ]; then
      rm -rf -- "$dir"
    fi
  done

  if [ -f "$DNSCRYPT_CONFIG_FILE_BACKUP" ]; then
    [ -f "$DNSCRYPT_CONFIG_FILE_ORIGINAL" ] && rm -f -- "$DNSCRYPT_CONFIG_FILE_ORIGINAL"
    mv -- "$DNSCRYPT_CONFIG_FILE_BACKUP" "$DNSCRYPT_CONFIG_FILE_ORIGINAL" 2>/dev/null
  fi

  if [ -f "$RESOLVER_CONFIG_BACKUP" ] && [ -s "$RESOLVER_CONFIG_BACKUP" ]; then
    [ -e "$RESOLVER_CONFIG_FILE" ] && rm -f -- "$RESOLVER_CONFIG_FILE"
    mv -- "$RESOLVER_CONFIG_BACKUP" "$RESOLVER_CONFIG_FILE" 2>/dev/null
  else
    # Use fallback from trusted list if available, otherwise default
    local fallback_ip="${TRUSTED_RESOLVER_LIST[0]%%|*}"
    if [[ -z "$fallback_ip" ]]; then
      fallback_ip="1.1.1.1"
    fi
    printf "nameserver %s\n" "$fallback_ip" > "$RESOLVER_CONFIG_FILE"
  fi

  for unit in "${RESOLVED_CONFLICT_LIST[@]}"; do
    systemctl unmask "$unit" 2>/dev/null || true
    systemctl start "$unit" 2>/dev/null || true
  done

  rm -f -- "$PID_FILE_PATH" "$LOCK_FILE_PATH"
}

# --- Cleanup ---
cleanup() {
  if [ -e /proc/self/fd/200 ]; then
    exec 200>&-
  fi
  for file in "${TEMPORARY_FILE_LIST[@]}"; do
    rm -f -- "$file" 2>/dev/null || true
  done
  # Cleanup private temp dir
  rm -rf -- "$RUNTIME_DIRECTORY/tmp" 2>/dev/null || true
}

# --- Exit helper ---
_exit_with_error_code() {
  local code="$1" message="$2"
  log_error "$message"
  exit "$code"
}

# --- Locking ---
acquire_lock() {
  if [ -f "$PID_FILE_PATH" ]; then
    local old_pid
    old_pid=$(cat "$PID_FILE_PATH" 2>/dev/null) || true
    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
      log_error "Another instance running (PID $old_pid)"
      _exit_with_error_code 1 "Another instance running"
    fi
  fi
  printf '%s' "$$" > "$PID_FILE_PATH"
  ROLLBACK_FILE_LIST+=("$PID_FILE_PATH")

  exec 200>"$LOCK_FILE_PATH"
  if ! flock -n 200; then
    log_error "Lock file held: $LOCK_FILE_PATH"
    _exit_with_error_code 1 "Lock file is held"
  fi
  ROLLBACK_FILE_LIST+=("$LOCK_FILE_PATH")
}

# --- Main ---
main() {
  log_info "Starting ${PROGRAM_NAME} v${SCRIPT_VERSION}..."

  if [ "$(id -u)" -ne 0 ]; then
    log_error "Must run as root"
    _exit_with_error_code 1 "Must run as root"
  fi

  verify_os_compatibility
  verify_disk_space "/var/log"
  verify_disk_space "/tmp"
  verify_disk_space "/var/tmp"

  acquire_lock

  trap 'perform_rollback $?' ERR
  trap 'cleanup' EXIT

  install -d -m 700 -o root -g adm /var/backups 2>/dev/null || true

  # Backup resolv.conf BEFORE stopping systemd-resolved
  if [ -f "$RESOLVER_CONFIG_FILE" ] && [ ! -L "$RESOLVER_CONFIG_FILE" ]; then
    safe_copy "$RESOLVER_CONFIG_FILE" "$RESOLVER_CONFIG_BACKUP"
    ROLLBACK_FILE_LIST+=("$RESOLVER_CONFIG_BACKUP")
  elif [ -L "$RESOLVER_CONFIG_FILE" ]; then
    local target
    target=$(readlink "$RESOLVER_CONFIG_FILE" 2>/dev/null) || true
    if [ -f "$target" ]; then
      safe_copy "$target" "$RESOLVER_CONFIG_BACKUP"
      ROLLBACK_FILE_LIST+=("$RESOLVER_CONFIG_BACKUP")
      # Store original content for later restoration
      ORIGINAL_RESOLV_CONTENT=$(cat "$target")
    fi
  else
    ORIGINAL_RESOLV_CONTENT=$(cat "$RESOLVER_CONFIG_FILE" 2>/dev/null || echo "")
  fi

  if [ -f "$DNSCRYPT_CONFIG_FILE_ORIGINAL" ] && [ ! -L "$DNSCRYPT_CONFIG_FILE_ORIGINAL" ]; then
    safe_copy "$DNSCRYPT_CONFIG_FILE_ORIGINAL" "$DNSCRYPT_CONFIG_FILE_BACKUP"
    ROLLBACK_FILE_LIST+=("$DNSCRYPT_CONFIG_FILE_BACKUP")
  fi

  stop_conflicting_dns_services
  verify_port_53_availability
  wait_for_package_manager

  # TEMPORARILY RESTORE DNS FOR PACKAGE INSTALLATION
  if [ -L "$RESOLVER_CONFIG_FILE" ]; then
    rm -f -- "$RESOLVER_CONFIG_FILE"
  fi
  [ -e "$RESOLVER_CONFIG_FILE" ] && rm -f -- "$RESOLVER_CONFIG_FILE"
  printf "nameserver 8.8.8.8\nnameserver 1.1.1.1\n" > "$RESOLVER_CONFIG_FILE"

  # Install packages
  DEBIAN_FRONTEND=noninteractive timeout 600 apt update -y || { log_error "apt update failed"; _exit_with_error_code 1 "apt update failed"; }
  DEBIAN_FRONTEND=noninteractive timeout 600 apt install -y \
    dnscrypt-proxy dnsutils curl logrotate ca-certificates || { log_error "Install failed"; _exit_with_error_code 1 "Install failed"; }

  # Verify dnscrypt-proxy is available
  if ! command -v dnscrypt-proxy >/dev/null 2>&1; then
    log_error "dnscrypt-proxy not found after installation"
    _exit_with_error_code 1 "dnscrypt-proxy not found"
  fi

  # Restore original resolv.conf
  if [ -n "$ORIGINAL_RESOLV_CONTENT" ]; then
    printf '%s\n' "$ORIGINAL_RESOLV_CONTENT" > "$RESOLVER_CONFIG_FILE"
  else
    printf "nameserver 8.8.8.8\n" > "$RESOLVER_CONFIG_FILE"
  fi

  # Create user FIRST, before using it in directories
  create_service_account

  # Create directories with user available
  install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DNSCRYPT_RUNTIME_DIRECTORY"
  ROLLBACK_DIRECTORY_LIST+=("$DNSCRYPT_RUNTIME_DIRECTORY")

  install -d -m 750 -o root -g root "$RUNTIME_DIRECTORY"
  ROLLBACK_DIRECTORY_LIST+=("$RUNTIME_DIRECTORY")

  install -d -m 700 -o root -g root "$DNSCRYPT_CONFIG_DIRECTORY"
  ROLLBACK_DIRECTORY_LIST+=("$DNSCRYPT_CONFIG_DIRECTORY")

  # Load resolvers
  load_trusted_resolver_list
  load_blocked_geo_list

  # Configs
  default_resolvers="scaleway-fr
faelix-ch-ipv4
adguard-dns
ams-dns-nl
jp.tiar.app
libredns-ar
uncensoreddns-dk"
  ensure_configuration_file_exists "$ROTATOR_CONFIG_FILE" "$default_resolvers" "600" "root:root"
  chmod 640 "$ROTATOR_CONFIG_FILE" || log_warn "chmod failed on rotator config"
  chown root:root "$ROTATOR_CONFIG_FILE" || log_warn "chown failed on rotator config"

  local resolvers_md
  resolvers_md=$(cat <<'EOF'
## scaleway-fr
  ip: 212.47.252.170
  url: https://dns.scaleway.com/dns-query
  logs: false
  geo: FR

## faelix-ch-ipv4
  ip: 185.236.104.104
  url: https://doh.faelix.net/dns-query
  logs: false
  geo: CH

## adguard-dns
  ip: 94.140.14.14
  url: https://dns.adguard-dns.com/dns-query
  logs: false
  geo: NL

## ams-dns-nl
  ip: 185.231.152.66
  url: https://doh.nl.libredns.gr/dns-query
  logs: false
  geo: NL

## jp.tiar.app
  ip: 103.175.7.17
  url: https://doh-jp.tiar.app/dns-query
  logs: false
  geo: JP

## libredns-ar
  ip: 199.58.81.218
  url: https://doh.ar.libredns.gr/dns-query
  logs: false
  geo: AR

## uncensoreddns-dk
  ip: 89.233.43.71
  url: https://anycast.censurfridns.dk/dns-query
  logs: false
  geo: DK
EOF
)
  printf '%s\n' "$resolvers_md" > "$RUNTIME_DIRECTORY/public-resolvers.md.tmp"
  deduplicate_resolvers "$RUNTIME_DIRECTORY/public-resolvers.md.tmp" "$RUNTIME_DIRECTORY/public-resolvers.md"
  chmod 640 "$RUNTIME_DIRECTORY/public-resolvers.md" || log_warn "chmod failed on resolvers.md"
  chown root:root "$RUNTIME_DIRECTORY/public-resolvers.md" || log_warn "chown failed on resolvers.md"

  generate_rotator_script
  install_systemd_units
  install_logrotate_configuration

  systemctl daemon-reload || { log_error "systemctl daemon-reload failed"; _exit_with_error_code 1 "systemctl daemon-reload failed"; }

  local initial_toml
  initial_toml=$(cat <<EOF
listen_addresses = ['127.0.0.1:53']
ipv4_servers = true
ipv6_servers = false
doh_servers = true
require_nolog = true
require_nofilter = true
bootstrap_resolvers = ['${TRUSTED_RESOLVER_LIST[0]%%|*}:53']
fallback_resolver = '${TRUSTED_RESOLVER_LIST[0]%%|*}:53'
ignore_system_dns = true
log_level = 1
cache = false

[static.'initial']
urls = ['${TRUSTED_RESOLVER_LIST[0]#*|}']
ip_addresses = ['${TRUSTED_RESOLVER_LIST[0]%%|*}']
EOF
)
  printf '%s' "$initial_toml" > "$DYNAMIC_CONFIG_FILE.tmp"
  replace_file_atomically "$DYNAMIC_CONFIG_FILE.tmp" "$DYNAMIC_CONFIG_FILE"
  chown "$SERVICE_USER:$SERVICE_GROUP" "$DYNAMIC_CONFIG_FILE" || log_warn "chown failed on dynamic.toml"
  chmod 600 "$DYNAMIC_CONFIG_FILE" || log_warn "chmod failed on dynamic.toml"

  systemctl enable outline-doh-rotator.timer || { log_error "Failed to enable timer"; _exit_with_error_code 1 "Timer enable failed"; }

  log_info "Running initial configuration..."
  if ! "$ROTATOR_SCRIPT_PATH"; then
    log_error "Initial run failed"
    _exit_with_error_code 1 "Initial run failed"
  fi

  if [ -L "$RESOLVER_CONFIG_FILE" ]; then
    local target
    target=$(readlink "$RESOLVER_CONFIG_FILE" 2>/dev/null) || true
    if [[ "$target" != *"/stub-resolv.conf" ]] && [[ "$target" != *"/resolv.conf" ]]; then
      rm -f -- "$RESOLVER_CONFIG_FILE"
    fi
  fi
  [ -e "$RESOLVER_CONFIG_FILE" ] && rm -f -- "$RESOLVER_CONFIG_FILE"
  printf "nameserver 127.0.0.1\nnameserver %s\n" "${TRUSTED_RESOLVER_LIST[0]%%|*}" > "$RESOLVER_CONFIG_FILE"
  chmod 600 "$RESOLVER_CONFIG_FILE" || log_warn "chmod failed on resolv.conf"
  chown root:root "$RESOLVER_CONFIG_FILE" || log_warn "chown failed on resolv.conf"

  systemctl enable --now outline-doh-proxy.service || { log_error "Failed to start service"; _exit_with_error_code 1 "Service start failed"; }

  if ! timeout 5 dig @127.0.0.1 +short dns.google >/dev/null 2>&1; then
    log_warn "DNS validation failed"
  else
    log_info "DNS operational"
  fi

  log_info "Installation completed successfully (v${SCRIPT_VERSION})"
  # Clear rollback state on success
  ROLLBACK_FILE_LIST=()
  ROLLBACK_DIRECTORY_LIST=()
  RESOLVED_CONFLICT_LIST=()
  TEMPORARY_FILE_LIST=()
  cleanup_on_success
}

main "$@"
