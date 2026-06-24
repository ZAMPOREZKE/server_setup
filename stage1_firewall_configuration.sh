#!/usr/bin/env bash

set -Eeuo pipefail

SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
MIN_PORT="${MIN_PORT:-20000}"
MAX_PORT="${MAX_PORT:-65000}"
BACKUP_DIR="${BACKUP_DIR:-/etc/ssh}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-200}"
UFW_BEFORE_RULES="${UFW_BEFORE_RULES:-/etc/ufw/before.rules}"

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$EUID" -eq 0 ]] || die "Run as root: sudo ./run"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

sshd_config_files() {
  printf '%s\n' "$SSHD_CONFIG"
  awk '
    /^[[:space:]]*Include[[:space:]]+/ {
      for (i = 2; i <= NF; i++) print $i
    }
  ' "$SSHD_CONFIG" 2>/dev/null | while IFS= read -r pattern; do
    [[ -n "$pattern" ]] || continue
    for path in $pattern; do
      [[ -f "$path" ]] && printf '%s\n' "$path"
    done
  done
}

current_port() {
  local port=""
  local file
  while IFS= read -r file; do
    [[ -f "$file" ]] || continue
    port="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' "$file" || true)"
    if [[ -n "$port" ]]; then
      printf '%s\n' "$port"
      return 0
    fi
  done < <(sshd_config_files)
  printf '22\n'
}

check_port_conflicts_in_includes() {
  local new_port="$1"
  local file
  local conflicts=""
  while IFS= read -r file; do
    [[ -f "$file" ]] || continue
    [[ "$file" == "$SSHD_CONFIG" ]] && continue
    if awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{exit 0} END{exit 1}' "$file"; then
      conflicts+="$file "
    fi
    if awk '/^[[:space:]]*ListenAddress[[:space:]]+.*:[0-9]+/{exit 0} END{exit 1}' "$file"; then
      conflicts+="$file "
    fi
  done < <(sshd_config_files)

  if awk '/^[[:space:]]*ListenAddress[[:space:]]+.*:[0-9]+/{exit 0} END{exit 1}' "$SSHD_CONFIG"; then
    log "Warning: ListenAddress with explicit port is set in $SSHD_CONFIG. It may override Port $new_port."
    log "Review with: grep -nE '^[[:space:]]*ListenAddress' $SSHD_CONFIG"
  fi

  if [[ -n "$conflicts" ]]; then
    log "Warning: Port or ListenAddress:port directives found in SSH Include files:"
    log "  $conflicts"
    log "These may override Port $new_port. Inspect them manually if SSH binds to the wrong port."
  fi
}

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn "( sport = :$port )" 2>/dev/null | grep -q .
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | awk '{print $4}' | grep -E "[:.]$port$" >/dev/null 2>&1
  else
    die "Neither ss, lsof, nor netstat is available to check ports."
  fi
}

random_port() {
  local old_port="$1"
  local candidate
  local attempts=0

  while (( attempts < MAX_ATTEMPTS )); do
    candidate="$(shuf -i "${MIN_PORT}-${MAX_PORT}" -n 1)"
    if [[ "$candidate" != "$old_port" ]] && ! port_in_use "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
    ((attempts++))
  done

  return 1
}

update_sshd_port() {
  local new_port="$1"
  local tmp_file
  tmp_file="$(mktemp)"

  awk -v port="$new_port" '
    BEGIN { done = 0 }
    /^[[:space:]]*#?[[:space:]]*Port[[:space:]]+[0-9]+([[:space:]]+.*)?$/ {
      if (!done) {
        print "Port " port
        done = 1
      }
      next
    }
    { print }
    END {
      if (!done) {
        print "Port " port
      }
    }
  ' "$SSHD_CONFIG" > "$tmp_file"

  cat "$tmp_file" > "$SSHD_CONFIG"
  rm -f "$tmp_file"
}

validate_sshd_config() {
  if command -v sshd >/dev/null 2>&1; then
    sshd -t -f "$SSHD_CONFIG"
  elif [[ -x /usr/sbin/sshd ]]; then
    /usr/sbin/sshd -t -f "$SSHD_CONFIG"
  else
    die "sshd binary not found for config validation."
  fi
}

unit_exists() {
  systemctl cat "$1" >/dev/null 2>&1
}

configure_ssh_socket_activation() {
  local socket_unit=""
  local service_unit=""

  command -v systemctl >/dev/null 2>&1 || return 0

  if unit_exists ssh.socket; then
    socket_unit="ssh.socket"
    service_unit="ssh.service"
  elif unit_exists sshd.socket; then
    socket_unit="sshd.socket"
    service_unit="sshd.service"
  else
    return 0
  fi

  if systemctl is-enabled "$socket_unit" >/dev/null 2>&1 || \
     systemctl is-active "$socket_unit" >/dev/null 2>&1; then
    log "Detected socket activation via $socket_unit."
    log "Disabling $socket_unit so SSH port is controlled by $SSHD_CONFIG."
    systemctl disable --now "$socket_unit" || true
    systemctl stop "$socket_unit" 2>/dev/null || true
    systemctl daemon-reload || true
  fi

  if [[ -n "$service_unit" ]] && unit_exists "$service_unit"; then
    systemctl enable "$service_unit" >/dev/null 2>&1 || true
  fi
}

reload_ssh_service() {
  if command -v systemctl >/dev/null 2>&1; then
    local unit=""
    if unit_exists sshd.service; then
      unit="sshd"
    elif unit_exists ssh.service; then
      unit="ssh"
    fi

    if [[ -n "$unit" ]]; then
      systemctl stop "$unit" 2>/dev/null || true
      sleep 1
      if ! systemctl start "$unit"; then
        systemctl status "$unit" --no-pager -l || true
        die "Failed to start $unit. See 'systemctl status $unit' and 'journalctl -u $unit'."
      fi
      return 0
    fi
  fi

  if command -v service >/dev/null 2>&1; then
    if service ssh restart 2>/dev/null || \
       service sshd restart 2>/dev/null; then
      return 0
    fi
  fi

  die "Unable to detect SSH service. Restart it manually."
}

find_sshd_pids_on_port() {
  local port="$1"

  command -v ss >/dev/null 2>&1 || return 0

  ss -H -lntp "( sport = :$port )" 2>/dev/null | awk '
    /users:\(\("sshd"/ {
      while (match($0, /"sshd",pid=[0-9]+/)) {
        item = substr($0, RSTART, RLENGTH)
        sub(/.*pid=/, "", item)
        print item
        $0 = substr($0, RSTART + RLENGTH)
      }
    }
  ' | sort -u
}

clear_stale_old_port_listener() {
  local old_port="$1"
  local new_port="$2"
  local pid
  local killed_any=0

  [[ "$old_port" != "$new_port" ]] || return 0
  command -v ss >/dev/null 2>&1 || return 0

  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    if [[ "$killed_any" -eq 0 ]]; then
      log "Detected lingering sshd listener on old port $old_port. Sending TERM signal."
      killed_any=1
    fi
    kill -TERM "$pid" 2>/dev/null || true
  done < <(find_sshd_pids_on_port "$old_port")

  if [[ "$killed_any" -eq 1 ]]; then
    sleep 1
  fi
}

warn_if_old_port_still_used_by_sshd() {
  local old_port="$1"
  local new_port="$2"

  [[ "$old_port" != "$new_port" ]] || return 0
  command -v ss >/dev/null 2>&1 || return 0

  if ss -H -lntp "( sport = :$old_port )" 2>/dev/null | grep -q 'sshd'; then
    log "Warning: old SSH port $old_port is still listened by sshd. Check service state manually."
  fi
}

ensure_new_port_listener() {
  local new_port="$1"
  local waited=0
  local max_wait="${NEW_PORT_WAIT_SECONDS:-15}"

  command -v ss >/dev/null 2>&1 || return 0

  while (( waited < max_wait )); do
    if ss -H -lntp "( sport = :$new_port )" 2>/dev/null | grep -q 'sshd'; then
      return 0
    fi
    sleep 1
    ((waited++))
  done

  log "New SSH port $new_port is not listening after ${max_wait}s. Diagnostic info follows:"
  log "--- effective sshd config (Port/ListenAddress) ---"
  if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | grep -E '^(port|listenaddress)\b' || true
  fi
  log "--- ss -lntp (sshd/ssh/systemd listeners) ---"
  ss -lntp 2>/dev/null | grep -E 'sshd|ssh|systemd' || true
  log "--- systemctl status (ssh/sshd) ---"
  if command -v systemctl >/dev/null 2>&1; then
    for u in ssh.service sshd.service ssh.socket sshd.socket; do
      if unit_exists "$u"; then
        systemctl --no-pager -l status "$u" 2>/dev/null | head -n 20 || true
      fi
    done
  fi
  die "New SSH port $new_port is not listening after restart. See diagnostics above."
}

print_ssh_listeners() {
  if command -v ss >/dev/null 2>&1; then
    log "Current SSH listeners:"
    ss -lntp | grep ssh || true
  fi
}

harden_ufw_icmp_rules() {
  local rules_file="$UFW_BEFORE_RULES"
  local tmp_file
  local backup_file

  if ! command -v ufw >/dev/null 2>&1; then
    return 0
  fi

  if [[ ! -f "$rules_file" ]]; then
    log "Warning: $rules_file not found. Skipping ICMP hardening."
    return 0
  fi

  tmp_file="$(mktemp)"

  awk '
    BEGIN {
      in_input = 0
      in_forward = 0
      has_source_quench = 0
    }

    function flush_input_block() {
      if (in_input && !has_source_quench) {
        print "-A ufw-before-input -p icmp --icmp-type source-quench -j DROP"
        has_source_quench = 1
      }
      in_input = 0
    }

    /^# ok icmp codes for INPUT/ {
      flush_input_block()
      in_forward = 0
      in_input = 1
      has_source_quench = 0
      print
      next
    }

    /^# ok icmp code for FORWARD/ {
      flush_input_block()
      in_forward = 1
      print
      next
    }

    {
      if (in_input) {
        if ($0 ~ /^-A ufw-before-input -p icmp /) {
          line = $0
          gsub(/-j ACCEPT/, "-j DROP", line)
          if (line ~ /--icmp-type source-quench/) {
            has_source_quench = 1
          }
          print line
          next
        } else {
          flush_input_block()
        }
      }

      if (in_forward) {
        if ($0 ~ /^-A ufw-before-forward -p icmp /) {
          line = $0
          gsub(/-j ACCEPT/, "-j DROP", line)
          print line
          next
        } else {
          in_forward = 0
        }
      }

      print
    }

    END {
      flush_input_block()
    }
  ' "$rules_file" > "$tmp_file"

  if cmp -s "$rules_file" "$tmp_file"; then
    rm -f "$tmp_file"
    log "UFW ICMP hardening already applied."
    return 0
  fi

  backup_file="${rules_file}.bak.$(date +%Y%m%d_%H%M%S)"
  cp "$rules_file" "$backup_file"
  cat "$tmp_file" > "$rules_file"
  rm -f "$tmp_file"
  log "Updated ICMP rules in $rules_file (backup: $backup_file)"

  if ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ufw reload >/dev/null
    log "Reloaded UFW to apply ICMP changes."
  fi
}

maybe_open_firewall() {
  local new_port="$1"
  local old_port="$2"
  local ufw_status=""

  if command -v ufw >/dev/null 2>&1; then
    ufw_status="$(ufw status 2>/dev/null | awk '/^Status:/{print tolower($2); exit}')"

    if [[ "$ufw_status" != "active" ]]; then
      log "UFW is installed but inactive. Opening SSH and HTTP ports, then enabling UFW."
      ufw allow "${new_port}/tcp" >/dev/null
      ufw allow "${old_port}/tcp" >/dev/null || true
      ufw allow "80/tcp" >/dev/null
      ufw --force enable >/dev/null
      return 0
    fi

    log "UFW is active: opening $new_port/tcp and 80/tcp"
    ufw allow "${new_port}/tcp" >/dev/null
    ufw allow "${old_port}/tcp" >/dev/null || true
    ufw allow "80/tcp" >/dev/null
    log "Old port ${old_port}/tcp is kept temporarily for safe migration."
    return 0
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    log "firewalld is active: opening $new_port/tcp and 80/tcp"
    firewall-cmd --quiet --add-port="${new_port}/tcp"
    firewall-cmd --quiet --permanent --add-port="${new_port}/tcp"
    firewall-cmd --quiet --add-port="80/tcp"
    firewall-cmd --quiet --permanent --add-port="80/tcp"
    firewall-cmd --quiet --reload
  fi
}

main() {
  local old_port
  local new_port
  local backup

  require_root
  require_cmd awk
  require_cmd shuf
  require_cmd mktemp
  require_cmd date

  [[ -f "$SSHD_CONFIG" ]] || die "File not found: $SSHD_CONFIG"

  old_port="$(current_port)"
  new_port="$(random_port "$old_port")" || die "Could not pick a free random port."
  backup="${BACKUP_DIR%/}/sshd_config.bak.$(date +%Y%m%d_%H%M%S)"

  cp "$SSHD_CONFIG" "$backup"
  log "Backup created: $backup"
  log "Changing SSH port: $old_port -> $new_port"

  update_sshd_port "$new_port"

  if ! validate_sshd_config; then
    cp "$backup" "$SSHD_CONFIG"
    die "sshd_config validation failed. Restored from backup."
  fi

  check_port_conflicts_in_includes "$new_port"

  harden_ufw_icmp_rules
  maybe_open_firewall "$new_port" "$old_port"
  configure_ssh_socket_activation
  reload_ssh_service
  clear_stale_old_port_listener "$old_port" "$new_port"
  warn_if_old_port_still_used_by_sshd "$old_port" "$new_port"
  ensure_new_port_listener "$new_port"
  print_ssh_listeners

  cat <<EOF
Done.
SSH port changed: $old_port -> $new_port
Backup: $backup

Test login in a new session:
ssh -p $new_port <user>@<server_ip>
EOF
}

main "$@"
