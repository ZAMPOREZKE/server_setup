#!/usr/bin/env bash
set -Eeuo pipefail

# stage2_server_setup.sh v2.2
# Safe post-SSH-port-change hardening for Debian/Ubuntu VPS.
#
# Fix in v2.2:
# - Fixes awk syntax error caused by multi-line `return (...)` in is_loopback().
# - Keeps localhost-only sshd listeners like 127.0.0.1:6010 / [::1]:6010 out of public SSH port detection.
# - Runs a small apt/dpkg preflight before package installation on apt-based systems.
#
# What it does:
# - Ensures /run/sshd exists, so sshd config validation does not fail.
# - Detects public SSH port(s) from sshd config and non-loopback sshd listeners.
# - Validates SSH config before touching SSH service.
# - Installs basic admin/security packages.
# - Enables UFW safely and keeps current SSH + HTTP/HTTPS open.
# - Optionally removes stale old SSH UFW rules like 22/tcp or previous random ports.
# - Enables fail2ban for the detected public SSH port(s).
# - Enables unattended security updates.
# - Applies conservative sysctl network hardening.
# - Adds conservative SSH hardening that should not lock you out.
#
# Usage:
#   bash stage2_server_setup.sh
#   bash stage2_server_setup.sh --yes
#
# Useful env vars:
#   CLEAN_OLD_SSH_PORTS=1     Remove stale SSH-looking UFW rules without asking.
#   OPEN_HTTP=1               Keep/open 80/tcp. Default: 1
#   OPEN_HTTPS=1              Keep/open 443/tcp. Default: 1
#   INSTALL_PACKAGES=1        Install baseline packages. Default: 1
#   ENABLE_FAIL2BAN=1         Configure fail2ban. Default: 1
#   ENABLE_AUTO_UPDATES=1     Configure unattended-upgrades. Default: 1
#   APPLY_SYSCTL=1            Apply network sysctl hardening. Default: 1
#   APPLY_SSH_HARDENING=1     Apply conservative sshd hardening. Default: 1

YES=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes)
      YES=1
      ;;
    -h|--help)
      sed -n '1,55p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

OPEN_HTTP="${OPEN_HTTP:-1}"
OPEN_HTTPS="${OPEN_HTTPS:-1}"
INSTALL_PACKAGES="${INSTALL_PACKAGES:-1}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-1}"
ENABLE_AUTO_UPDATES="${ENABLE_AUTO_UPDATES:-1}"
APPLY_SYSCTL="${APPLY_SYSCTL:-1}"
APPLY_SSH_HARDENING="${APPLY_SSH_HARDENING:-1}"
CLEAN_OLD_SSH_PORTS="${CLEAN_OLD_SSH_PORTS:-0}"

SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
SSHD_HARDENING_DROPIN="${SSHD_HARDENING_DROPIN:-/etc/ssh/sshd_config.d/99-stage2-hardening.conf}"
SYSCTL_DROPIN="${SYSCTL_DROPIN:-/etc/sysctl.d/99-stage2-network-hardening.conf}"
FAIL2BAN_JAIL="${FAIL2BAN_JAIL:-/etc/fail2ban/jail.d/sshd-stage2.local}"

MIN_RANDOM_SSH_PORT="${MIN_RANDOM_SSH_PORT:-20000}"
MAX_RANDOM_SSH_PORT="${MAX_RANDOM_SSH_PORT:-65000}"

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

as_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root."
}

have() {
  command -v "$1" >/dev/null 2>&1
}

confirm() {
  local prompt="$1"

  if [[ "$YES" -eq 1 ]]; then
    return 0
  fi

  local ans
  read -r -p "$prompt [y/N]: " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

detect_pkg_manager() {
  if have apt-get; then
    echo "apt"
  elif have dnf; then
    echo "dnf"
  elif have yum; then
    echo "yum"
  else
    echo "unknown"
  fi
}

ensure_run_sshd() {
  install -d -o root -g root -m 0755 /run/sshd
}

sshd_bin() {
  if have sshd; then
    command -v sshd
  elif [[ -x /usr/sbin/sshd ]]; then
    echo /usr/sbin/sshd
  else
    die "sshd binary not found."
  fi
}

validate_sshd() {
  ensure_run_sshd
  "$(sshd_bin)" -t -f "$SSHD_CONFIG"
}

ssh_service_units() {
  local units=()

  if have systemctl; then
    systemctl cat ssh.service >/dev/null 2>&1 && units+=("ssh.service")
    systemctl cat sshd.service >/dev/null 2>&1 && units+=("sshd.service")
  fi

  printf '%s\n' "${units[@]}"
}

reload_ssh_safely() {
  validate_sshd

  if have systemctl; then
    local unit
    while IFS= read -r unit; do
      [[ -n "$unit" ]] || continue
      log "Reloading $unit"
      systemctl reload "$unit" 2>/dev/null || systemctl restart "$unit"
      return 0
    done < <(ssh_service_units)
  fi

  if have service; then
    service ssh reload 2>/dev/null || service ssh restart 2>/dev/null || \
      service sshd reload 2>/dev/null || service sshd restart 2>/dev/null || \
      die "Could not reload/restart SSH service."
    return 0
  fi

  die "Could not detect SSH service manager."
}

configured_ssh_ports() {
  ensure_run_sshd

  if [[ -f "$SSHD_CONFIG" ]]; then
    "$(sshd_bin)" -T -f "$SSHD_CONFIG" 2>/dev/null \
      | awk '/^port / && $2 ~ /^[0-9]+$/ {print $2}' \
      | sort -n -u
  fi
}

external_sshd_listener_ports() {
  have ss || return 0

  # Important:
  # sshd may create localhost-only listeners such as 127.0.0.1:6010 / [::1]:6010
  # for X11 forwarding or tunnels. Those are NOT public SSH login ports.
  # We only keep non-loopback listeners here.
  ss -H -ltnp 2>/dev/null \
    | awk '
        function split_addr_port(s) {
          bind = s
          port = s

          if (s ~ /^\[/) {
            bind = s
            sub(/^\[/, "", bind)
            sub(/\]:[0-9]+$/, "", bind)

            port = s
            sub(/^.*\]:/, "", port)
          } else {
            bind = s
            sub(/:[0-9]+$/, "", bind)

            port = s
            sub(/^.*:/, "", port)
          }
        }

        function is_loopback(a) {
          return (a == "localhost" || a ~ /^127\./ || a == "::1" || a ~ /^::ffff:127\./)
        }

        /users:\(\("sshd"/ {
          split_addr_port($4)
          if (port ~ /^[0-9]+$/ && !is_loopback(bind)) {
            print port
          }
        }
      ' \
    | sort -n -u
}

effective_ssh_ports() {
  local ports=()

  # Primary source: effective sshd config.
  # This avoids confusing sshd child-process forwarding listeners with the real login port.
  while IFS= read -r p; do
    [[ "$p" =~ ^[0-9]+$ ]] && ports+=("$p")
  done < <(configured_ssh_ports || true)

  # Secondary source: public/non-loopback live sshd listeners.
  # This helps on hosts where systemd socket activation or a custom service is involved.
  while IFS= read -r p; do
    [[ "$p" =~ ^[0-9]+$ ]] && ports+=("$p")
  done < <(external_sshd_listener_ports || true)

  # Fallback to configured Port lines if sshd -T failed for some unexpected reason.
  if [[ ${#ports[@]} -eq 0 && -f "$SSHD_CONFIG" ]]; then
    while IFS= read -r p; do
      [[ "$p" =~ ^[0-9]+$ ]] && ports+=("$p")
    done < <(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2}' "$SSHD_CONFIG" || true)
  fi

  if [[ ${#ports[@]} -eq 0 ]]; then
    ports=("22")
  fi

  printf '%s\n' "${ports[@]}" | sort -n -u
}

list_sshd_listeners() {
  if have ss; then
    ss -ltnp | grep -E 'sshd|ssh' || true
  else
    log "ss not found; cannot display listeners."
  fi
}

list_public_sshd_ports() {
  effective_ssh_ports | paste -sd' ' -
}

port_is_listening() {
  local port="$1"

  have ss || return 1
  ss -H -ltn "( sport = :$port )" 2>/dev/null | grep -q .
}

port_has_only_loopback_sshd_listener() {
  local port="$1"

  have ss || return 1

  local result
  result="$(
    ss -H -ltnp "( sport = :$port )" 2>/dev/null \
      | awk '
          function split_addr_port(s) {
            bind = s

            if (s ~ /^\[/) {
              sub(/^\[/, "", bind)
              sub(/\]:[0-9]+$/, "", bind)
            } else {
              sub(/:[0-9]+$/, "", bind)
            }
          }

          function is_loopback(a) {
            return (a == "localhost" || a ~ /^127\./ || a == "::1" || a ~ /^::ffff:127\./)
          }

          BEGIN {
            sshd = 0
            loopback = 0
            nonloopback = 0
            other = 0
          }

          {
            if ($0 ~ /users:\(\("sshd"/) {
              sshd = 1
              split_addr_port($4)

              if (is_loopback(bind)) {
                loopback = 1
              } else {
                nonloopback = 1
              }
            } else {
              other = 1
            }
          }

          END {
            if (sshd && loopback && !nonloopback && !other) {
              print "ONLY_LOOPBACK_SSHD"
            } else {
              print "NO"
            }
          }
        '
  )"

  [[ "$result" == "ONLY_LOOPBACK_SSHD" ]]
}

apt_preflight() {
  have apt-get || return 0

  export DEBIAN_FRONTEND=noninteractive

  if have dpkg; then
    log "Running dpkg preflight"
    dpkg --configure -a
  fi

  log "Fixing apt dependencies if needed"
  apt-get -f install -y
}

install_baseline_packages() {
  [[ "$INSTALL_PACKAGES" -eq 1 ]] || return 0

  local pm
  pm="$(detect_pkg_manager)"

  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt_preflight

      log "Updating apt package index"
      apt-get update -y

      log "Installing baseline packages"
      apt-get install -y \
        ca-certificates curl wget gnupg lsb-release \
        ufw fail2ban unattended-upgrades apt-listchanges \
        htop nano vim git jq unzip tar rsync \
        net-tools iproute2 dnsutils
      ;;
    dnf)
      log "Installing baseline packages with dnf"
      dnf install -y \
        ca-certificates curl wget gnupg2 \
        firewalld fail2ban \
        htop nano vim git jq unzip tar rsync \
        net-tools iproute bind-utils
      ;;
    yum)
      log "Installing baseline packages with yum"
      yum install -y \
        ca-certificates curl wget gnupg2 \
        firewalld fail2ban \
        htop nano vim git jq unzip tar rsync \
        net-tools iproute bind-utils
      ;;
    *)
      log "No supported package manager found; skipping package installation."
      ;;
  esac
}

configure_ufw() {
  have ufw || {
    log "UFW not found; skipping UFW configuration."
    return 0
  }

  local ssh_ports=()
  mapfile -t ssh_ports < <(effective_ssh_ports)

  log "Configuring UFW"
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null

  local p
  for p in "${ssh_ports[@]}"; do
    log "Allowing public SSH port: ${p}/tcp"
    ufw allow "${p}/tcp" >/dev/null
  done

  if [[ "$OPEN_HTTP" -eq 1 ]]; then
    ufw allow 80/tcp >/dev/null
  fi

  if [[ "$OPEN_HTTPS" -eq 1 ]]; then
    ufw allow 443/tcp >/dev/null
  fi

  if ! ufw status | grep -qi '^Status: active'; then
    log "Enabling UFW"
    ufw --force enable >/dev/null
  else
    ufw reload >/dev/null || true
  fi
}

ufw_allowed_tcp_ports() {
  have ufw || return 0

  ufw status 2>/dev/null \
    | awk '
        $1 ~ /^[0-9]+\/tcp$/ && $2 == "ALLOW" {
          sub(/\/tcp$/, "", $1)
          print $1
        }
      ' \
    | sort -n -u
}

in_array() {
  local needle="$1"
  shift

  local x
  for x in "$@"; do
    [[ "$x" == "$needle" ]] && return 0
  done

  return 1
}

cleanup_buggy_local_sshd_ufw_rules() {
  have ufw || return 0

  local keep_ports=()
  mapfile -t keep_ports < <(effective_ssh_ports)

  [[ "$OPEN_HTTP" -eq 1 ]] && keep_ports+=("80")
  [[ "$OPEN_HTTPS" -eq 1 ]] && keep_ports+=("443")

  local p
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    in_array "$p" "${keep_ports[@]}" && continue

    if port_has_only_loopback_sshd_listener "$p"; then
      log "Removing buggy UFW rule for localhost-only sshd listener: ${p}/tcp"
      ufw --force delete allow "${p}/tcp" >/dev/null 2>&1 || true
    fi
  done < <(ufw_allowed_tcp_ports)

  ufw reload >/dev/null || true
}

cleanup_stale_ufw_ssh_rules() {
  have ufw || return 0

  # Always clean the previous v2.0 bug automatically:
  # localhost-only sshd forwarding ports must never be opened publicly.
  cleanup_buggy_local_sshd_ufw_rules

  local keep_ports=()
  mapfile -t keep_ports < <(effective_ssh_ports)

  [[ "$OPEN_HTTP" -eq 1 ]] && keep_ports+=("80")
  [[ "$OPEN_HTTPS" -eq 1 ]] && keep_ports+=("443")

  local candidates=()
  local p

  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    in_array "$p" "${keep_ports[@]}" && continue

    # Only touch obvious SSH-migration leftovers:
    # - 22/tcp
    # - random high ports in the same range as the first setup script
    if [[ "$p" == "22" || ( "$p" -ge "$MIN_RANDOM_SSH_PORT" && "$p" -le "$MAX_RANDOM_SSH_PORT" ) ]]; then
      # Do not delete if something is actually listening on that port.
      if port_is_listening "$p"; then
        log "Keeping ${p}/tcp because something is listening on it."
        continue
      fi

      candidates+=("$p")
    fi
  done < <(ufw_allowed_tcp_ports)

  if [[ ${#candidates[@]} -eq 0 ]]; then
    log "No stale SSH-looking UFW rules found."
    return 0
  fi

  log "Stale SSH-looking UFW rules detected: ${candidates[*]}"
  log "Current keep-list: ${keep_ports[*]}"

  if [[ "$CLEAN_OLD_SSH_PORTS" -eq 1 ]] || confirm "Delete these stale UFW allow rules: ${candidates[*]} ?"; then
    for p in "${candidates[@]}"; do
      log "Deleting UFW rule: allow ${p}/tcp"
      ufw --force delete allow "${p}/tcp" >/dev/null 2>&1 || true
    done
    ufw reload >/dev/null || true
  else
    log "Skipped stale UFW rule cleanup."
  fi
}

configure_fail2ban() {
  [[ "$ENABLE_FAIL2BAN" -eq 1 ]] || return 0

  have fail2ban-server || {
    log "fail2ban is not installed; skipping."
    return 0
  }

  local ssh_ports_csv
  ssh_ports_csv="$(effective_ssh_ports | paste -sd, -)"

  mkdir -p /etc/fail2ban/jail.d

  cat > "$FAIL2BAN_JAIL" <<EOF
[sshd]
enabled = true
port = ${ssh_ports_csv}
filter = sshd
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF

  log "Configured fail2ban SSH jail for public port(s): ${ssh_ports_csv}"

  if have systemctl; then
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban || {
      log "fail2ban restart failed; showing status."
      systemctl status fail2ban --no-pager -l || true
      return 0
    }
  else
    service fail2ban restart 2>/dev/null || true
  fi
}

configure_auto_updates() {
  [[ "$ENABLE_AUTO_UPDATES" -eq 1 ]] || return 0

  if ! have apt-get; then
    log "Automatic security updates block is apt-specific; skipping."
    return 0
  fi

  mkdir -p /etc/apt/apt.conf.d

  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  log "Enabled unattended apt upgrades."
}

apply_sysctl_hardening() {
  [[ "$APPLY_SYSCTL" -eq 1 ]] || return 0

  cat > "$SYSCTL_DROPIN" <<'EOF'
# Conservative network hardening.
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF

  log "Applying sysctl hardening"
  sysctl --system >/dev/null || log "sysctl --system returned non-zero; review ${SYSCTL_DROPIN}"
}

apply_ssh_hardening() {
  [[ "$APPLY_SSH_HARDENING" -eq 1 ]] || return 0

  mkdir -p /etc/ssh/sshd_config.d

  cat > "$SSHD_HARDENING_DROPIN" <<'EOF'
# Conservative SSH hardening.
# This file intentionally does NOT disable root login or password login,
# because doing that automatically can lock you out.
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
EOF

  log "Validating SSH config after hardening"
  validate_sshd
  reload_ssh_safely
}

print_summary() {
  local ssh_ports
  ssh_ports="$(effective_ssh_ports | paste -sd' ' -)"

  echo
  echo "================ STAGE 2 COMPLETE ================"
  echo "Public SSH port(s): ${ssh_ports}"
  echo
  echo "SSH listeners:"
  list_sshd_listeners
  echo

  if have ufw; then
    echo "UFW status:"
    ufw status
    echo
  fi

  if have fail2ban-client; then
    echo "fail2ban status:"
    fail2ban-client status sshd 2>/dev/null || fail2ban-client status 2>/dev/null || true
    echo
  fi

  echo "Test login from a NEW terminal before closing this session:"
  local p
  for p in ${ssh_ports}; do
    echo "  ssh -p ${p} root@YOUR_SERVER_IP"
  done
  echo "=================================================="
}

main() {
  as_root
  [[ -f "$SSHD_CONFIG" ]] || die "Missing ${SSHD_CONFIG}"

  log "Stage 2 server setup started."

  ensure_run_sshd
  validate_sshd

  log "Detected public SSH port(s): $(list_public_sshd_ports)"
  log "Current SSH-related listeners:"
  list_sshd_listeners

  install_baseline_packages
  configure_ufw
  cleanup_stale_ufw_ssh_rules
  configure_fail2ban
  configure_auto_updates
  apply_sysctl_hardening
  apply_ssh_hardening
  print_summary
}

main "$@"
