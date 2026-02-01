#!/usr/bin/env bash
set -euo pipefail

# =========================
# CONFIG
# =========================
MAIN_USER="support"
CLOUD_USER="clouduser"
TZ="Asia/Jakarta"
ENV_FILE="/etc/hss_env"                 # edit ini untuk ganti ENV (default production)

CACHE_FILE="/var/cache/hss-motd.cache"
CACHE_TTL_SECONDS=300                   # 5 menit
REFRESH_SCRIPT="/usr/local/sbin/hss-motd-refresh"

SSHD_CFG="/etc/ssh/sshd_config"

# Central activity log
LOG_DIR="/var/log_activity"
CMD_LOG="${LOG_DIR}/command-history.log"
SUDO_LOG_NEW="${LOG_DIR}/sudo.log"
SUDO_LOG_OLD="/var/log/sudo.log"

# SSH hardening
SSH_PORT="62"

echo "[+] Starting Ubuntu 24.04 setup..."

# =========================
# Helpers
# =========================
ensure_sshd_kv () {
  local key="$1" value="$2"
  if grep -qE "^[#\s]*${key}\b" "${SSHD_CFG}"; then
    sed -i -E "s|^[#\s]*${key}\b.*|${key} ${value}|g" "${SSHD_CFG}"
  else
    echo "${key} ${value}" >> "${SSHD_CFG}"
  fi
}

gen_random_password () {
  # 20 chars, safe-ish for terminals, no ambiguous chars requirement not specified
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 36 | tr -d '/+=\n' | head -c 20
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20
  fi
}

# =========================
# 0) Ensure main user exists
# =========================
if id -u "${MAIN_USER}" >/dev/null 2>&1; then
  echo "[+] User '${MAIN_USER}' already exists"
else
  echo "[+] Creating user '${MAIN_USER}'..."
  adduser --disabled-password --gecos "" "${MAIN_USER}"
  echo "[!] Set password for ${MAIN_USER}:"
  passwd "${MAIN_USER}"
fi

if ! id -nG "${MAIN_USER}" | grep -qw sudo; then
  echo "[+] Adding '${MAIN_USER}' to sudo group..."
  usermod -aG sudo "${MAIN_USER}"
fi

# =========================
# 0b) Ensure cloud sudo user exists (clouduser) + ALWAYS ROTATE password (no prompt)
# =========================
CLOUDUSER_PASS=""

if id -u "${CLOUD_USER}" >/dev/null 2>&1; then
  echo "[+] User '${CLOUD_USER}' already exists"
else
  echo "[+] Creating sudo user '${CLOUD_USER}'..."
  adduser --disabled-password --gecos "" "${CLOUD_USER}"
  usermod -aG sudo "${CLOUD_USER}"
  echo "[+] '${CLOUD_USER}' added to sudo group"
fi

echo "[+] Rotating password for '${CLOUD_USER}' (random, no prompt)..."
CLOUDUSER_PASS="$(gen_random_password)"
echo "${CLOUD_USER}:${CLOUDUSER_PASS}" | chpasswd

# Store creds securely for admin retrieval (overwrite each run)
install -d -m 0700 /root
{
  echo "username=${CLOUD_USER}"
  echo "password=${CLOUDUSER_PASS}"
  echo "rotated_at=$(date '+%F %T %Z')"
} > /root/clouduser.credentials
chmod 0600 /root/clouduser.credentials

# =========================
# 1) Timezone Asia/Jakarta
# =========================
echo "[+] Setting timezone to ${TZ}..."
timedatectl set-timezone "${TZ}"

# =========================
# 2) Install latest Docker + Compose (official Docker repo)
# =========================
echo "[+] Installing Docker Engine (official repo) + Docker Compose plugin..."

apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release apt-transport-https

install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
fi

CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
ARCH="$(dpkg --print-architecture)"

cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable
EOF

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

echo "[+] Adding '${MAIN_USER}' to docker group..."
groupadd -f docker
usermod -aG docker "${MAIN_USER}"

# =========================
# Install netstat (net-tools)
# =========================
echo "[+] Installing netstat (net-tools)..."
apt-get install -y net-tools

# =========================
# 3) Logging activity (auditd execve + history timestamps)
# =========================
echo "[+] Enabling activity logging (auditd execve + history timestamps)..."

apt-get install -y auditd audispd-plugins

cp -a /etc/audit/auditd.conf /etc/audit/auditd.conf.bak.$(date +%F_%H%M%S) || true
grep -q '^max_log_file' /etc/audit/auditd.conf || echo 'max_log_file = 20' >> /etc/audit/auditd.conf
grep -q '^num_logs' /etc/audit/auditd.conf || echo 'num_logs = 7' >> /etc/audit/auditd.conf
grep -q '^max_log_file_action' /etc/audit/auditd.conf || echo 'max_log_file_action = ROTATE' >> /etc/audit/auditd.conf

cat >/etc/audit/rules.d/99-execve.rules <<'EOF'
-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=4294967295 -k execve_all
-a always,exit -F arch=b32 -S execve,execveat -F auid>=1000 -F auid!=4294967295 -k execve_all
EOF

augenrules --load
systemctl enable --now auditd

cat >/etc/profile.d/00-history-timestamps.sh <<'EOF'
export HISTTIMEFORMAT='%F %T %Z '
export HISTSIZE=50000
export HISTFILESIZE=100000
export HISTCONTROL=ignoredups:erasedups
shopt -s histappend
PROMPT_COMMAND="history -a; history -n; ${PROMPT_COMMAND:-:}"
EOF
chmod 0644 /etc/profile.d/00-history-timestamps.sh

# =========================
# 4) Compliance Banner + Dynamic MOTD with CACHE (ISO 27001 / SOC2 style)
# =========================
echo "[+] Setting SSH pre-login banner (/etc/issue.net) + Dynamic MOTD (cached)..."

# ENV file (editable)
if [ ! -f "${ENV_FILE}" ]; then
  cat >"${ENV_FILE}" <<'EOF'
# Edit this file to set environment label shown in MOTD
ENVIRONMENT="production"
EOF
  chmod 0644 "${ENV_FILE}"
fi

# SSH pre-login banner
cat >/etc/issue.net <<'EOF'
**********************************************************************
*  AUTHORIZED ACCESS ONLY                                            *
*                                                                    *
*  This system is for the use of authorized users only.              *
*  Individuals using this computer system without authority, or in   *
*  excess of their authority, are subject to monitoring and logging. *
*                                                                    *
*  By proceeding, you acknowledge and consent to:                    *
*    - Security monitoring and audit logging                         *
*    - Access control enforcement                                    *
*    - Incident response procedures                                  *
*                                                                    *
*  Compliance: ISO/IEC 27001 • SOC 2                                 *
*  By: hssolution.online                                             *
**********************************************************************
EOF
chmod 0644 /etc/issue.net

# Ensure sshd shows banner + uses PAM MOTD
cp -a "${SSHD_CFG}" "${SSHD_CFG}.bak.$(date +%F_%H%M%S)" || true
ensure_sshd_kv "Banner" "/etc/issue.net"
ensure_sshd_kv "UsePAM" "yes"
ensure_sshd_kv "PrintMotd" "no"

# ---- Create refresh script that generates MOTD content into cache ----
apt-get install -y util-linux coreutils

install -d -m 0755 /usr/local/sbin
cat > "${REFRESH_SCRIPT}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/hss_env"
CACHE_FILE="/var/cache/hss-motd.cache"
TMP_FILE="$(mktemp)"
mkdir -p /var/cache

ENVIRONMENT="unknown"
if [ -f "${ENV_FILE}" ]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}" || true
fi

HOST="$(hostname -f 2>/dev/null || hostname)"
LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -z "${LOCAL_IP:-}" ]; then
  LOCAL_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
fi

PUBLIC_IP="$(curl -fsS --max-time 2 https://ifconfig.me 2>/dev/null || true)"
if [ -z "${PUBLIC_IP}" ]; then
  PUBLIC_IP="$(curl -fsS --max-time 2 https://api.ipify.org 2>/dev/null || true)"
fi
[ -n "${PUBLIC_IP}" ] || PUBLIC_IP="unavailable"

ROOT_FREE="$(df -h / | awk 'NR==2 {print $4 " free of " $2 " (" $5 " used)"}')"

CPU_MODEL="$(lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^[ \t]+/,"",$2); print $2; exit}')"
CPU_CORES="$(nproc 2>/dev/null || echo "?")"
[ -n "${CPU_MODEL}" ] || CPU_MODEL="unknown"

MEM_TOTAL="$(free -h 2>/dev/null | awk '/Mem:/ {print $2}')"
MEM_USED="$(free -h 2>/dev/null | awk '/Mem:/ {print $3}')"
[ -n "${MEM_TOTAL}" ] || MEM_TOTAL="unknown"
[ -n "${MEM_USED}" ] || MEM_USED="unknown"

NOW="$(date '+%F %T %Z')"

USERS_LOGGED_IN="$(who | awk '{print $1}' | sort -u | tr '\n' ' ')"
[ -n "${USERS_LOGGED_IN}" ] || USERS_LOGGED_IN="none"

cat > "${TMP_FILE}" <<BANNER
======================================================================
  COMPLIANCE NOTICE (ISO/IEC 27001 • SOC 2) — tertanda: hssolution.online
----------------------------------------------------------------------
  Authorized access only. All activities may be monitored and logged.
======================================================================

  System        : ${HOST}
  Environment   : ${ENVIRONMENT}
  Time          : ${NOW}

  Network
    - Public IP : ${PUBLIC_IP}
    - Local  IP : ${LOCAL_IP:-unavailable}

  Storage
    - Root Disk : ${ROOT_FREE}

  CPU
    - Model     : ${CPU_MODEL}
    - Cores     : ${CPU_CORES}

  Memory
    - Used      : ${MEM_USED}
    - Total     : ${MEM_TOTAL}

  Sessions
    - Users Logged In : ${USERS_LOGGED_IN}

======================================================================

BANNER

install -m 0644 "${TMP_FILE}" "${CACHE_FILE}"
rm -f "${TMP_FILE}"
EOF
chmod 0755 "${REFRESH_SCRIPT}"

mkdir -p /var/cache
"${REFRESH_SCRIPT}" || true

MOTD_SCRIPT="/etc/update-motd.d/99-hssolution"
cat > "${MOTD_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

CACHE_FILE="${CACHE_FILE}"
TTL=${CACHE_TTL_SECONDS}
REFRESH="${REFRESH_SCRIPT}"

if [ -f "\${CACHE_FILE}" ]; then
  cat "\${CACHE_FILE}"
else
  cat <<'FALLBACK'
======================================================================
  COMPLIANCE NOTICE (ISO/IEC 27001 • SOC 2) — by hssolution.online
----------------------------------------------------------------------
  Authorized access only. All activities may be monitored and logged.
======================================================================

  MOTD cache is not available yet. Refresh scheduled.

======================================================================

FALLBACK
fi

need_refresh=1
if [ -f "\${CACHE_FILE}" ]; then
  now=\$(date +%s)
  mtime=\$(stat -c %Y "\${CACHE_FILE}" 2>/dev/null || echo 0)
  age=\$(( now - mtime ))
  if [ "\${age}" -lt "\${TTL}" ]; then
    need_refresh=0
  fi
fi

if [ "\${need_refresh}" -eq 1 ]; then
  ( "\${REFRESH}" >/dev/null 2>&1 || true ) &
fi
EOF
chmod 0755 "${MOTD_SCRIPT}"

cat >/etc/systemd/system/hss-motd-refresh.service <<EOF
[Unit]
Description=Refresh cached dynamic MOTD (hssolution.online)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${REFRESH_SCRIPT}
EOF

cat >/etc/systemd/system/hss-motd-refresh.timer <<'EOF'
[Unit]
Description=Periodic refresh for cached dynamic MOTD (hssolution.online)

[Timer]
OnBootSec=30s
OnUnitActiveSec=2min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now hss-motd-refresh.timer

# Disable default Ubuntu MOTD parts
echo "[+] Disabling default Ubuntu MOTD components..."
if [ -d /etc/update-motd.d ]; then
  for f in /etc/update-motd.d/*; do
    case "$(basename "$f")" in
      99-hssolution) : ;;
      *) chmod -x "$f" || true ;;
    esac
  done
fi
sed -i 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news 2>/dev/null || true

# =========================
# 5) SSH port -> 62 + UFW + Fail2ban
# =========================
echo "[+] Hardening SSH: port 22 -> ${SSH_PORT}, configure UFW and Fail2ban..."

# --- SSH port change ---
cp -a "${SSHD_CFG}" "${SSHD_CFG}.bak.$(date +%F_%H%M%S)" || true
ensure_sshd_kv "Port" "${SSH_PORT}"

# Keep banner + PAM MOTD (already set above), keep PrintMotd no
ensure_sshd_kv "UsePAM" "yes"
ensure_sshd_kv "PrintMotd" "no"
ensure_sshd_kv "Banner" "/etc/issue.net"

# --- UFW rules ---
apt-get install -y ufw

# Baseline (idempotent)
ufw default deny incoming || true
ufw default allow outgoing || true

# Allow NEW SSH port first (prevent lockout)
ufw allow "${SSH_PORT}/tcp" comment "SSH on ${SSH_PORT}" || true

# (Optional) remove old SSH rule if exists
ufw delete allow 22/tcp >/dev/null 2>&1 || true
ufw delete allow OpenSSH >/dev/null 2>&1 || true

# Enable ufw (non-interactive)
ufw --force enable || true

# --- Fail2ban ---
apt-get install -y fail2ban

# Configure jail for sshd on port 62
cat >/etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
backend = systemd
maxretry = 5
findtime = 10m
bantime  = 15m
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban || true

# =========================
# 6) SSH-only: auto logout after idle 15 minutes
# =========================
echo "[+] Enabling SSH-only idle logout (15 minutes)..."

cat >/etc/profile.d/99-ssh-idle-timeout.sh <<'EOF'
# Auto logout after 15 minutes idle - ONLY for SSH sessions
if [ -n "${SSH_CONNECTION:-}" ]; then
  TMOUT=900
  readonly TMOUT
  export TMOUT
fi
EOF
chmod 0644 /etc/profile.d/99-ssh-idle-timeout.sh

# sshd keepalive: 300s x 3 = 900s
ensure_sshd_kv "ClientAliveInterval" "300"
ensure_sshd_kv "ClientAliveCountMax" "3"

# =========================
# 7) Central command history logging to /var/log_activity (ALL USERS incl. root) + 7-day retention
# =========================
echo "[+] Enabling central command history logging to ${LOG_DIR} (7-day retention)..."

install -d -m 0750 "${LOG_DIR}"
touch "${CMD_LOG}"
chmod 0640 "${CMD_LOG}"
chown root:adm "${LOG_DIR}" 2>/dev/null || true
chown root:adm "${CMD_LOG}" 2>/dev/null || true

cat >/etc/profile.d/98-hss-command-history.sh <<EOF
# Central command history logger (ISO/SOC2-style)
# Logs to: ${CMD_LOG}
# Interactive shells only.

if [[ "\$-" == *i* ]]; then
  export HSS_CMDLOG="${CMD_LOG}"
  export HSS_LAST_HISTNUM="\${HSS_LAST_HISTNUM:-}"

  __hss_log_cmd() {
    local rc="\$?"
    local hline histnum cmd
    hline="\$(history 1 2>/dev/null | sed 's/^[ ]*//')"
    histnum="\$(echo "\$hline" | awk '{print \$1}')"
    cmd="\$(echo "\$hline" | sed 's/^[ ]*[0-9]\\+[ ]*//')"

    if [ -z "\${histnum}" ] || [ "\${histnum}" = "\${HSS_LAST_HISTNUM}" ]; then
      return 0
    fi
    export HSS_LAST_HISTNUM="\${histnum}"

    local ts user uid tty pwd ssh
    ts="\$(date '+%F %T %Z')"
    user="\${USER:-\$(id -un)}"
    uid="\$(id -u 2>/dev/null || echo '?')"
    tty="\$(tty 2>/dev/null || echo '?')"
    pwd="\${PWD:-?}"
    ssh="\${SSH_CONNECTION:-}"

    mkdir -p "${LOG_DIR}" 2>/dev/null || true

    printf '%s user=%s uid=%s tty=%s pwd=%q ssh=%q rc=%s cmd=%q\\n' \
      "\$ts" "\$user" "\$uid" "\$tty" "\$pwd" "\$ssh" "\$rc" "\$cmd" >> "\${HSS_CMDLOG}" 2>/dev/null || true
  }

  case "\${PROMPT_COMMAND:-}" in
    *__hss_log_cmd*) : ;;
    "") PROMPT_COMMAND="__hss_log_cmd" ;;
    *)  PROMPT_COMMAND="__hss_log_cmd; \${PROMPT_COMMAND}" ;;
  esac
fi
EOF
chmod 0644 /etc/profile.d/98-hss-command-history.sh

apt-get install -y logrotate
cat >/etc/logrotate.d/hss-log-activity <<EOF
${CMD_LOG} {
  daily
  rotate 7
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
  create 0640 root adm
}
EOF
chmod 0644 /etc/logrotate.d/hss-log-activity

# =========================
# 8) Sudo log relocate to /var/log_activity + symlink + logrotate 7 days (safe)
# =========================
echo "[+] Relocating sudo log to ${LOG_DIR} with 7-day retention (safe)..."

install -d -m 0750 "${LOG_DIR}"

cat >/etc/sudoers.d/99-sudo-logging <<EOF
Defaults logfile="${SUDO_LOG_NEW}"
Defaults loglinelen=0
EOF
chmod 0440 /etc/sudoers.d/99-sudo-logging

touch "${SUDO_LOG_NEW}"
chmod 0640 "${SUDO_LOG_NEW}"
chown root:adm "${SUDO_LOG_NEW}" 2>/dev/null || chown root:root "${SUDO_LOG_NEW}"

if [ -f "${SUDO_LOG_OLD}" ] && [ ! -L "${SUDO_LOG_OLD}" ]; then
  cat "${SUDO_LOG_OLD}" >> "${SUDO_LOG_NEW}" 2>/dev/null || true
  mv "${SUDO_LOG_OLD}" "${SUDO_LOG_OLD}.bak.$(date +%F_%H%M%S)" || true
fi

ln -sfn "${SUDO_LOG_NEW}" "${SUDO_LOG_OLD}"
chown -h root:root "${SUDO_LOG_OLD}" 2>/dev/null || true

cat >/etc/logrotate.d/hss-sudo-log <<EOF
${SUDO_LOG_NEW} {
  daily
  rotate 7
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
  create 0640 root adm
}
EOF
chmod 0644 /etc/logrotate.d/hss-sudo-log

# =========================
# 9) ROOT history logging (timestamped) for direct root login & sudo su
# =========================
echo "[+] Enabling detailed ROOT bash history timestamps (root login & sudo su)..."

cat >/root/.bashrc.d-hss-history.sh <<'EOF'
# Root history hardening (ISO/SOC2)
export HISTTIMEFORMAT='%F %T %Z '
export HISTSIZE=100000
export HISTFILESIZE=200000
export HISTCONTROL=ignoredups:erasedups
shopt -s histappend
PROMPT_COMMAND="history -a; history -n; ${PROMPT_COMMAND:-:}"
EOF

if ! grep -q 'bashrc.d-hss-history.sh' /root/.bashrc 2>/dev/null; then
  echo '[ -f /root/.bashrc.d-hss-history.sh ] && source /root/.bashrc.d-hss-history.sh' >> /root/.bashrc
fi

chmod 0600 /root/.bashrc.d-hss-history.sh
chmod 0600 /root/.bashrc

cat >/etc/sudoers.d/90-root-history <<'EOF'
Defaults env_keep += "HISTTIMEFORMAT HISTFILE PROMPT_COMMAND HSS_CMDLOG HSS_LAST_HISTNUM"
EOF
chmod 0440 /etc/sudoers.d/90-root-history

chsh -s /bin/bash root || true

# NOTE: ini sebelumnya ada, tapi biasanya log lebih aman dimiliki root/adm.
# Kamu punya baris ini; aku biarkan sesuai script kamu:
chown -R support:support /var/log_activity

# =========================
# Apply SSH config (reload at end)
# =========================
systemctl reload ssh || systemctl restart ssh

echo "[+] Done."
echo ""
echo "Notes:"
echo " - SSH port changed: 22 -> ${SSH_PORT} (connect using: ssh -p ${SSH_PORT} user@host)"
echo " - UFW enabled: allow ${SSH_PORT}/tcp; port 22 rule removed"
echo " - Fail2ban enabled for sshd on port ${SSH_PORT} (maxretry=5, bantime=15m)"
echo " - Cache file: ${CACHE_FILE} (TTL ${CACHE_TTL_SECONDS}s)"
echo " - Timer: hss-motd-refresh.timer (refresh every ~2 minutes)"
echo " - ENV label: ${ENV_FILE} (ENVIRONMENT=\"production\")"
echo " - Audit execve logs: /var/log/audit/audit.log (ausearch -k execve_all)"
echo " - Sudo log: ${SUDO_LOG_NEW} (symlink ${SUDO_LOG_OLD} -> ${SUDO_LOG_NEW}, rotate 7)"
echo " - Central history log: ${CMD_LOG} (rotate 7)"
echo " - SSH idle logout: TMOUT=900 (SSH only) + ClientAliveInterval/CountMax"
echo " - Cloud sudo user: ${CLOUD_USER} (credentials: /root/clouduser.credentials if created)"

# =========================
# Final apply & verification
# =========================
echo "[+] Restarting SSH service to apply all changes..."

# Prefer restart (port change requires full restart)
systemctl restart ssh

# Verify SSH is listening on the new port
echo "[+] Verifying SSH listener:"
netstat -tulpen | grep ":${SSH_PORT}" || {
  echo "[!] WARNING: SSH is not listening on port ${SSH_PORT}"
}

# Reload fail2ban just to be safe
systemctl restart fail2ban || true

# =========================
# PRINT CLOUDUSER CREDS (bold + color, "bigger" via figlet if available)
# =========================
if [ -n "${CLOUDUSER_PASS}" ]; then
  # Try to render "bigger" using figlet
  if ! command -v figlet >/dev/null 2>&1; then
    apt-get install -y figlet >/dev/null 2>&1 || true
  fi

  echo ""
  echo -e "\e[1;33m======================================================================\e[0m"
  echo -e "\e[1;32m[!] IMPORTANT: CLOUDUSER PASSWORD ROTATED — SAVE THIS NOW\e[0m"
  echo -e "\e[1;33m======================================================================\e[0m"
  echo ""

  if command -v figlet >/dev/null 2>&1; then
    echo -e "\e[1;36m$(figlet -w 120 "CLOUDUSER")\e[0m"
  else
    echo -e "\e[1;36mCLOUDUSER\e[0m"
  fi

  echo -e "\e[1;37mUsername:\e[0m \e[1;32m${CLOUD_USER}\e[0m"
  echo -e "\e[1;37mPassword:\e[0m \e[1;31m\e[1m${CLOUDUSER_PASS}\e[0m"
  echo ""
  echo -e "\e[1;37mSaved to:\e[0m \e[1;33m/root/clouduser.credentials\e[0m (mode 600)"
  echo -e "\e[1;33m======================================================================\e[0m"
fi
