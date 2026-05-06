#!/usr/bin/env bash
set -euo pipefail

BIN_URL=""
SHA256_URL=""
API_URL=""
TOKEN=""
AUTH_MODE="x-api-key"
HOST_IP=""

BIN_PATH="/usr/local/bin/cve3po-agent"
CONFIG_DIR="/etc/cve3po-agent"
ENV_FILE="${CONFIG_DIR}/agent.env"
SERVICE_FILE="/etc/systemd/system/cve3po-agent.service"
TIMER_FILE="/etc/systemd/system/cve3po-agent.timer"
RUN_USER="cve3po-agent"

usage() {
  cat <<'EOF'
Usage: install.sh --binary-url URL --api-url URL [options]

Required:
  --binary-url URL         Download URL of Linux agent binary
  --api-url URL            CVE3PO agent endpoint URL

Optional:
  --sha256-url URL         URL containing expected sha256 (format: "<sha>  <file>")
  --token TOKEN            Bearer/API key token
  --auth-mode MODE         bearer (default) or x-api-key
  --host-ip IP             Explicit host IP (otherwise auto-detected by agent)

Example:
  sudo bash install.sh \
    --binary-url https://server/agent/latest/cve3po-agent-linux-amd64 \
    --sha256-url https://server/agent/latest/cve3po-agent-linux-amd64.sha256 \
    --api-url https://server/extensions/agent/inventory/ \
    --token abc123
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
  --binary-url)
    BIN_URL="${2:-}"
    shift 2
    ;;
  --sha256-url)
    SHA256_URL="${2:-}"
    shift 2
    ;;
  --api-url)
    API_URL="${2:-}"
    shift 2
    ;;
  --token)
    TOKEN="${2:-}"
    shift 2
    ;;
  --auth-mode)
    AUTH_MODE="${2:-}"
    shift 2
    ;;
  --host-ip)
    HOST_IP="${2:-}"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "Unknown argument: $1"
    usage
    exit 1
    ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

if [[ -z "${BIN_URL}" || -z "${API_URL}" ]]; then
  usage
  exit 1
fi

if [[ "${AUTH_MODE}" != "bearer" && "${AUTH_MODE}" != "x-api-key" ]]; then
  echo "--auth-mode must be 'bearer' or 'x-api-key'" >&2
  exit 1
fi

tmp_bin="$(mktemp)"
tmp_sha=""
trap 'rm -f "${tmp_bin}" "${tmp_sha}"' EXIT

echo "Downloading agent binary..."
wget -qO "${tmp_bin}" "${BIN_URL}"
chmod +x "${tmp_bin}"

if [[ -n "${SHA256_URL}" ]]; then
  tmp_sha="$(mktemp)"
  echo "Verifying sha256..."
  wget -qO "${tmp_sha}" "${SHA256_URL}"
  expected="$(awk '{print $1}' "${tmp_sha}")"
  actual="$(sha256sum "${tmp_bin}" | awk '{print $1}')"
  if [[ "${expected}" != "${actual}" ]]; then
    echo "sha256 mismatch: expected ${expected}, got ${actual}" >&2
    exit 1
  fi
fi

if ! id -u "${RUN_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "${RUN_USER}"
fi

install -m 0755 "${tmp_bin}" "${BIN_PATH}"
mkdir -p "${CONFIG_DIR}"

cat >"${ENV_FILE}" <<EOF
SOFTWARE_API_URL=${API_URL}
SOFTWARE_API_AUTH=${AUTH_MODE}
SOFTWARE_AGENT_CONFIG=${ENV_FILE}
EOF

if [[ -n "${TOKEN}" ]]; then
  echo "SOFTWARE_API_BEARER_TOKEN=${TOKEN}" >>"${ENV_FILE}"
fi

if [[ -n "${HOST_IP}" ]]; then
  echo "HOST_IP=${HOST_IP}" >>"${ENV_FILE}"
fi

chmod 600 "${ENV_FILE}"
chown root:"${RUN_USER}" "${ENV_FILE}"
chmod 640 "${ENV_FILE}"

cat >"${SERVICE_FILE}" <<EOF
[Unit]
Description=CVE3PO Software Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=${RUN_USER}
Group=${RUN_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONFIG_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

cat >"${TIMER_FILE}" <<EOF
[Unit]
Description=Run CVE3PO Software Agent every 60 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=60min
Persistent=true
Unit=cve3po-agent.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl disable --now cve3po-agent.service >/dev/null 2>&1 || true
systemctl enable --now cve3po-agent.timer
systemctl start cve3po-agent.service

echo "Installed cve3po-agent.service and enabled cve3po-agent.timer (60 min interval)"
echo "Config: ${ENV_FILE}"
