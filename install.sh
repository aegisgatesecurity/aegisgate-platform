#!/usr/bin/env bash
# =========================================================================
# AegisGate Security Platform - Single-binary Installer (v3.4.0+ c2)
# =========================================================================
# Quick install:
#   curl -sSL https://aegisgatesecurity.io/install.sh | sudo bash
#
# Or with a specific version:
#   curl -sSL https://aegisgatesecurity.io/install.sh | sudo bash -s -- --version=v3.4.0-beta.1
#
# The installer:
#   1. Detects OS and architecture
#   2. Downloads the platform binary from the official GHCR release
#   3. Installs it to /usr/local/bin/aegisgate
#   4. Creates a non-root 'aegisgate' system user
#   5. Sets up /etc/aegisgate/ (config dir) and /var/lib/aegisgate/ (data dir)
#   6. Installs a systemd unit for managed start/stop/restart
#   7. Prints a one-line quick-start including the first admin command
#
# No Docker, no Kubernetes, no apt repo. Just one binary + one systemd unit.
# =========================================================================

set -euo pipefail

VERSION="v3.4.0-beta.1"
REPO="aegisgatesecurity/aegisgate-platform"
BIN_NAME="aegisgate"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/aegisgate"
DATA_DIR="/var/lib/aegisgate"
USER_NAME="aegisgate"
GROUP_NAME="aegisgate"
SERVICE_NAME="aegisgate"

# --- Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version=*) VERSION="${1#*=}" ;;
    --version) VERSION="$2"; shift ;;
    --help|-h)
      echo "Usage: $0 [--version=VERSION]"
      echo "  --version: platform version to install (default: $VERSION)"
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
  shift
done

# --- Detect OS/arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 3 ;;
esac
case "$OS" in
  linux) ;;
  *) echo "Unsupported OS: $OS (this installer is Linux-only)" >&2; exit 3 ;;
esac

echo ">>> AegisGate installer"
echo "    version : $VERSION"
echo "    os/arch : $OS/$ARCH"

# --- Check root
if [[ $EUID -ne 0 ]]; then
  echo "This installer must be run as root (try: sudo $0)" >&2
  exit 4
fi

# --- Create user/group if missing
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  echo ">>> Creating system user $USER_NAME"
  useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin "$USER_NAME"
fi

# --- Create dirs
echo ">>> Creating $CONFIG_DIR and $DATA_DIR"
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chown -R "$USER_NAME:$GROUP_NAME" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

# --- Download binary
ASSET="aegisgate-platform-${OS}-${ARCH}-${VERSION}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
TMP_TGZ="$(mktemp)"
echo ">>> Downloading $URL"
if ! curl -fSL --retry 3 -o "$TMP_TGZ" "$URL"; then
  echo "Download failed. Check that the version $VERSION exists at:" >&2
  echo "  https://github.com/${REPO}/releases/tag/${VERSION}" >&2
  rm -f "$TMP_TGZ"
  exit 5
fi

# --- Extract
TMP_DIR="$(mktemp -d)"
tar -xzf "$TMP_TGZ" -C "$TMP_DIR"
BIN_PATH="$TMP_DIR/$BIN_NAME"
if [[ ! -x "$BIN_PATH" ]]; then
  # The release archive may place the binary under a sub-dir
  BIN_PATH="$(find "$TMP_DIR" -type f -name "$BIN_NAME" -executable | head -1)"
  if [[ -z "$BIN_PATH" ]]; then
    echo "Could not find $BIN_NAME in the downloaded archive" >&2
    exit 6
  fi
fi

echo ">>> Installing binary to $INSTALL_DIR/$BIN_NAME"
install -m 0755 "$BIN_PATH" "$INSTALL_DIR/$BIN_NAME"
rm -rf "$TMP_DIR" "$TMP_TGZ"

# --- Write default config (idempotent)
CONFIG_FILE="$CONFIG_DIR/aegisgate.yaml"
if [[ ! -f "$CONFIG_FILE" ]]; then
  cat > "$CONFIG_FILE" <<'YAML'
# AegisGate default config. See:
#   aegisgate --help
#   https://aegisgatesecurity.io/docs

platform:
  # Tier is license-derived. Set AEGISGATE_LICENSE_KEY in the systemd
  # unit (see /etc/systemd/system/aegisgate.service) to unlock Pro+.
  data_dir: /var/lib/aegisgate
  proxy_port: 8080
  mcp_port: 8081
  dashboard_port: 8443

logging:
  level: info

# Federated IOC Library (v3.4.0+, default OFF - opt-in)
ioc:
  share: false
  receive: false
  peers: ""
  store_dir: /var/lib/aegisgate/ioc
  gossip_interval: 5m
YAML
  chown root:root "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
fi

# --- Install systemd unit (idempotent)
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
echo ">>> Installing systemd unit to $UNIT_FILE"
cat > "$UNIT_FILE" <<'UNIT'
[Unit]
Description=AegisGate Security Platform (v3.4.0+)
Documentation=https://aegisgatesecurity.io/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aegisgate
Group=aegisgate
WorkingDirectory=/var/lib/aegisgate
ExecStart=/usr/local/bin/aegisgate --config=/etc/aegisgate/aegisgate.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/aegisgate
# Optional: license key (recommended). Set via:
#   sudo systemctl edit aegisgate
# then add:
#   [Service]
#   Environment="AEGISGATE_LICENSE_KEY=..."

[Install]
WantedBy=multi-user.target
UNIT

# --- Reload systemd + enable (don't auto-start; let the operator do it)
systemctl daemon-reload
systemctl enable "$SERVICE_NAME.service" >/dev/null 2>&1 || true

echo ""
echo ">>> Installation complete."
echo ""
echo "  Binary : $INSTALL_DIR/$BIN_NAME"
echo "  Config : $CONFIG_FILE"
echo "  Data   : $DATA_DIR"
echo "  Service: $UNIT_FILE"
echo ""
echo "Quick start:"
echo "  sudo systemctl start $SERVICE_NAME"
echo "  sudo systemctl status $SERVICE_NAME"
echo ""
echo "Verify the install:"
echo "  curl -sSL http://localhost:8443/health"
echo "  curl -sSL http://localhost:8443/.well-known/aegisgate-evidence-pubkey.pem"
echo ""
echo "Build a cross-protocol evidence artifact (v3.4.0+ c1):"
echo "  curl -X POST -H 'Content-Type: application/json' \ "
echo "    -d '{\"period_start\":\"2026-01-01T00:00:00Z\",\"period_end\":\"2026-03-31T23:59:59Z\"}' \ "
echo "    http://localhost:8443/api/v1/compliance/evidence/cross_protocol/build"
echo ""