#!/usr/bin/env bash
# ASI installer for Ubuntu 24.04/26.04 (systemd). Idempotent - safe to re-run
# for upgrades. Usage (as root, from the release directory):
#   ./deploy/install.sh [--demo] [--listen 127.0.0.1:8090]
set -euo pipefail

PREFIX=/opt/asi
ETC=/etc/asi
LISTEN="127.0.0.1:8090"
DEMO=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --demo) DEMO=1 ;;
    --listen) LISTEN="$2"; shift ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
  shift
done
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> packages (nmap, ca-certificates, tzdata)"
if ! command -v nmap >/dev/null; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap ca-certificates tzdata >/dev/null
fi
nmap --version | head -1

echo "==> user and directories"
id asi >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin asi
install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/docs" "$PREFIX/examples"
install -d -m 0700 -o asi -g asi "$PREFIX/data"
install -d -m 0750 -o root -g asi "$ETC"

echo "==> binary"
BIN="$SRC/bin/asi-linux-amd64"
[[ -f "$BIN" ]] || BIN="$SRC/asi"
install -m 0755 "$BIN" "$PREFIX/bin/asi.new"
mv -f "$PREFIX/bin/asi.new" "$PREFIX/bin/asi"
cp -r "$SRC/docs/." "$PREFIX/docs/" 2>/dev/null || true
cp -r "$SRC/examples/." "$PREFIX/examples/" 2>/dev/null || true

echo "==> configuration ($ETC/asi.env)"
if [[ ! -f "$ETC/master.key" ]]; then
  "$PREFIX/bin/asi" gen-key > "$ETC/master.key"
  echo "    generated master key $ETC/master.key - BACK IT UP separately from data backups"
fi
chown root:asi "$ETC/master.key"; chmod 0640 "$ETC/master.key"
if [[ ! -f "$ETC/asi.env" ]]; then
  ADMIN_PW="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
  DEMO_PW="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 16)"
  cat > "$ETC/asi.env" <<EOF
# ASI configuration - see docs/ARCHITEKTURA.md
ASI_LISTEN=$LISTEN
ASI_DATA_DIR=$PREFIX/data
ASI_MASTER_KEY_FILE=$ETC/master.key
ASI_NMAP_PATH=/usr/bin/nmap
# raw sockets via systemd AmbientCapabilities (SYN scan); set false for TCP connect
ASI_NMAP_PRIVILEGED=true
# global safety caps
ASI_MAX_RATE=2000
ASI_MAX_TARGETS=1048576
ASI_ADMIN_PASSWORD=$ADMIN_PW
ASI_DEMO=$DEMO
ASI_DEMO_PASSWORD=$DEMO_PW
# set to 1 when served over HTTPS (directly or behind a TLS reverse proxy)
ASI_SECURE_COOKIE=0
ASI_TRUST_PROXY=0
EOF
  chmod 0640 "$ETC/asi.env"; chown root:asi "$ETC/asi.env"
  echo "    admin password: $ADMIN_PW   (stored in $ETC/asi.env)"
  [[ $DEMO == 1 ]] && echo "    demo users (operator, analityk, audytor, soc) password: $DEMO_PW"
fi

echo "==> systemd"
install -m 0644 "$SRC/deploy/systemd/asi.service" /etc/systemd/system/asi.service
systemctl daemon-reload
systemctl enable asi >/dev/null 2>&1
systemctl restart asi

echo "==> waiting for health check"
for i in $(seq 1 120); do
  if ASI_LISTEN="$(grep ^ASI_LISTEN= "$ETC/asi.env" | cut -d= -f2)" "$PREFIX/bin/asi" healthcheck 2>/dev/null; then
    echo "    ASI is up on $(grep ^ASI_LISTEN= "$ETC/asi.env" | cut -d= -f2)"; exit 0
  fi
  sleep 1
done
echo "Sentinelis did not become healthy - check: journalctl -u asi -n 100"; exit 1
