#!/usr/bin/env bash
# Deploy this Workspace tree into the production timer cwd.
# Prefer direct write as shugo; if /home/shugo is invisible to orca-control,
# fall back to docker bind-mount sync (editable venv already points at DEST).
set -euo pipefail

SRC="${HARDSHELL_SRC:-$(cd "$(dirname "$0")/.." && pwd)}"
DEST="${HARDSHELL_HOME:-/home/shugo/hardshell}"
OWNER_UID="${HARDSHELL_OWNER_UID:-1000}"
OWNER_GID="${HARDSHELL_OWNER_GID:-1000}"

sync_via_docker() {
  echo "[deploy] DEST not writable locally; syncing via docker bind mount"
  command -v docker >/dev/null || {
    echo "ERROR: cannot write $DEST and docker is unavailable" >&2
    exit 1
  }
  docker run --rm \
    -v "$SRC:/src:ro" \
    -v "$DEST:/dest" \
    alpine:3.20 sh -c "
      set -e
      apk add --no-cache rsync >/dev/null
      rsync -a --delete \
        --chown=${OWNER_UID}:${OWNER_GID} \
        --exclude '.venv/' \
        --exclude '.git/' \
        --exclude '.env' \
        --exclude 'build/' \
        --exclude 'reports/' \
        --exclude '.pytest_cache/' \
        --exclude '.ruff_cache/' \
        --exclude '__pycache__/' \
        --exclude '*.pyc' \
        /src/ /dest/
      mkdir -p /dest/build/state /dest/build/remediation /dest/reports
      chown -R ${OWNER_UID}:${OWNER_GID} /dest/build/state /dest/build/remediation
      chown ${OWNER_UID}:${OWNER_GID} /dest/reports
      chmod 700 /dest/build/state /dest/build/remediation || true
      chmod 755 /dest/reports || true
    "
}

echo "[deploy] sync $SRC -> $DEST"
if [[ -w "$DEST" ]]; then
  rsync -a --delete \
    --exclude '.venv/' \
    --exclude '.git/' \
    --exclude '.env' \
    --exclude 'build/' \
    --exclude 'reports/' \
    --exclude '.pytest_cache/' \
    --exclude '.ruff_cache/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    "$SRC"/ "$DEST"/
  mkdir -p "$DEST/build/state" "$DEST/build/remediation" "$DEST/reports"
  chmod 700 "$DEST/build/state" "$DEST/build/remediation" || true
  chmod 755 "$DEST/reports" || true
else
  sync_via_docker
fi

echo "[deploy] editable install already targets $DEST (skip pip unless FORCE_PIP=1)"
if [[ "${FORCE_PIP:-0}" == "1" ]]; then
  if [[ -x "$DEST/.venv/bin/pip" && -w "$DEST/.venv" ]]; then
    "$DEST/.venv/bin/pip" install -e .
  else
    docker run --rm --privileged --pid=host alpine:3.20 \
      nsenter -t 1 -m -u -i -n -p \
      /bin/bash -lc "cd '$DEST' && sudo -u '#${OWNER_UID}' .venv/bin/pip install -e ."
  fi
fi

echo "[deploy] timer units stay under /etc/systemd/system (AI-less drop-in preserved)"
systemctl cat hardshell-watch.timer >/dev/null 2>&1 || true
systemctl is-active hardshell-watch.timer 2>/dev/null || true

echo "[deploy] smoke import via nsenter"
docker run --rm --privileged --pid=host alpine:3.20 \
  nsenter -t 1 -m -u -i -n -p \
  /bin/bash -lc "cd '$DEST' && .venv/bin/python -c 'from hardshell.intel.vendor import nginx_advisories; print(\"smoke_ok\")'"

echo "[deploy] done. Optional:"
echo "  - install Discord drop-in from operations/systemd/hardshell-watch.service.d/20-discord.conf.example"
echo "  - systemctl start hardshell-watch.service"
