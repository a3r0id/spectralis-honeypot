#!/usr/bin/env bash
set -euo pipefail

if ! command -v cmake >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cmake g++ make python3
fi

cmake --preset linux-docker-debug
cmake --build --preset linux-docker-debug

BIN="${HOME}/.cache/spectralis-honeypot/build/linux-docker-debug/spectralis-honeypot"

"${BIN}" --help

"${BIN}" 10200 0.0.0.0 S7-200 >/tmp/hp.log 2>&1 &
server_pid=$!
sleep 1

python3 tests/connect.py 127.0.0.1 10200

echo "--- server log ---"
cat /tmp/hp.log
kill "${server_pid}" || true

ctest --test-dir "${HOME}/.cache/spectralis-honeypot/build/linux-docker-debug" --output-on-failure
