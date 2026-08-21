# Spectralis Honeypot

Modular industrial PLC honeypot. It listens on a TCP port, pretends to be a Siemens or Modicon PLC, completes enough of the handshake for scanners and clients to stick around, and records every session to disk.

More mock devices coming soon™.

**Repo:** [github.com/a3r0id/spectralis-honeypot](https://github.com/a3r0id/spectralis-honeypot)

> Use only on systems and networks you own or have explicit permission to monitor. This is a research / defensive tool, not a toy to drop on someone else’s LAN.

---

## What it does

| Family | Protocol | Typical port | Devices |
|--------|----------|--------------|---------|
| Siemens | S7comm over ISO-on-TCP ([RFC 1006](https://www.rfc-editor.org/rfc/rfc1006)) | `102` | `S7-200`, `S7-300`, `S7-400`, `S7-1200` |
| Modicon | Modbus TCP | `502` | `M221`, `M340` |

Each accepted connection is handled on its own thread. Framed protocol traffic is answered by the selected device’s handler; everything is appended to a binary session file for later review.

---

## Quick start

**Dependencies:** CMake ≥ 3.19, a C++17 compiler (`g++` / `clang++`), Make, Threads.

```bash
cmake --preset linux-release
cmake --build --preset linux-release

BIN="$HOME/.cache/spectralis-honeypot/build/linux-release/spectralis-honeypot"

"$BIN" --list
"$BIN" 102 0.0.0.0 S7-200
```

Debug preset (used by the devcontainer / VS Code):

```bash
cmake --preset linux-docker-debug
cmake --build --preset linux-docker-debug
```

Binding ports below `1024` needs elevated privileges (or `CAP_NET_BIND_SERVICE`). For local testing, prefer a high port such as `10200`.

---

## Usage

```text
spectralis-honeypot [port] [bind_addr] [device]
spectralis-honeypot --list
spectralis-honeypot -h | --help
```

| Argument | Default | Description |
|----------|---------|-------------|
| `port` | `102` | TCP listen port |
| `bind_addr` | `0.0.0.0` | IPv4 address or local interface name |
| `device` | `S7-200` | Device id to mock (case-insensitive) |

Examples:

```bash
./spectralis-honeypot --list
./spectralis-honeypot 102 0.0.0.0 S7-200
./spectralis-honeypot 502 0.0.0.0 M221
./spectralis-honeypot 10200 127.0.0.1 s7-300   # high port, loopback, any casing
```

`--list` prints the built-in catalog:

```text
0:  "S7-200" - Siemens PLC model series
1:  "S7-300" - Siemens PLC model
2:  "S7-400" - Siemens PLC model
3:  "S7-1200" - Siemens S7-1200 PLC
4:  "M221" - Modicon PLC model
5:  "M340" - Modicon M340 PLC
```

### Environment variables

CLI arguments override these.

| Variable | Default | Notes |
|----------|---------|-------|
| `HONEYPOT_PORT` | `102` | Listen port |
| `HONEYPOT_BIND_ADDR` | `0.0.0.0` | Bind address / interface |
| `HONEYPOT_DEVICE` | `S7-200` | Preferred device id |
| `HONEYPOT_PLC_TYPE` | — | Legacy alias if `HONEYPOT_DEVICE` is unset |

---

## Session capture

On startup the honeypot creates:

```text
<unix-epoch>.spectralis.session.bin
```

in the process working directory.

**Layout (little-endian host structs):**

1. **Header** (`SessionHeader`): listen timestamp, bind `in_addr`, port, `IPPROTO_TCP`
2. **Entries** (appended per framed or raw payload): client timestamp, client `in_addr`, `uint16_t` length, then `length` payload bytes

Session files are gitignored (`*session.bin`).

### Viewing results

A dedicated viewer for these captures is planned. Until then, inspect hex dumps with `xxd` / `hexdump`, or parse the structs from `include/honeypot/session_file.hpp`.

---

## Docker

Hardened image: distroless runtime, non-root, dropped capabilities (except `NET_BIND_SERVICE`), read-only rootfs.

```bash
docker compose up --build -d
```

Defaults map host `102` → container `102` with `HONEYPOT_DEVICE=S7-200`. Override env in `docker-compose.yml` for Modbus (`502` / `M221`), or run the image directly:

```bash
docker build -t spectralis-honeypot .
docker run --rm -p 502:502 \
  -e HONEYPOT_PORT=502 \
  -e HONEYPOT_DEVICE=M221 \
  spectralis-honeypot
```

Optional: uncomment `runtime: runsc` in compose if the host has [gVisor](https://gvisor.dev/) installed.

---

## Architecture (short)

```text
CLI / env  →  DeviceRegistry  →  ProtocolHandler
                                      │
                    ┌─────────────────┴─────────────────┐
                    │                                   │
              S7comm (RFC 1006)                   Modbus TCP
              iso_on_tcp + s7comm                 modbus_tcp
```

- **`ProtocolHandler`** — frame extraction + reply generation
- **`DeviceRegistry`** — maps device ids onto a shared protocol implementation
- **`sock_server`** — accept loop, per-client thread, session logging

Adding a device usually means implementing (or reusing) a protocol handler and registering it in `src/device_registry.cpp`.

---

## Development

```bash
# unit tests (GoogleTest, fetched by CMake)
cmake --preset linux-docker-debug
cmake --build --preset linux-docker-debug
ctest --test-dir "$HOME/.cache/spectralis-honeypot/build/linux-docker-debug" --output-on-failure

# end-to-end smoke (starts honeypot, runs tests/connect.py)
./scripts/smoke-test.sh
```

A VS Code / Cursor [devcontainer](.devcontainer/) is included for a ready Linux toolchain.

---

## License

[MIT](LICENSE) © 2026 hostinfodev
