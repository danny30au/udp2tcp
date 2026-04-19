# udp2tcp

A high-performance, multi-core UDP ↔ TCP proxy written in Rust, purpose-built for WireGuard tunnelling over TCP.

## Features

- **Multi-core scaling** via SO_REUSEPORT + one Tokio runtime per OS thread  
- **WireGuard-compatible framing** — 2-byte big-endian length prefix (identical to wg-tcp-tunnel / wstunnel wire format)  
- **Bidirectional** — UDP→TCP (client side) or TCP→UDP (`--reverse`, server/endpoint side)  
- **Zero-copy path** — `Bytes` slices avoid unnecessary allocations on the hot path  
- **Lock-free session table** — DashMap with per-worker sharding  
- **Optional CPU affinity pinning** (`--cpu-pin`) for NUMA/cache locality  
- **Configurable via CLI flags or environment variables**  
- **Prometheus metrics** (opt-in, `--features metrics`)  
- Release profile: `opt-level=3`, fat LTO, single codegen unit, panic=abort

## Build

```bash
# Standard release build (recommended)
cargo build --release

# With Clang/LTO (even faster on Linux)
CC=clang CXX=clang++ \
  RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=lld" \
  cargo build --release

# With Prometheus metrics endpoint
cargo build --release --features metrics
```

The binary lands at `target/release/udp2tcp`.

## Architecture

```
UDP→TCP mode (client side)
─────────────────────────────────────────────────────────────────────
 WireGuard (userspace) ──UDP──► [Worker 0]──┐
                        ◄─────              ├──► TCP (WG framing) ──► remote
                                [Worker 1]──┘
                        ← each worker binds the same UDP port via SO_REUSEPORT →
                        ← kernel distributes datagrams across workers (RSS-like) →

TCP→UDP mode (--reverse, server/endpoint side)
─────────────────────────────────────────────────────────────────────
 udp2tcp client ──TCP──► [TCP listener] ──UDP──► WireGuard server
                ◄──────                 ◄───────
```

### Session management

Each unique `(src_ip, src_port)` in UDP→TCP mode gets its own logical session:
- A `mpsc::channel` carries packets from the UDP receiver to the per-session TCP task
- Sessions expire after `--idle-timeout` seconds (default 180 s)
- A background sweeper runs every 30 s
- `--max-sessions` caps the session table to prevent resource exhaustion

### TCP framing

WireGuard UDP packets are wrapped with a 2-byte big-endian length prefix:

```
┌──────────────────────┬──────────────────────────────────┐
│  Length (2 bytes BE) │  WireGuard packet (1–65535 bytes)│
└──────────────────────┴──────────────────────────────────┘
```

This is the same framing used by [wstunnel](https://github.com/erebe/wstunnel), wg-tcp-tunnel, and similar tools.

## Usage

### UDP → TCP (client side — run alongside WireGuard)

WireGuard on the local machine sends to UDP `127.0.0.1:51820`.  
`udp2tcp` listens there and forwards over TCP to your server.

```bash
udp2tcp \
  --listen 127.0.0.1:51820 \
  --remote 203.0.113.1:51820 \
  --threads 4
```

Configure WireGuard to use `Endpoint = 127.0.0.1:51820`.

### TCP → UDP (server / endpoint side — `--reverse`)

On the server, run alongside `wg` listening on UDP `127.0.0.1:51820`:

```bash
udp2tcp \
  --listen 0.0.0.0:51820 \
  --remote 127.0.0.1:51820 \
  --reverse \
  --threads 4
```

### All options

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` / `-l` | `UDP2TCP_LISTEN` | `0.0.0.0:51820` | Local bind address |
| `--remote` / `-r` | `UDP2TCP_REMOTE` | *(required)* | Remote forward address |
| `--reverse` | `UDP2TCP_REVERSE` | false | TCP→UDP mode |
| `--threads` / `-t` | `UDP2TCP_THREADS` | # of CPUs | Worker thread count |
| `--udp-recv-buf` | `UDP2TCP_UDP_RECV_BUF` | 26214400 (25 MB) | UDP SO_RCVBUF |
| `--udp-send-buf` | `UDP2TCP_UDP_SEND_BUF` | 26214400 (25 MB) | UDP SO_SNDBUF |
| `--tcp-buf` | `UDP2TCP_TCP_BUF` | 4194304 (4 MB) | TCP SO_SNDBUF/SO_RCVBUF |
| `--pkt-buf` | `UDP2TCP_PKT_BUF` | 65536 | Per-read buffer size |
| `--max-sessions` | `UDP2TCP_MAX_SESSIONS` | 65536 | Max UDP client sessions |
| `--idle-timeout` | `UDP2TCP_IDLE_TIMEOUT` | 180 | Session idle timeout (s) |
| `--nodelay` | `UDP2TCP_NODELAY` | true | TCP_NODELAY |
| `--reuseport` | `UDP2TCP_REUSEPORT` | true | SO_REUSEPORT (Linux) |
| `--cpu-pin` | `UDP2TCP_CPU_PIN` | false | Pin threads to CPU cores |
| `--log-level` | `RUST_LOG` | info | Log level |

## Kernel tuning

For maximum throughput, raise kernel socket buffer limits:

```bash
# Increase UDP/TCP buffer limits (persistent in /etc/sysctl.d/99-udp2tcp.conf)
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 65535
net.ipv4.udp_mem = 8388608 12582912 16777216
net.ipv4.tcp_mem = 8388608 12582912 16777216
```

Apply with `sysctl --system` or `sysctl -p`.

## Running as a systemd service

```ini
[Unit]
Description=udp2tcp WireGuard TCP proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/udp2tcp --listen 127.0.0.1:51820 --remote 203.0.113.1:51820 --threads 4
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

## License

MIT
