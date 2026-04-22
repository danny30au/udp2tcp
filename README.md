# udp2tcp

A high-performance, multi-core UDP ↔ TCP proxy written in Rust, purpose-built for WireGuard tunnelling over TCP.

## Features

- **Multi-core scaling** via SO_REUSEPORT + one Tokio runtime per OS thread  
- **WireGuard-compatible framing** — 2-byte big-endian length prefix (identical to wg-tcp-tunnel / wstunnel wire format)  
- **Bidirectional** — UDP→TCP (client side) or TCP→UDP (`--reverse`, server/endpoint side)  
- **Low-copy packet path** — `Bytes`/`BytesMut` avoid extra hot-path packet copies  
- **Lock-free session table** — DashMap with per-worker sharding  
- **Parallel TCP streams per session** (`--tcp-streams`) to break single-stream bottlenecks  
- **Optional CPU affinity pinning** (`--cpu-pin`) for NUMA/cache locality  
- **Optional Linux daemon mode** (`--daemon`) for background operation  
- **Configurable via CLI flags or environment variables**  
- **Prometheus metrics** (opt-in, `--features metrics`)  
- **mimalloc global allocator** (default-on, `--no-default-features` to disable) for lower-latency hot-path allocations
- **Batched UDP I/O on Linux** — uses `recvmmsg`/`sendmmsg` to drain up to 32 datagrams per syscall and best-effort `UDP_GRO` for kernel-side coalescing
- **Vectored TCP writes** — outbound frames are emitted with `writev`, eliminating one per-packet payload `memcpy`
- **Sampled latency metrics** — packet counters are always-on, but `Instant::now()` is taken on a 1-in-64 schedule to keep the hot path lean
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

### Tuning the CPU baseline

The default release build targets the conservative `x86-64` baseline so it
runs anywhere. On a known machine you can typically squeeze out an extra
5–15% by enabling the local CPU's full instruction set (AVX2, BMI, FMA, …):

```bash
# Best for self-hosted boxes — binary is NOT portable.
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Portable across most post-2013 Intel/AMD CPUs (AVX2/BMI/FMA baseline).
RUSTFLAGS="-C target-cpu=x86-64-v3" cargo build --release
```

A commented `.cargo/config.toml` template is included with ready-to-uncomment
`rustflags` blocks for both options.

### Profile-Guided Optimization (PGO)

PGO typically yields another 5–15% on a network proxy. The flow is:

```bash
# 1. Build an instrumented binary.
RUSTFLAGS="-C target-cpu=native -Cprofile-generate=/tmp/pgo-data" \
  cargo build --release --target x86_64-unknown-linux-gnu

# 2. Run a representative workload through it (a few minutes of real or
#    synthetic traffic in the modes you care about).
./target/x86_64-unknown-linux-gnu/release/udp2tcp -l 0.0.0.0:51820 -r ...

# 3. Merge the raw profiles. Requires `llvm-profdata` from the Rust toolchain
#    (install with `rustup component add llvm-tools-preview`).
llvm-profdata merge -o /tmp/pgo-data/merged.profdata /tmp/pgo-data

# 4. Rebuild using the collected profile.
RUSTFLAGS="-C target-cpu=native -Cprofile-use=/tmp/pgo-data/merged.profdata" \
  cargo build --release --target x86_64-unknown-linux-gnu
```

For a turnkey workflow, `cargo install cargo-pgo` automates steps 1 and 4.

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
- One or more TCP streams (`--tcp-streams`) are opened per session
- Packets are distributed across stream channels in round-robin order
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

### Run as a Linux daemon

```bash
udp2tcp \
  --listen 127.0.0.1:51820 \
  --remote 203.0.113.1:51820 \
  --daemon
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
| `--write-batch` | `UDP2TCP_WRITE_BATCH` | 64 | Number of TCP frames to batch before writing the aggregated batch to TCP |
| `--flush-ms` | `UDP2TCP_FLUSH_MS` | 4 | Max time to hold queued TCP frames before writing the aggregated batch to TCP |
| `--tcp-streams` | `UDP2TCP_TCP_STREAMS` | 1 | Parallel TCP streams per UDP session (UDP→TCP mode) |
| `--pkt-buf` | `UDP2TCP_PKT_BUF` | 65536 | Per-read buffer size |
| `--max-sessions` | `UDP2TCP_MAX_SESSIONS` | 65536 | Max UDP client sessions |
| `--idle-timeout` | `UDP2TCP_IDLE_TIMEOUT` | 180 | Session idle timeout (s) |
| `--nodelay` | `UDP2TCP_NODELAY` | false | TCP_NODELAY (set true for lower latency; keep false for more TCP coalescing/throughput) |
| `--reuseport` | `UDP2TCP_REUSEPORT` | true | SO_REUSEPORT (Linux) |
| `--cpu-pin` | `UDP2TCP_CPU_PIN` | false | Pin threads to CPU cores |
| `--log-level` | `RUST_LOG` | info | Log level |
| `--daemon` | `UDP2TCP_DAEMON` | false | Run in background as a daemon (Linux only) |

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

For high-bandwidth or high-latency links, also try:

- raising `--write-batch` to increase TCP write coalescing
- raising `--flush-ms` slightly to allow larger batches
- disabling `--nodelay` if raw throughput matters more than per-packet latency

The periodic `stats` log now also reports queue drops, UDP syscall counts/average wait, TCP frame counts, flush counts, and average frames per TCP flush so you can see whether throughput is limited by queue pressure or too-frequent flushes.

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
