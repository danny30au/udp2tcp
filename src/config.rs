use clap::Parser;
use std::net::SocketAddr;

/// High-performance UDP↔TCP proxy with WireGuard framing support.
///
/// In UDP→TCP mode the proxy listens for UDP datagrams, wraps each
/// packet with a 2-byte big-endian length prefix (WireGuard-over-TCP
/// framing), and streams them over a persistent TCP connection.
///
/// In TCP→UDP mode (--reverse) it does the opposite: reads length-
/// prefixed frames from a TCP listener and emits raw UDP datagrams.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// Local address to listen on (UDP in normal mode, TCP in reverse mode).
    #[arg(short = 'l', long, env = "UDP2TCP_LISTEN", default_value = "0.0.0.0:51820")]
    pub listen: SocketAddr,

    /// Remote address to forward to (TCP in normal mode, UDP in reverse mode).
    #[arg(short = 'r', long, env = "UDP2TCP_REMOTE")]
    pub remote: SocketAddr,

    /// Reverse mode: TCP listen → UDP forward (for the server/endpoint side).
    #[arg(long, env = "UDP2TCP_REVERSE", default_value_t = false)]
    pub reverse: bool,

    /// Number of worker threads (defaults to number of logical CPUs).
    #[arg(short = 't', long, env = "UDP2TCP_THREADS")]
    pub threads: Option<usize>,

    /// UDP receive buffer size in bytes per socket.
    #[arg(long, env = "UDP2TCP_UDP_RECV_BUF", default_value_t = 26_214_400)]
    pub udp_recv_buf: usize,

    /// UDP send buffer size in bytes per socket.
    #[arg(long, env = "UDP2TCP_UDP_SEND_BUF", default_value_t = 26_214_400)]
    pub udp_send_buf: usize,

    /// TCP socket send/receive buffer size in bytes.
    #[arg(long, env = "UDP2TCP_TCP_BUF", default_value_t = 4_194_304)]
    pub tcp_buf: usize,

    /// Per-packet read buffer size in bytes.  Must be >= WireGuard MTU (1500).
    #[arg(long, env = "UDP2TCP_PKT_BUF", default_value_t = 65_536)]
    pub pkt_buf: usize,

    /// Maximum number of concurrent UDP client sessions (UDP→TCP mode).
    #[arg(long, env = "UDP2TCP_MAX_SESSIONS", default_value_t = 65_536)]
    pub max_sessions: usize,

    /// Idle session timeout in seconds.
    #[arg(long, env = "UDP2TCP_IDLE_TIMEOUT", default_value_t = 180)]
    pub idle_timeout: u64,

    /// Enable TCP_NODELAY on the TCP leg (reduces latency, slightly lower throughput).
    #[arg(long, env = "UDP2TCP_NODELAY", default_value_t = true)]
    pub nodelay: bool,

    /// Enable SO_REUSEPORT on UDP sockets (allows multiple worker sockets on same port).
    #[arg(long, env = "UDP2TCP_REUSEPORT", default_value_t = true)]
    pub reuseport: bool,

    /// Pin worker threads to CPU cores (requires Linux).
    #[arg(long, env = "UDP2TCP_CPU_PIN", default_value_t = false)]
    pub cpu_pin: bool,

    /// Log level: trace, debug, info, warn, error.
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_level: String,

    /// Expose Prometheus metrics on this address (optional, requires --features metrics).
    #[cfg(feature = "metrics")]
    #[arg(long, env = "UDP2TCP_METRICS_ADDR")]
    pub metrics_addr: Option<SocketAddr>,
}

impl Config {
    pub fn num_threads(&self) -> usize {
        self.threads
            .unwrap_or_else(|| num_cpus())
            .max(1)
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
