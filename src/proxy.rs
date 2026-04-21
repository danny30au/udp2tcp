//! Core proxy logic — two modes:
//!
//! ## Mode A: UDP → TCP  (default, client side)
//!
//!  ┌──────────────┐  UDP pkts   ┌─────────────┐  TCP (WG framing)  ┌──────────┐
//!  │ WireGuard    │ ──────────► │  udp2tcp    │ ─────────────────► │  server  │
//!  │ (userspace)  │ ◄────────── │  (this app) │ ◄───────────────── │  side    │
//!  └──────────────┘             └─────────────┘                     └──────────┘
//!
//! ## Mode B: TCP → UDP  (--reverse, server side / endpoint side)
//!
//!  ┌──────────────┐  TCP (WG)   ┌─────────────┐  UDP pkts   ┌──────────────┐
//!  │  udp2tcp     │ ──────────► │  udp2tcp    │ ───────────►│ WireGuard    │
//!  │  client      │ ◄────────── │  --reverse  │ ◄────────── │  server      │
//!  └──────────────┘             └─────────────┘             └──────────────┘

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc::{self, error::TryRecvError},
    time,
};
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info, warn};

use crate::{
    codec::{encode_frame, WireGuardTcpCodec},
    config::Config,
    metrics,
    session::{Session, SessionTable},
};

// ─── mode A: UDP listen → TCP forward ──────────────────────────────────────

/// Run in UDP→TCP proxy mode.
///
/// Each worker calls this. Because we use SO_REUSEPORT, the kernel distributes
/// datagrams across all worker sockets automatically (RSS-style load balancing).
pub async fn run_udp_to_tcp(cfg: Arc<Config>, worker_id: usize) -> anyhow::Result<()> {
    let sessions: Arc<SessionTable> = Arc::new(SessionTable::new(
        cfg.max_sessions.div_ceil(cfg.num_threads().max(1)),
        Duration::from_secs(cfg.idle_timeout),
    ));

    // Bind the UDP listener socket.
    let udp_sock = bind_udp(&cfg, worker_id)?;
    let udp_sock = Arc::new(udp_sock);

    info!(worker = worker_id, listen = %cfg.listen, "UDP listener ready");

    // Idle-session sweeper — runs every 30 s.
    {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                sessions.sweep_idle();
                metrics::SESSIONS_ACTIVE.store(sessions.len() as u64,
                    std::sync::atomic::Ordering::Relaxed);
            }
        });
    }

    let batch_size = cfg.write_batch.max(1);
    let flush_interval = Duration::from_millis(cfg.flush_ms.max(1));
    let mut pkt_buf = BytesMut::with_capacity(cfg.pkt_buf);

    loop {
        // Receive next UDP datagram from any client.
        pkt_buf.clear();
        let recv_started = Instant::now();
        let (n, src_addr) = match udp_sock.recv_buf_from(&mut pkt_buf).await {
            Ok(v) => v,
            Err(e) => {
                metrics::inc_errors();
                error!(worker = worker_id, err = %e, "UDP recv_from failed");
                continue;
            }
        };
        metrics::observe_udp_recv(recv_started.elapsed());

        let data = pkt_buf.split().freeze();
        metrics::inc_rx(n as u64);

        // Look up or create a session for this client.
        let session = if let Some(s) = sessions.get(&src_addr) {
            s
        } else {
            // No existing session — create one.
            let stream_count = cfg.tcp_streams.max(1);
            let mut txs = Vec::with_capacity(stream_count);

            for stream_id in 0..stream_count {
                let (tx, rx) = mpsc::channel::<Bytes>(4096);
                txs.push(tx);

                // Spawn one TCP forwarder task per configured stream.
                tokio::spawn(tcp_forward_task(
                    cfg.clone(),
                    udp_sock.clone(),
                    src_addr,
                    rx,
                    worker_id,
                    stream_id,
                    batch_size,
                    flush_interval,
                ));
            }

            let session = Session::new(txs);
            if !sessions.insert(src_addr, session.clone()) {
                // Table full — drop packet.
                metrics::inc_errors();
                continue;
            }

            metrics::SESSIONS_ACTIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!(worker = worker_id, client = %src_addr, "new session");

            sessions.get(&src_addr).unwrap_or(session)
        };

        // Forward the packet to the TCP task via channel.
        if session.try_send(data).is_err() {
            metrics::inc_errors();
            metrics::inc_queue_drops();
            debug!(client = %src_addr, "all stream channels full/closed, dropping packet");
        }
    }
}

/// Per-session TCP forwarding task.
///
/// Connects to the remote TCP endpoint, then runs two concurrent loops:
///   1. channel → TCP (framed write)
///   2. TCP (framed read) → UDP reply back to the original client
async fn tcp_forward_task(
    cfg: Arc<Config>,
    udp_sock: Arc<UdpSocket>,
    client_addr: SocketAddr,
    mut rx: mpsc::Receiver<Bytes>,
    worker_id: usize,
    stream_id: usize,
    batch_size: usize,
    flush_interval: Duration,
) {
    // Connect to the remote TCP endpoint.
    let connect_started = Instant::now();
    let tcp_stream = match TcpStream::connect(cfg.remote).await {
        Ok(s) => s,
        Err(e) => {
            error!(worker = worker_id, stream = stream_id, client = %client_addr, remote = %cfg.remote,
                   err = %e, "TCP connect failed");
            metrics::inc_errors();
            return;
        }
    };
    metrics::observe_tcp_connect(connect_started.elapsed());

    apply_tcp_opts(&tcp_stream, &cfg);
    debug!(worker = worker_id, stream = stream_id, client = %client_addr, remote = %cfg.remote, "TCP connected");

    let (tcp_rd, mut tcp_wr) = tcp_stream.into_split();
    let mut framed_rd = FramedRead::new(tcp_rd, WireGuardTcpCodec);

    use futures::StreamExt;

    let mut pending_writes = 0usize;
    let mut write_buf = BytesMut::with_capacity(tcp_write_batch_capacity(&cfg, batch_size));
    let mut flush_tick = time::interval(flush_interval);

    // Run both directions concurrently until either side closes.
    loop {
        tokio::select! {
            // Outbound: channel → TCP write
            maybe_pkt = rx.recv() => {
                match maybe_pkt {
                    Some(pkt) => {
                        let len = pkt.len();
                        if let Err(e) = encode_frame(&pkt, &mut write_buf) {
                            error!(stream = stream_id, client = %client_addr, err = %e, "TCP frame encode failed");
                            metrics::inc_errors();
                            break;
                        }
                        metrics::inc_tx(len as u64);
                        metrics::inc_tcp_frame_tx();
                        pending_writes += 1;
                        let mut write_failed = false;
                        let mut stream_disconnected = false;

                        while pending_writes < batch_size {
                            match rx.try_recv() {
                                Ok(pkt) => {
                                    let len = pkt.len();
                                    if let Err(e) = encode_frame(&pkt, &mut write_buf) {
                                        error!(stream = stream_id, client = %client_addr, err = %e, "TCP frame encode failed");
                                        metrics::inc_errors();
                                        write_failed = true;
                                        break;
                                    }
                                    metrics::inc_tx(len as u64);
                                    metrics::inc_tcp_frame_tx();
                                    pending_writes += 1;
                                }
                                Err(TryRecvError::Empty) => break,
                                Err(TryRecvError::Disconnected) => {
                                    stream_disconnected = true;
                                    break;
                                }
                            }
                        }
                        if write_failed {
                            break;
                        }
                        if stream_disconnected {
                            if pending_writes > 0 {
                                if let Err(e) = flush_encoded_frames(&mut tcp_wr, &mut write_buf, &mut pending_writes).await {
                                    error!(stream = stream_id, client = %client_addr, err = %e, "TCP flush failed");
                                }
                            }
                            break;
                        }

                        if pending_writes >= batch_size {
                            if let Err(e) = flush_encoded_frames(&mut tcp_wr, &mut write_buf, &mut pending_writes).await {
                                error!(stream = stream_id, client = %client_addr, err = %e, "TCP flush failed");
                                metrics::inc_errors();
                                break;
                            }
                        }
                    }
                    None => {
                        if pending_writes > 0 {
                            if let Err(e) = flush_encoded_frames(&mut tcp_wr, &mut write_buf, &mut pending_writes).await {
                                error!(stream = stream_id, client = %client_addr, err = %e, "TCP flush failed");
                            }
                        }
                        break; // sender dropped → session closed
                    }
                }
            }

            // Inbound: TCP read → UDP send back to client
            maybe_frame = framed_rd.next() => {
                match maybe_frame {
                    Some(Ok(frame)) => {
                        let len = frame.len();
                        metrics::inc_tcp_frame_rx();
                        let send_started = Instant::now();
                        if let Err(e) = udp_sock.send_to(&frame, client_addr).await {
                            error!(client = %client_addr, err = %e, "UDP sendto failed");
                            metrics::inc_errors();
                        } else {
                            metrics::observe_udp_send(send_started.elapsed());
                            metrics::inc_rx(len as u64);
                        }
                    }
                    Some(Err(e)) => {
                        error!(stream = stream_id, client = %client_addr, err = %e, "TCP frame decode error");
                        metrics::inc_errors();
                        break;
                    }
                    None => {
                        debug!(stream = stream_id, client = %client_addr, "TCP connection closed by remote");
                        break;
                    }
                }
            }

            _ = flush_tick.tick(), if pending_writes > 0 => {
                if let Err(e) = flush_encoded_frames(&mut tcp_wr, &mut write_buf, &mut pending_writes).await {
                    error!(stream = stream_id, client = %client_addr, err = %e, "TCP flush failed");
                    metrics::inc_errors();
                    break;
                }
            }
        }
    }

    debug!(stream = stream_id, client = %client_addr, "stream task closed");
}

// ─── mode B: TCP listen → UDP forward ──────────────────────────────────────

/// Run in TCP→UDP proxy mode (--reverse).
pub async fn run_tcp_to_udp(cfg: Arc<Config>, worker_id: usize) -> anyhow::Result<()> {
    let listener = bind_tcp_listener(&cfg).with_context(|| format!("bind TCP {}", cfg.listen))?;

    info!(worker = worker_id, listen = %cfg.listen, "TCP listener ready (reverse mode)");

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(worker = worker_id, err = %e, "TCP accept failed");
                metrics::inc_errors();
                continue;
            }
        };

        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_client(cfg, tcp_stream, peer_addr, worker_id).await {
                warn!(peer = %peer_addr, err = %e, "TCP client error");
            }
        });
    }
}

/// Handle one TCP client in reverse mode: TCP frames → UDP datagrams.
async fn handle_tcp_client(
    cfg: Arc<Config>,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    worker_id: usize,
) -> anyhow::Result<()> {
    apply_tcp_opts(&tcp_stream, &cfg);

    // Bind an ephemeral UDP socket to talk to the WireGuard backend.
    let udp_sock = bind_connected_udp(&cfg.remote, &cfg)?;
    udp_sock.connect(cfg.remote).await?;
    let udp_sock = Arc::new(udp_sock);

    let (tcp_rd, mut tcp_wr) = tcp_stream.into_split();
    let mut framed_rd = FramedRead::new(tcp_rd, WireGuardTcpCodec);

    use futures::StreamExt;

    let batch_size = cfg.write_batch.max(1);
    let flush_interval = Duration::from_millis(cfg.flush_ms.max(1));
    let mut udp_buf = BytesMut::with_capacity(cfg.pkt_buf);
    let mut pending_writes = 0usize;
    let mut write_buf = BytesMut::with_capacity(tcp_write_batch_capacity(&cfg, batch_size));
    let mut flush_tick = time::interval(flush_interval);

    debug!(worker = worker_id, peer = %peer_addr, remote = %cfg.remote, "reverse session started");

    loop {
        tokio::select! {
            // Inbound: TCP frame → UDP datagram
            maybe_frame = framed_rd.next() => {
                match maybe_frame {
                    Some(Ok(frame)) => {
                        let len = frame.len();
                        metrics::inc_tcp_frame_rx();
                        let send_started = Instant::now();
                        udp_sock.send(&frame).await?;
                        metrics::observe_udp_send(send_started.elapsed());
                        metrics::inc_rx(len as u64);
                    }
                    Some(Err(e)) => {
                        metrics::inc_errors();
                        return Err(e.into());
                    }
                    None => break,
                }
            }

            // Outbound: UDP datagram → TCP frame
            result = async {
                udp_buf.clear();
                let recv_started = Instant::now();
                udp_sock.recv_buf(&mut udp_buf).await
                    .map(|n| (n, recv_started.elapsed()))
            } => {
                let (n, recv_wait) = result?;
                metrics::observe_udp_recv(recv_wait);
                let data = udp_buf.split().freeze();
                let len = n as u64;
                encode_frame(&data, &mut write_buf).map_err(|e| anyhow::anyhow!("{e}"))?;
                metrics::inc_tx(len);
                metrics::inc_tcp_frame_tx();
                pending_writes += 1;

                if pending_writes >= batch_size {
                    flush_encoded_frames(&mut tcp_wr, &mut write_buf, &mut pending_writes).await?;
                }
            }

            _ = flush_tick.tick(), if pending_writes > 0 => {
                flush_encoded_frames(&mut tcp_wr, &mut write_buf, &mut pending_writes).await?;
            }
        }
    }

    if pending_writes > 0 {
        if let Err(e) = flush_encoded_frames(&mut tcp_wr, &mut write_buf, &mut pending_writes).await {
            error!(peer = %peer_addr, err = %e, "TCP final flush failed");
        }
    }

    debug!(peer = %peer_addr, "reverse session closed");
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────────

/// Bind a UDP socket with SO_REUSEPORT if enabled, or plain SO_REUSEADDR.
fn bind_udp(cfg: &Config, _worker_id: usize) -> anyhow::Result<UdpSocket> {
    let socket = build_udp_socket(cfg.listen, cfg.udp_recv_buf, cfg.udp_send_buf, cfg.reuseport)?;
    socket.bind(&cfg.listen.into())?;

    let std_sock: std::net::UdpSocket = socket.into();
    let tokio_sock = UdpSocket::from_std(std_sock)?;
    Ok(tokio_sock)
}

fn bind_connected_udp(remote: &SocketAddr, cfg: &Config) -> anyhow::Result<UdpSocket> {
    let bind_addr = unspecified_addr_for(remote);
    let socket = build_udp_socket(bind_addr, cfg.udp_recv_buf, cfg.udp_send_buf, false)?;
    socket.bind(&bind_addr.into())?;

    let std_sock: std::net::UdpSocket = socket.into();
    let tokio_sock = UdpSocket::from_std(std_sock)?;
    Ok(tokio_sock)
}

fn build_udp_socket(
    bind_addr: SocketAddr,
    recv_buf: usize,
    send_buf: usize,
    reuseport: bool,
) -> anyhow::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(bind_addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_reuse_address(true)?;

    #[cfg(target_os = "linux")]
    if reuseport {
        socket.set_reuse_port(true)?;
    }

    // Kernel-level buffer sizes.
    socket.set_recv_buffer_size(recv_buf)?;
    socket.set_send_buffer_size(send_buf)?;

    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn bind_tcp_listener(cfg: &Config) -> anyhow::Result<TcpListener> {
    use std::net::TcpListener as StdTcp;

    let socket = socket2::Socket::new(
        socket2::Domain::for_address(cfg.listen),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    socket.set_reuse_address(true)?;

    #[cfg(target_os = "linux")]
    if cfg.reuseport {
        socket.set_reuse_port(true)?;
    }

    socket.set_nonblocking(true)?;
    socket.bind(&cfg.listen.into())?;
    socket.listen(65_535)?;

    let std_listener: StdTcp = socket.into();
    let listener = TcpListener::from_std(std_listener)?;
    Ok(listener)
}

fn apply_tcp_opts(stream: &TcpStream, cfg: &Config) {
    if cfg.nodelay {
        let _ = stream.set_nodelay(true);
    }
    // Best-effort socket buffer sizing via the raw fd.
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    unsafe {
        let buf = cfg.tcp_buf as libc::c_int;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &buf as *const _ as _, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &buf as *const _ as _, 4);
    }
}

fn unspecified_addr_for(addr: &SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn tcp_write_batch_capacity(cfg: &Config, batch_size: usize) -> usize {
    let per_frame = cfg.pkt_buf.saturating_add(2).max(1_502);
    per_frame
        .saturating_mul(batch_size.min(128))
        .clamp(4_096, 8 * 1024 * 1024)
}

async fn flush_encoded_frames<W: AsyncWrite + Unpin>(
    writer: &mut W,
    write_buf: &mut BytesMut,
    pending_writes: &mut usize,
) -> std::io::Result<()> {
    if *pending_writes == 0 || write_buf.is_empty() {
        *pending_writes = 0;
        write_buf.clear();
        return Ok(());
    }

    let flush_started = Instant::now();
    writer.write_all(&write_buf[..]).await?;
    metrics::observe_tcp_flush(*pending_writes as u64, flush_started.elapsed());
    write_buf.clear();
    *pending_writes = 0;
    Ok(())
}
