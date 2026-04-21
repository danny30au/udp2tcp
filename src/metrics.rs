//! In-process metrics (always available, Prometheus export requires --features metrics).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub static PACKETS_RX: AtomicU64 = AtomicU64::new(0);
pub static PACKETS_TX: AtomicU64 = AtomicU64::new(0);
pub static BYTES_RX: AtomicU64 = AtomicU64::new(0);
pub static BYTES_TX: AtomicU64 = AtomicU64::new(0);
pub static SESSIONS_ACTIVE: AtomicU64 = AtomicU64::new(0);
pub static ERRORS: AtomicU64 = AtomicU64::new(0);
pub static QUEUE_DROPS: AtomicU64 = AtomicU64::new(0);
pub static UDP_RECV_CALLS: AtomicU64 = AtomicU64::new(0);
pub static UDP_SEND_CALLS: AtomicU64 = AtomicU64::new(0);
pub static UDP_RECV_WAIT_NS: AtomicU64 = AtomicU64::new(0);
pub static UDP_SEND_WAIT_NS: AtomicU64 = AtomicU64::new(0);
pub static TCP_CONNECTS: AtomicU64 = AtomicU64::new(0);
pub static TCP_CONNECT_NS: AtomicU64 = AtomicU64::new(0);
pub static TCP_FRAMES_RX: AtomicU64 = AtomicU64::new(0);
pub static TCP_FRAMES_TX: AtomicU64 = AtomicU64::new(0);
pub static TCP_FLUSHES: AtomicU64 = AtomicU64::new(0);
pub static TCP_BATCHED_FRAMES: AtomicU64 = AtomicU64::new(0);
pub static TCP_FLUSH_NS: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
pub fn inc_rx(bytes: u64) {
    PACKETS_RX.fetch_add(1, Ordering::Relaxed);
    BYTES_RX.fetch_add(bytes, Ordering::Relaxed);
}

#[inline(always)]
pub fn inc_tx(bytes: u64) {
    PACKETS_TX.fetch_add(1, Ordering::Relaxed);
    BYTES_TX.fetch_add(bytes, Ordering::Relaxed);
}

#[inline(always)]
pub fn inc_errors() {
    ERRORS.fetch_add(1, Ordering::Relaxed);
}

#[inline(always)]
pub fn inc_queue_drops() {
    QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
}

#[inline(always)]
pub fn observe_udp_recv(wait: Duration) {
    UDP_RECV_CALLS.fetch_add(1, Ordering::Relaxed);
    UDP_RECV_WAIT_NS.fetch_add(duration_to_nanos(wait), Ordering::Relaxed);
}

#[inline(always)]
pub fn observe_udp_send(wait: Duration) {
    UDP_SEND_CALLS.fetch_add(1, Ordering::Relaxed);
    UDP_SEND_WAIT_NS.fetch_add(duration_to_nanos(wait), Ordering::Relaxed);
}

#[inline(always)]
pub fn observe_tcp_connect(wait: Duration) {
    TCP_CONNECTS.fetch_add(1, Ordering::Relaxed);
    TCP_CONNECT_NS.fetch_add(duration_to_nanos(wait), Ordering::Relaxed);
}

#[inline(always)]
pub fn inc_tcp_frame_rx() {
    TCP_FRAMES_RX.fetch_add(1, Ordering::Relaxed);
}

#[inline(always)]
pub fn inc_tcp_frame_tx() {
    TCP_FRAMES_TX.fetch_add(1, Ordering::Relaxed);
}

#[inline(always)]
pub fn observe_tcp_flush(frames: u64, wait: Duration) {
    TCP_FLUSHES.fetch_add(1, Ordering::Relaxed);
    TCP_BATCHED_FRAMES.fetch_add(frames, Ordering::Relaxed);
    TCP_FLUSH_NS.fetch_add(duration_to_nanos(wait), Ordering::Relaxed);
}

/// Log a periodic stats summary at INFO level.
pub fn log_stats() {
    let udp_recv_calls = UDP_RECV_CALLS.load(Ordering::Relaxed);
    let udp_send_calls = UDP_SEND_CALLS.load(Ordering::Relaxed);
    let tcp_connects = TCP_CONNECTS.load(Ordering::Relaxed);
    let tcp_flushes = TCP_FLUSHES.load(Ordering::Relaxed);
    let tcp_batched_frames = TCP_BATCHED_FRAMES.load(Ordering::Relaxed);

    tracing::info!(
        packets_rx = PACKETS_RX.load(Ordering::Relaxed),
        packets_tx = PACKETS_TX.load(Ordering::Relaxed),
        bytes_rx = BYTES_RX.load(Ordering::Relaxed),
        bytes_tx = BYTES_TX.load(Ordering::Relaxed),
        sessions = SESSIONS_ACTIVE.load(Ordering::Relaxed),
        errors = ERRORS.load(Ordering::Relaxed),
        queue_drops = QUEUE_DROPS.load(Ordering::Relaxed),
        udp_recv_calls,
        udp_send_calls,
        udp_recv_avg_us = avg_nanos(UDP_RECV_WAIT_NS.load(Ordering::Relaxed), udp_recv_calls),
        udp_send_avg_us = avg_nanos(UDP_SEND_WAIT_NS.load(Ordering::Relaxed), udp_send_calls),
        tcp_connects,
        tcp_connect_avg_us = avg_nanos(TCP_CONNECT_NS.load(Ordering::Relaxed), tcp_connects),
        tcp_frames_rx = TCP_FRAMES_RX.load(Ordering::Relaxed),
        tcp_frames_tx = TCP_FRAMES_TX.load(Ordering::Relaxed),
        tcp_flushes,
        tcp_flush_avg_us = avg_nanos(TCP_FLUSH_NS.load(Ordering::Relaxed), tcp_flushes),
        tcp_frames_per_flush = avg_units(tcp_batched_frames, tcp_flushes),
        "stats"
    );
}

#[inline(always)]
fn duration_to_nanos(duration: Duration) -> u64 {
    const MAX_U64_AS_U128: u128 = u64::MAX as u128;
    duration.as_nanos().min(MAX_U64_AS_U128) as u64
}

#[inline(always)]
fn avg_nanos(total_nanos: u64, count: u64) -> u64 {
    if count == 0 {
        return 0;
    }
    total_nanos / count / 1_000
}

#[inline(always)]
fn avg_units(total: u64, count: u64) -> u64 {
    if count == 0 {
        return 0;
    }
    total / count
}
