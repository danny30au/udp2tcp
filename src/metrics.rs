//! In-process metrics (always available, Prometheus export requires --features metrics).

use std::sync::atomic::{AtomicU64, Ordering};

pub static PACKETS_RX: AtomicU64 = AtomicU64::new(0);
pub static PACKETS_TX: AtomicU64 = AtomicU64::new(0);
pub static BYTES_RX: AtomicU64 = AtomicU64::new(0);
pub static BYTES_TX: AtomicU64 = AtomicU64::new(0);
pub static SESSIONS_ACTIVE: AtomicU64 = AtomicU64::new(0);
pub static ERRORS: AtomicU64 = AtomicU64::new(0);

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

/// Log a periodic stats summary at INFO level.
pub fn log_stats() {
    tracing::info!(
        packets_rx = PACKETS_RX.load(Ordering::Relaxed),
        packets_tx = PACKETS_TX.load(Ordering::Relaxed),
        bytes_rx = BYTES_RX.load(Ordering::Relaxed),
        bytes_tx = BYTES_TX.load(Ordering::Relaxed),
        sessions = SESSIONS_ACTIVE.load(Ordering::Relaxed),
        errors = ERRORS.load(Ordering::Relaxed),
        "stats"
    );
}
