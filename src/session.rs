//! UDP client session management.
//!
//! In UDP→TCP mode every unique (src_ip, src_port) pair that sends a UDP
//! datagram gets its own logical session.  A session holds the channel
//! through which the worker sends packets to the TCP forwarding task
//! associated with that session.
//!
//! Sessions are stored in a DashMap (lock-free concurrent hashmap) keyed
//! by the UDP client's SocketAddr.  Expired/idle sessions are reaped by
//! a background sweeper task.

use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    sync::Arc,
    sync::OnceLock,
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, warn};

/// A handle to a single UDP client session.
#[derive(Debug, Clone)]
pub struct Session {
    /// Channels to send outbound UDP datagrams to per-stream TCP forwarding tasks.
    txs: Arc<Vec<mpsc::Sender<Bytes>>>,
    /// Round-robin index for selecting the next stream.
    next_tx: Arc<AtomicUsize>,
    /// Last time this session was used (for idle timeout sweeping).
    pub last_seen_millis: Arc<AtomicU64>,
}

impl Session {
    pub fn new(txs: Vec<mpsc::Sender<Bytes>>) -> Self {
        Self {
            txs: Arc::new(txs),
            next_tx: Arc::new(AtomicUsize::new(0)),
            last_seen_millis: Arc::new(AtomicU64::new(now_millis())),
        }
    }

    pub fn try_send(&self, mut pkt: Bytes) -> Result<(), Bytes> {
        let count = self.txs.len();
        if count == 0 {
            return Err(pkt);
        }

        let start = self.next_tx.fetch_add(1, Ordering::Relaxed) % count;
        for offset in 0..count {
            let idx = (start + offset) % count;
            let send_pkt = if offset + 1 == count {
                pkt
            } else {
                pkt.clone()
            };
            match self.txs[idx].try_send(send_pkt) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(returned)) => {
                    pkt = returned;
                    continue;
                }
                Err(TrySendError::Closed(returned)) => {
                    pkt = returned;
                    debug!("session stream channel {} is closed", idx);
                    continue;
                }
            }
        }

        Err(pkt)
    }

    pub fn touch(&self) {
        self.last_seen_millis.store(now_millis(), Ordering::Relaxed);
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        now_millis().saturating_sub(self.last_seen_millis.load(Ordering::Relaxed))
            > duration_to_millis(timeout)
    }
}

fn now_millis() -> u64 {
    session_clock_start().elapsed().as_millis() as u64
}

fn duration_to_millis(duration: Duration) -> u64 {
    const MAX_U64_AS_U128: u128 = u64::MAX as u128;
    duration.as_millis().min(MAX_U64_AS_U128) as u64
}

fn session_clock_start() -> &'static Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now)
}

/// Concurrent session table.
pub struct SessionTable {
    inner: dashmap::DashMap<SocketAddr, Session>,
    max: usize,
    idle_timeout: Duration,
}

impl SessionTable {
    pub fn new(max: usize, idle_timeout: Duration) -> Self {
        Self {
            inner: dashmap::DashMap::with_capacity(max.min(65536)),
            max,
            idle_timeout,
        }
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<Session> {
        self.inner.get(addr).map(|s| {
            s.touch();
            s.clone()
        })
    }

    /// Insert a new session.  Returns false and drops the entry if the table
    /// is full (back-pressure).
    pub fn insert(&self, addr: SocketAddr, session: Session) -> bool {
        if self.inner.len() >= self.max {
            warn!(
                "session table full ({} entries), dropping new session from {}",
                self.max, addr
            );
            return false;
        }
        self.inner.insert(addr, session);
        true
    }

    pub fn remove(&self, addr: &SocketAddr) {
        self.inner.remove(addr);
        debug!("session removed: {}", addr);
    }

    /// Sweep and remove sessions that have been idle longer than the timeout.
    pub fn sweep_idle(&self) {
        self.inner
            .retain(|addr, session| {
                let idle = session.is_idle(self.idle_timeout);
                if idle {
                    debug!("evicting idle session: {}", addr);
                }
                !idle
            });
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}
