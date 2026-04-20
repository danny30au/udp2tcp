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
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
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
    pub last_seen: Arc<std::sync::Mutex<Instant>>,
}

impl Session {
    pub fn new(txs: Vec<mpsc::Sender<Bytes>>) -> Self {
        Self {
            txs: Arc::new(txs),
            next_tx: Arc::new(AtomicUsize::new(0)),
            last_seen: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    pub fn try_send(&self, pkt: Bytes) -> Result<(), Bytes> {
        let count = self.txs.len();
        if count == 0 {
            return Err(pkt);
        }

        let start = self.next_tx.fetch_add(1, Ordering::Relaxed) % count;
        for offset in 0..count {
            let idx = (start + offset) % count;
            match self.txs[idx].try_send(pkt.clone()) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(_)) => continue,
                Err(TrySendError::Closed(_)) => {
                    debug!("session stream channel {} is closed", idx);
                    continue;
                }
            }
        }

        Err(pkt)
    }

    pub fn touch(&self) {
        if let Ok(mut t) = self.last_seen.lock() {
            *t = Instant::now();
        }
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_seen
            .lock()
            .map(|t| t.elapsed() > timeout)
            .unwrap_or(false)
    }
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
