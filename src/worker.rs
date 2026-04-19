//! Worker thread spawning with optional CPU affinity pinning.

use std::sync::Arc;

use anyhow::Context;
use tracing::{info, warn};

use crate::config::Config;

/// Spawn `n` Tokio runtimes (one per OS thread) and run the proxy function
/// on each.  Each runtime uses a single-threaded scheduler to avoid cross-core
/// migrations — all parallelism comes from running multiple runtimes on
/// different CPU cores.
///
/// With SO_REUSEPORT the kernel distributes incoming UDP packets across all
/// worker sockets via the kernel's socket hashing (RSS-equivalent in software),
/// giving near-linear multi-core scaling.
pub fn spawn_workers<F, Fut>(cfg: Arc<Config>, make_fut: F) -> anyhow::Result<()>
where
    F: Fn(Arc<Config>, usize) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let n = cfg.num_threads();
    info!(threads = n, "starting workers");

    let make_fut = Arc::new(make_fut);
    let mut handles = Vec::with_capacity(n);

    // Collect available CPU IDs for pinning.
    let cpu_ids: Vec<usize> = core_affinity::get_core_ids()
        .unwrap_or_default()
        .into_iter()
        .map(|c| c.id)
        .collect();

    for worker_id in 0..n {
        let cfg = cfg.clone();
        let make_fut = make_fut.clone();
        let cpu_id = cpu_ids.get(worker_id).copied();
        let pin = cfg.cpu_pin;

        let handle = std::thread::Builder::new()
            .name(format!("udp2tcp-w{worker_id}"))
            .spawn(move || {
                // Optionally pin this thread to a specific CPU core.
                if pin {
                    if let Some(id) = cpu_id {
                        #[cfg(target_os = "linux")]
                        {
                            let core = core_affinity::CoreId { id };
                            if core_affinity::set_for_current(core) {
                                info!(worker = worker_id, cpu = id, "pinned to CPU");
                            } else {
                                warn!(worker = worker_id, cpu = id, "CPU pin failed");
                            }
                        }
                        #[cfg(not(target_os = "linux"))]
                        {
                            warn!(worker = worker_id, "CPU pinning only supported on Linux");
                        }
                    }
                }

                // Each worker gets its own single-threaded Tokio runtime.
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .thread_name(format!("udp2tcp-io-w{worker_id}"))
                    .build()
                    .expect("failed to build Tokio runtime");

                rt.block_on(async move {
                    if let Err(e) = make_fut(cfg, worker_id).await {
                        tracing::error!(worker = worker_id, err = %e, "worker exited with error");
                    }
                });
            })
            .with_context(|| format!("spawn worker thread {worker_id}"))?;

        handles.push(handle);
    }

    // Block the main thread until all workers exit.
    for handle in handles {
        let _ = handle.join();
    }

    Ok(())
}
