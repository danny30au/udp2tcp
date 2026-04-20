use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tracing::info;

use udp2tcp_lib::{
    config::Config,
    metrics,
    proxy::{run_tcp_to_udp, run_udp_to_tcp},
    worker::spawn_workers,
};

fn main() -> anyhow::Result<()> {
    let cfg = Arc::new(Config::parse());

    // Initialize structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cfg.log_level.parse().unwrap_or_default()),
        )
        .with_target(false)
        .with_thread_ids(true)
        .compact()
        .init();

    daemonize_if_requested(&cfg)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        threads = cfg.num_threads(),
        listen  = %cfg.listen,
        remote  = %cfg.remote,
        mode    = if cfg.reverse { "tcp→udp (reverse)" } else { "udp→tcp" },
        reuseport = cfg.reuseport,
        cpu_pin   = cfg.cpu_pin,
        daemon    = cfg.daemon,
        "udp2tcp starting"
    );

    // Print sysctl tuning advice if buffers are at defaults.
    if cfg.udp_recv_buf > 4_194_304 {
        info!(
            "tip: raise kernel UDP buffers for full throughput:\n  \
             sysctl -w net.core.rmem_max=134217728\n  \
             sysctl -w net.core.wmem_max=134217728\n  \
             sysctl -w net.core.netdev_max_backlog=5000"
        );
    }

    // Periodic stats logger — runs in a dedicated thread.
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(Duration::from_secs(60));
            metrics::log_stats();
        }
    });

    if cfg.reverse {
        // TCP → UDP  (server / endpoint side)
        spawn_workers(cfg, |cfg, worker_id| async move {
            run_tcp_to_udp(cfg, worker_id)
                .await
                .with_context(|| format!("worker {worker_id} (reverse)"))
        })
    } else {
        // UDP → TCP  (client side)
        spawn_workers(cfg, |cfg, worker_id| async move {
            run_udp_to_tcp(cfg, worker_id)
                .await
                .with_context(|| format!("worker {worker_id}"))
        })
    }
}

#[cfg(target_os = "linux")]
fn daemonize_if_requested(cfg: &Config) -> anyhow::Result<()> {
    if !cfg.daemon {
        return Ok(());
    }

    const NO_CHDIR: libc::c_int = 1;
    const NO_CLOSE_STDIO: libc::c_int = 1;

    let rc = unsafe { libc::daemon(NO_CHDIR, NO_CLOSE_STDIO) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to daemonize process - check system permissions and resources");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn daemonize_if_requested(cfg: &Config) -> anyhow::Result<()> {
    if cfg.daemon {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "--daemon is only supported on Linux",
        )
        .into());
    }
    Ok(())
}
