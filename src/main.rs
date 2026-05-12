mod config;
mod congestion;
mod hysteria2;
mod proxy;
mod tls;
mod vless;

use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Install TLS crypto provider (required by rustls + quinn) ─────────────
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // ── Parse CLI: ./ruproxy -c config.yaml ──────────────────────────────────
    let config_path = parse_config_arg();

    // ── Load config ───────────────────────────────────────────────────────────
    let cfg = config::load(&config_path)
        .with_context(|| format!("failed to load config: {config_path}"))?;

    // ── Init logging ──────────────────────────────────────────────────────────
    let filter = EnvFilter::try_new(&cfg.log.level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!("ruproxy starting, config: {config_path}");

    // ── Validate: at least one protocol must be enabled ───────────────────────
    let hy2_enabled = cfg.hysteria2.as_ref().is_some_and(|c| c.enable);
    let vless_enabled = cfg.vless.as_ref().is_some_and(|c| c.enable);

    if !hy2_enabled && !vless_enabled {
        anyhow::bail!("no protocols enabled — set hysteria2.enable or vless.enable to true");
    }

    let mut handles = Vec::new();

    // ── Hysteria2 server ──────────────────────────────────────────────────────
    if hy2_enabled {
        let hy2_cfg = Arc::new(cfg.hysteria2.clone().unwrap());
        info!("[hy2] enabled, listen: {}", hy2_cfg.listen);
        let h = tokio::spawn(async move {
            if let Err(e) = hysteria2::server::run(hy2_cfg).await {
                tracing::error!("[hy2] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── VLESS server ──────────────────────────────────────────────────────────
    if vless_enabled {
        let vless_cfg = Arc::new(cfg.vless.clone().unwrap());
        info!("[vless] enabled, listen: {}", vless_cfg.listen);
        info!(
            "[vless] transport: type={}, tls={}",
            vless_cfg.transport.r#type, vless_cfg.transport.tls
        );
        let h = tokio::spawn(async move {
            if let Err(e) = vless::listener::run(vless_cfg).await {
                tracing::error!("[vless] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── Wait for Ctrl-C ───────────────────────────────────────────────────────
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    info!("Shutting down...");

    for h in handles {
        h.abort();
    }

    Ok(())
}

/// Parse `-c <path>` from argv, defaulting to "config.yaml".
fn parse_config_arg() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-c" {
            if let Some(path) = args.get(i + 1) {
                return path.clone();
            }
        }
        i += 1;
    }
    "config.yaml".to_string()
}
