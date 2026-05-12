//! VLESS TCP listener.
//!
//! Accepts TCP connections and dispatches to the correct transport stack
//! based on config (raw / TLS / WS / WS+TLS), then decodes the VLESS
//! header and proxies the connection.
//!
//! Transport selection mirrors Xray inbound handler structure:
//!   - TLS is the outer layer (if enabled)
//!   - WebSocket upgrade happens inside TLS (if both enabled)
//!   - VLESS header is decoded from the resulting byte stream

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::config::VlessConfig;
use crate::vless::protocol::{decode_request, encode_response, parse_uuid, CMD_TCP};
use crate::vless::transport::{tls as vless_tls, websocket as vless_ws};

pub async fn run(cfg: Arc<VlessConfig>) -> Result<()> {
    // Validate UUID at startup — fail fast
    let uuid_bytes =
        parse_uuid(&cfg.uuid).map_err(|e| anyhow::anyhow!("vless: invalid UUID in config: {e}"))?;

    // Build TLS acceptor once if TLS is enabled
    let tls_server_config = if cfg.transport.tls {
        let sc = vless_tls::build_vless_tls(&cfg.transport)?;
        Some(Arc::new(sc))
    } else {
        None
    };

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "[vless] Listening on {addr} (transport={}, tls={})",
        cfg.transport.r#type, cfg.transport.tls
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = Arc::clone(&cfg);
        let tls_cfg = tls_server_config.clone();

        tokio::spawn(async move {
            debug!("[vless] New connection from {peer}");
            if let Err(e) = handle_conn(stream, peer, &cfg2, uuid_bytes, tls_cfg).await {
                warn!("[vless] Connection from {peer} error: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &VlessConfig,
    uuid_bytes: [u8; 16],
    tls_server_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let transport_type = cfg.transport.r#type.as_str();
    let use_tls = cfg.transport.tls;
    let ws_path = cfg.transport.ws_path.as_str();

    match (transport_type, use_tls) {
        // ── Plain TCP ─────────────────────────────────────────────────────────
        ("tcp", false) => {
            debug!("[vless] {peer} → plain TCP");
            process_vless_stream(stream, peer, uuid_bytes).await
        }

        // ── TCP + TLS ─────────────────────────────────────────────────────────
        ("tcp", true) => {
            debug!("[vless] {peer} → TCP+TLS");
            let sc = tls_server_config.ok_or_else(|| anyhow::anyhow!("TLS config missing"))?;
            let tls_stream = vless_tls::accept(stream, sc).await?;
            process_vless_stream(tls_stream, peer, uuid_bytes).await
        }

        // ── WebSocket (no TLS) ────────────────────────────────────────────────
        ("ws", false) => {
            debug!("[vless] {peer} → WS");
            let ws = vless_ws::accept_plain(stream, ws_path).await?;
            process_vless_stream(ws, peer, uuid_bytes).await
        }

        // ── WebSocket + TLS ───────────────────────────────────────────────────
        ("ws", true) => {
            debug!("[vless] {peer} → WS+TLS");
            let sc = tls_server_config.ok_or_else(|| anyhow::anyhow!("TLS config missing"))?;
            let tls_stream = vless_tls::accept(stream, sc).await?;
            let ws = vless_ws::accept_tls(tls_stream, ws_path).await?;
            process_vless_stream(ws, peer, uuid_bytes).await
        }

        _ => anyhow::bail!("vless: unknown transport type '{transport_type}'"),
    }
}

/// Decode the VLESS header and proxy to upstream.
/// Equivalent to Xray's Handler.Process() after transport is established.
async fn process_vless_stream<S>(
    mut stream: S,
    peer: SocketAddr,
    uuid_bytes: [u8; 16],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Decode VLESS request header
    let request = decode_request(&mut stream, &uuid_bytes)
        .await
        .map_err(|e| {
            warn!("[vless] {peer} header decode failed: {e}");
            e
        })?;

    if request.command != CMD_TCP {
        anyhow::bail!("vless: UDP not supported (cmd={:#x})", request.command);
    }

    info!("[vless] {peer} → {}", request.target);

    // 2. Connect to upstream
    let outbound = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(&request.target),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("[vless] {peer} connect {} failed: {e}", request.target);
            // No error response in VLESS protocol — just drop (same as Xray)
            return Err(e.into());
        }
        Err(_) => {
            warn!("[vless] {peer} connect {} timeout", request.target);
            anyhow::bail!("connect timeout");
        }
    };

    // 3. Send VLESS response header: [version=0x00][addon_len=0x00]
    //    Mirrors Xray EncodeResponseHeader. Must precede any upstream data.
    encode_response(&mut stream).await?;

    // 4. Bidirectional relay
    relay(stream, outbound, peer, &request.target).await
}

/// Bidirectional byte relay.
///
/// We use tokio::io::copy in two concurrent async blocks joined with
/// tokio::join! so that the borrows from tokio::io::split() are valid
/// (both halves are dropped before relay() returns).
///
/// This mirrors Xray's task.Run(uplink, downlink) pattern.
async fn relay<S>(inbound: S, outbound: TcpStream, peer: SocketAddr, target: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut out_r, mut out_w) = outbound.into_split();

    // tokio::io::split borrows; both halves are used only inside this function
    // so the borrow is valid. We join! instead of spawn! to keep the borrows alive.
    let (mut in_r, mut in_w) = tokio::io::split(inbound);

    let target_str = target.to_string();

    let uplink = async {
        match tokio::io::copy(&mut in_r, &mut out_w).await {
            Ok(n) => debug!("[vless] {peer}→{target_str} uplink {n}B"),
            Err(e) => debug!("[vless] {peer}→{target_str} uplink: {e}"),
        }
        let _ = out_w.shutdown().await;
    };

    let target_str2 = target.to_string();
    let downlink = async {
        match tokio::io::copy(&mut out_r, &mut in_w).await {
            Ok(n) => debug!("[vless] {target_str2}→{peer} downlink {n}B"),
            Err(e) => debug!("[vless] {target_str2}→{peer} downlink: {e}"),
        }
        let _ = in_w.shutdown().await;
    };

    tokio::join!(uplink, downlink);
    debug!("[vless] relay closed: {peer} ↔ {target}");
    Ok(())
}
