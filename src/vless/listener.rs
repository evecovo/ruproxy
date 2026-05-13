//! VLESS TCP listener.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::VlessConfig;
use crate::vless::protocol::{decode_request, encode_response, parse_uuid, CMD_TCP};
use crate::vless::transport::{reality as vless_reality, tls as vless_tls, websocket as vless_ws};

pub async fn run(cfg: Arc<VlessConfig>) -> Result<()> {
    let uuid_bytes =
        parse_uuid(&cfg.uuid).map_err(|e| anyhow::anyhow!("vless: invalid UUID in config: {e}"))?;

    let transport_type = cfg.transport.r#type.as_str();

    let tls_acceptor: Option<Arc<TlsAcceptor>> = match transport_type {
        "reality" => {
            let reality_cfg = cfg.transport.reality.as_ref().ok_or_else(|| {
                anyhow::anyhow!("vless: transport.type=reality requires [vless.transport.reality]")
            })?;
            let sc = vless_reality::build_reality_tls(reality_cfg)?;
            Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
        }
        _ if cfg.transport.tls => {
            let sc = vless_tls::build_vless_tls(&cfg.transport)?;
            Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
        }
        _ => None,
    };

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "[vless] Listening on {addr} (transport={}, tls={})",
        transport_type, cfg.transport.tls
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = Arc::clone(&cfg);
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            debug!("[vless] New connection from {peer}");
            if let Err(e) = handle_conn(stream, peer, &cfg2, uuid_bytes, acceptor).await {
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
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let transport_type = cfg.transport.r#type.as_str();
    let use_tls = cfg.transport.tls;
    let ws_path = cfg.transport.ws_path.as_str();
    let ws_host = cfg.transport.ws_host.as_deref();

    match transport_type {
        "reality" => {
            debug!("[vless] {peer} → Reality");
            let reality_cfg = cfg.transport.reality.as_ref().ok_or_else(|| {
                anyhow::anyhow!("vless: missing [vless.transport.reality] section")
            })?;
            let acceptor =
                tls_acceptor.ok_or_else(|| anyhow::anyhow!("vless: Reality TLS acceptor missing"))?;

            let reality_stream = vless_reality::accept(stream, peer, reality_cfg, acceptor).await?;
            process_vless_stream(reality_stream, peer, uuid_bytes).await
        }

        "tcp" if !use_tls => {
            debug!("[vless] {peer} → plain TCP");
            process_vless_stream(stream, peer, uuid_bytes).await
        }

        "tcp" => {
            debug!("[vless] {peer} → TCP+TLS");
            let acceptor =
                tls_acceptor.ok_or_else(|| anyhow::anyhow!("[vless] TLS acceptor missing"))?;
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| anyhow::anyhow!("vless TLS handshake failed: {e}"))?;
            process_vless_stream(tls_stream, peer, uuid_bytes).await
        }

        "ws" if !use_tls => {
            debug!("[vless] {peer} → WS");
            let ws = vless_ws::accept_plain(stream, ws_path, ws_host).await?;
            process_vless_stream(ws, peer, uuid_bytes).await
        }

        "ws" => {
            debug!("[vless] {peer} → WS+TLS");
            let acceptor =
                tls_acceptor.ok_or_else(|| anyhow::anyhow!("[vless] TLS acceptor missing"))?;
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| anyhow::anyhow!("vless WS+TLS handshake failed: {e}"))?;
            let ws = vless_ws::accept_tls(tls_stream, ws_path, ws_host).await?;
            process_vless_stream(ws, peer, uuid_bytes).await
        }

        other => anyhow::bail!("vless: unknown transport type '{other}'"),
    }
}

async fn process_vless_stream<S>(
    mut stream: S,
    peer: SocketAddr,
    uuid_bytes: [u8; 16],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

    let outbound = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(&request.target),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("[vless] {peer} connect {} failed: {e}", request.target);
            return Err(e.into());
        }
        Err(_) => {
            warn!("[vless] {peer} connect {} timeout", request.target);
            anyhow::bail!("connect timeout");
        }
    };

    encode_response(&mut stream).await?;

    relay(stream, outbound, peer, &request.target).await
}

async fn relay<S>(inbound: S, outbound: TcpStream, peer: SocketAddr, target: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut out_r, mut out_w) = outbound.into_split();
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
