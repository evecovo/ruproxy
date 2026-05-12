//! Hysteria2 QUIC server core (unchanged from original ruhy implementation)

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::hysteria2::auth::{authenticate, read_tcp_request, AuthResult, FRAME_TYPE_TCP_REQUEST};
use crate::config::Hysteria2Config;
use crate::congestion::brutal::BrutalFactory;
use crate::proxy::{handle_tcp_stream, handle_udp_session, parse_udp_frame, UdpFrame};
use crate::tls::build_hy2_tls;

type SessionMap = Arc<Mutex<HashMap<u32, mpsc::Sender<UdpFrame>>>>;

const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONN_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_INCOMING_STREAMS: u32 = 1024;

pub async fn run(cfg: Arc<Hysteria2Config>) -> Result<()> {
    let tls_config = build_hy2_tls(&cfg.tls)?;

    let brutal_bps = cfg.bandwidth.up_bps();
    if let Some(bps) = brutal_bps {
        info!("[hy2] Congestion: Brutal @ {} Mbps", bps * 8 / 1_000_000);
    } else {
        info!("[hy2] Congestion: CUBIC (no bandwidth configured)");
    }

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(MAX_INCOMING_STREAMS.into())
        .stream_receive_window(STREAM_RECEIVE_WINDOW.into())
        .receive_window(CONN_RECEIVE_WINDOW.into())
        .max_idle_timeout(Some(MAX_IDLE_TIMEOUT.try_into()?))
        .keep_alive_interval(Some(Duration::from_secs(10)));

    if let Some(bps) = brutal_bps {
        transport.congestion_controller_factory(BrutalFactory::new(bps));
    }

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));
    server_config.transport_config(Arc::new(transport));

    let addr: SocketAddr = cfg.listen.parse()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!("[hy2] Listening on {}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        let cfg2 = Arc::clone(&cfg);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, cfg2).await {
                error!("[hy2] Connection error: {e:#}");
            }
        });
    }

    Ok(())
}

async fn handle_connection(incoming: quinn::Incoming, cfg: Arc<Hysteria2Config>) -> Result<()> {
    let conn = incoming.await?;
    let peer = conn.remote_address();
    info!("[hy2] New connection from {peer}");

    match authenticate(conn.clone(), &cfg).await {
        AuthResult::Ok => {
            info!("[hy2] Authenticated: {peer}");
        }
        AuthResult::Fail(msg) => {
            warn!("[hy2] Auth failed from {peer}: {msg}");
            conn.close(quinn::VarInt::from_u32(1), b"auth failed");
            return Ok(());
        }
    }

    let session_map: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let conn2 = conn.clone();
    let smap2 = Arc::clone(&session_map);
    let cfg2 = Arc::clone(&cfg);
    tokio::spawn(async move {
        if let Err(e) = datagram_loop(conn2, cfg2, smap2).await {
            debug!("[hy2] Datagram loop ended for {peer}: {e}");
        }
    });

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let cfg3 = Arc::clone(&cfg);
                tokio::spawn(async move {
                    if let Err(e) = handle_quic_stream(send, recv, cfg3).await {
                        debug!("[hy2] QUIC stream error: {e}");
                    }
                });
            }
            Err(e) => {
                info!("[hy2] Connection closed from {peer}: {e}");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_quic_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    _cfg: Arc<Hysteria2Config>,
) -> Result<()> {
    let frame_type = {
        let first = recv.read_u8().await?;
        let len = 1usize << (first >> 6);
        let mut val = (first & 0x3f) as u64;
        for _ in 1..len {
            let b = recv.read_u8().await?;
            val = (val << 8) | b as u64;
        }
        val
    };

    if frame_type != FRAME_TYPE_TCP_REQUEST {
        debug!("[hy2] Unknown frame type: {frame_type:#x}, ignoring stream");
        return Ok(());
    }

    let addr = read_tcp_request(&mut recv).await?;
    debug!("[hy2] TCP proxy → {addr}");

    handle_tcp_stream(send, recv, addr).await
}

async fn datagram_loop(
    conn: quinn::Connection,
    cfg: Arc<Hysteria2Config>,
    session_map: SessionMap,
) -> Result<()> {
    loop {
        let datagram = conn.read_datagram().await?;
        let frame = match parse_udp_frame(datagram) {
            Ok(f) => f,
            Err(e) => {
                warn!("[hy2] Bad UDP frame: {e}");
                continue;
            }
        };

        let session_id = frame.session_id;
        let maybe_tx = {
            let map = session_map.lock().await;
            map.get(&session_id).cloned()
        };

        if let Some(tx) = maybe_tx {
            if tx.send(frame).await.is_err() {
                session_map.lock().await.remove(&session_id);
            }
        } else {
            let (tx, rx) = mpsc::channel::<UdpFrame>(256);
            session_map.lock().await.insert(session_id, tx);

            let conn2 = conn.clone();
            let smap2 = Arc::clone(&session_map);

            tokio::spawn(async move {
                let send_fn: Arc<dyn Fn(bytes::Bytes) -> Result<()> + Send + Sync> =
                    Arc::new(move |pkt: bytes::Bytes| {
                        conn2.send_datagram(pkt)?;
                        Ok(())
                    });

                if let Err(e) = handle_udp_session(session_id, frame, rx, send_fn).await {
                    debug!("[hy2] UDP session {session_id} error: {e}");
                }

                smap2.lock().await.remove(&session_id);
                let _ = cfg;
            });
        }
    }
}
