//! Hysteria2 authentication module (H3 handshake)
//! Identical logic to original ruhy, updated to use Hysteria2Config.

use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use h3::server::RequestStream;
use h3_quinn::BidiStream;
use hyper::http::{Response, StatusCode};
use rand::Rng;
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};

use crate::config::{AuthConfig, Hysteria2Config};

pub const HYSTERIA_AUTH_HEADER: &str = "Hysteria-Auth";
pub const STATUS_AUTH_OK: u16 = 233;
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

pub enum AuthResult {
    Ok,
    Fail(String),
}

pub async fn authenticate(conn: quinn::Connection, cfg: &Hysteria2Config) -> AuthResult {
    let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
        Ok(c) => c,
        Err(e) => return AuthResult::Fail(format!("H3 connection init failed: {e}")),
    };

    match do_handshake(&mut h3_conn, &cfg.auth).await {
        Ok(true) => {
            tokio::spawn(async move { while let Ok(Some(_)) = h3_conn.accept().await {} });
            AuthResult::Ok
        }
        Ok(false) => AuthResult::Fail("wrong credentials".to_string()),
        Err(e) => AuthResult::Fail(format!("handshake error: {e}")),
    }
}

async fn do_handshake(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    auth_cfg: &AuthConfig,
) -> Result<bool> {
    let (req, mut stream) = match h3_conn.accept().await? {
        Some(resolver) => resolver.resolve_request().await?,
        None => anyhow::bail!("connection closed before auth request"),
    };

    let auth_header = req
        .headers()
        .get(HYSTERIA_AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    debug!(
        "[hy2] Auth attempt, header present: {}",
        !auth_header.is_empty()
    );

    let ok = match auth_cfg {
        AuthConfig::Password { password } => auth_header == password.as_str(),
        AuthConfig::None => true,
    };

    if ok {
        send_h3_response(&mut stream, STATUS_AUTH_OK, true).await?;
        debug!("[hy2] Auth OK");
        Ok(true)
    } else {
        warn!("[hy2] Auth failed: wrong password");
        send_h3_response(&mut stream, 403, false).await?;
        Ok(false)
    }
}

fn gen_padding(min: usize, max: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(min..max);
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

async fn send_h3_response(
    stream: &mut RequestStream<BidiStream<Bytes>, Bytes>,
    status: u16,
    udp_enabled: bool,
) -> Result<()> {
    let resp = Response::builder()
        .status(StatusCode::from_u16(status)?)
        .header("Hysteria-UDP", if udp_enabled { "true" } else { "false" })
        .header("Hysteria-CC-RX", "0")
        .header("Hysteria-Padding", gen_padding(256, 2048))
        .body(())?;
    stream.send_response(resp).await?;
    stream.finish().await?;
    Ok(())
}

/// Hysteria2 TCP request frame (frame type 0x401 already consumed by caller):
///   [varint] addr_len
///   [bytes]  addr (host:port)
///   [varint] padding_len
///   [bytes]  padding (ignored)
pub async fn read_tcp_request(stream: &mut quinn::RecvStream) -> Result<String> {
    let addr_len = read_varint_stream(stream).await? as usize;
    anyhow::ensure!(
        addr_len > 0 && addr_len <= 2048,
        "invalid addr_len: {addr_len}"
    );

    let mut addr_buf = vec![0u8; addr_len];
    stream.read_exact(&mut addr_buf).await?;
    let addr = String::from_utf8(addr_buf)?;

    let pad_len = read_varint_stream(stream).await? as usize;
    if pad_len > 0 && pad_len <= 4096 {
        let mut discard = vec![0u8; pad_len];
        let _ = stream.read_exact(&mut discard).await;
    }

    Ok(addr)
}

pub async fn write_tcp_response(
    stream: &mut quinn::SendStream,
    ok: bool,
    message: &str,
) -> Result<()> {
    let status: u8 = if ok { 0x00 } else { 0x01 };
    let msg = message.as_bytes();
    let pad_len = rand::thread_rng().gen_range(128usize..1024);
    let padding = gen_padding(pad_len, pad_len + 1).into_bytes();
    let mut buf = BytesMut::new();
    buf.put_u8(status);
    write_varint(&mut buf, msg.len() as u64);
    buf.put_slice(msg);
    write_varint(&mut buf, pad_len as u64);
    buf.put_slice(&padding);
    use tokio::io::AsyncWriteExt;
    stream.write_all(&buf).await?;
    Ok(())
}

async fn read_varint_stream(stream: &mut quinn::RecvStream) -> Result<u64> {
    let first = stream.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut val = (first & 0x3f) as u64;
    for _ in 1..len {
        let b = stream.read_u8().await?;
        val = (val << 8) | b as u64;
    }
    Ok(val)
}

fn write_varint(buf: &mut BytesMut, val: u64) {
    if val < 64 {
        buf.put_u8(val as u8);
    } else if val < 16384 {
        buf.put_u16(0x4000 | val as u16);
    } else if val < 1_073_741_824 {
        buf.put_u32(0x8000_0000 | val as u32);
    } else {
        buf.put_u64(0xc000_0000_0000_0000 | val);
    }
}
