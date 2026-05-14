//! VLESS + Reality TLS layer.
//!
//! Reality is a TLS-camouflage layer developed by the Xray community.
//!
//! This implementation:
//!   1. Peeks at the raw TLS ClientHello before the handshake to extract
//!      the uTLS random field and verify the Reality short ID.
//!   2. Accepts matching clients as Reality and completes the TLS handshake.
//!   3. Transparently forwards non-matching clients to `dest`, making the
//!      port indistinguishable from a normal HTTPS server.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::config::RealityConfig;

// ── Public entry point ────────────────────────────────────────────────────────

pub async fn accept(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &RealityConfig,
    tls_acceptor: Arc<TlsAcceptor>,
) -> Result<RealityStream> {
    let mut peek_buf = [0u8; 1024];
    let n = peek_tls_client_hello(&stream, &mut peek_buf).await?;
    let client_hello = &peek_buf[..n];

    match verify_reality_client(client_hello, cfg) {
        Ok(()) => {
            debug!("[reality] {peer} short-ID verified, accepting as Reality client");
            let tls_stream = tls_acceptor
                .accept(stream)
                .await
                .context("Reality TLS handshake failed")?;
            Ok(RealityStream::Authenticated(Box::new(tls_stream)))
        }
        Err(e) => {
            debug!("[reality] {peer} not a Reality client ({e}), forwarding to dest");
            forward_to_dest(stream, cfg).await?;
            bail!("reality: non-Reality client forwarded to dest")
        }
    }
}

// ── Reality stream wrapper ────────────────────────────────────────────────────

pub enum RealityStream {
    Authenticated(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl AsyncRead for RealityStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            RealityStream::Authenticated(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RealityStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            RealityStream::Authenticated(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            RealityStream::Authenticated(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            RealityStream::Authenticated(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ── ClientHello peek ──────────────────────────────────────────────────────────

async fn peek_tls_client_hello(stream: &TcpStream, buf: &mut [u8]) -> Result<usize> {
    use std::os::unix::io::AsRawFd;

    stream.readable().await?;

    let fd = stream.as_raw_fd();
    // SAFETY: fd is valid for the duration of this call; buf is a valid mutable slice.
    let n = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            libc::MSG_PEEK,
        )
    };

    if n < 0 {
        let err = std::io::Error::last_os_error();
        bail!("peek ClientHello: {err}");
    }
    Ok(n as usize)
}

// ── Reality short-ID verification ─────────────────────────────────────────────

// TLS ClientHello layout (TLS 1.3 / uTLS):
//   Offset  Len  Field
//     0      1   Content-Type (0x16 = Handshake)
//     1      2   Legacy version
//     3      2   Record length
//     5      1   Handshake type (0x01 = ClientHello)
//     6      3   Handshake length
//     9      2   Client version
//    11     32   Random  ← uTLS embeds ECDH pub key + short ID here
const TLS_RECORD_HEADER: usize = 5;
const HANDSHAKE_HEADER: usize = 4;
const CLIENT_VERSION_LEN: usize = 2;
const RANDOM_OFFSET: usize = TLS_RECORD_HEADER + HANDSHAKE_HEADER + CLIENT_VERSION_LEN;
const RANDOM_LEN: usize = 32;

fn verify_reality_client(client_hello: &[u8], cfg: &RealityConfig) -> Result<()> {
    if client_hello.len() < RANDOM_OFFSET + RANDOM_LEN {
        bail!("too short to be a TLS ClientHello");
    }
    if client_hello[0] != 0x16 {
        bail!("not a TLS record (type={:#x})", client_hello[0]);
    }
    if client_hello[TLS_RECORD_HEADER] != 0x01 {
        bail!("not a ClientHello");
    }

    let random = &client_hello[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN];

    // ── 1. 解码服务端 x25519 私钥 ────────────────────────────────────────────
    let private_key_bytes =
        base64_decode(&cfg.private_key).context("reality: decode private_key")?;
    anyhow::ensure!(
        private_key_bytes.len() == 32,
        "reality: private_key must be 32 bytes (got {})",
        private_key_bytes.len()
    );
    let server_private: [u8; 32] = private_key_bytes.try_into().unwrap();

    // ── 2. 从 Session ID 字段取出客户端 x25519 公钥 ──────────────────────────
    //
    // uTLS 把客户端 x25519 临时公钥（32 字节）写在 Session ID 字段里：
    //   ClientHello body 起点 = RANDOM_OFFSET + RANDOM_LEN
    //   session_id_len (1 byte) @ 该起点
    //   session_id     (32 bytes) 紧随其后
    let session_id_len_offset = RANDOM_OFFSET + RANDOM_LEN;
    if client_hello.len() < session_id_len_offset + 1 {
        bail!("ClientHello too short for session ID length");
    }
    let session_id_len = client_hello[session_id_len_offset] as usize;
    if session_id_len != 32 {
        bail!("session ID length {session_id_len} != 32, not a uTLS Reality client");
    }
    let session_id_offset = session_id_len_offset + 1;
    if client_hello.len() < session_id_offset + 32 {
        bail!("ClientHello too short for session ID data");
    }
    let client_pub: [u8; 32] = client_hello[session_id_offset..session_id_offset + 32]
        .try_into()
        .unwrap();

    // ── 3. x25519 ECDH → shared_secret ───────────────────────────────────────
    let shared_secret = x25519(&server_private, &client_pub);

    // ── 4. HMAC-SHA256(key=shared_secret, data=server_name) → auth_key ───────
    use ring::hmac;
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &shared_secret);
    let auth_tag = hmac::sign(&hmac_key, cfg.server_name.as_bytes());
    let auth_key = auth_tag.as_ref(); // 32 bytes

    // ── 5. 验证 short_id ─────────────────────────────────────────────────────
    //
    // 客户端：random[16..16+n] = short_id XOR auth_key[0..n]
    // 服务端还原并比对配置中的每个 short_id。
    for sid in &cfg.short_ids {
        let sid_bytes =
            hex::decode(sid).with_context(|| format!("reality: decode short_id '{sid}'"))?;
        anyhow::ensure!(
            sid_bytes.len() <= 8,
            "reality: short_id '{sid}' too long (max 8 bytes)"
        );
        let n = sid_bytes.len();
        if n == 0 {
            return Ok(()); // 空 short_id 匹配所有客户端
        }
        let candidate: Vec<u8> = random[16..16 + n]
            .iter()
            .zip(&auth_key[..n])
            .map(|(r, k)| r ^ k)
            .collect();
        if candidate == sid_bytes {
            return Ok(());
        }
    }

    bail!("short-ID mismatch");
}

// ── x25519 scalar multiplication ─────────────────────────────────────────────
fn x25519(server_private: &[u8; 32], client_public: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*server_private);
    let public = PublicKey::from(*client_public);
    secret.diffie_hellman(&public).to_bytes()
}

// ── Transparent forward to dest ───────────────────────────────────────────────

async fn forward_to_dest(mut inbound: TcpStream, cfg: &RealityConfig) -> Result<()> {
    let mut outbound = tokio::net::TcpStream::connect(&cfg.dest)
        .await
        .with_context(|| format!("reality: connect to dest {}", cfg.dest))?;

    let (mut in_r, mut in_w) = inbound.split();
    let (mut out_r, mut out_w) = outbound.split();

    let up = tokio::io::copy(&mut in_r, &mut out_w);
    let down = tokio::io::copy(&mut out_r, &mut in_w);
    let _ = tokio::join!(up, down);
    Ok(())
}

// ── Build TLS acceptor for Reality ────────────────────────────────────────────

/// Build a rustls ServerConfig for the Reality TLS layer.
///
/// Reality clients don't validate the CA chain (they use the ECDH-derived
/// secret instead), so a self-signed certificate works fine.
pub fn build(cfg: &RealityConfig) -> Result<rustls::ServerConfig> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    info!(
        "[reality/tls] generating self-signed cert for SNI: {}",
        cfg.server_name
    );

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![cfg.server_name.clone()])
            .with_context(|| format!("reality: self-signed cert for {}", cfg.server_name))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("reality: serialize key: {e}"))?;

    let mut sc = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("reality: build rustls ServerConfig")?;

    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(sc)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .context("base64 decode")
}
