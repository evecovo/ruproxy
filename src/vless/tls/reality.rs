//! VLESS + Reality TLS layer — 正确实现
//!
//! Reality 协议的完整握手流程（参考 sing-box reality_client.go / Xray reality 包）：
//!
//! ## 客户端发送的 ClientHello 结构
//!
//!   字段           位置
//!   ──────────────────────────────────────────────────────────────────
//!   Random         TLS Record[11..43]（32 字节）
//!   Session ID     ClientHello body 中的 session_id（32 字节）
//!   KeyShare       扩展 0x0033，包含客户端 x25519 临时公钥（32 字节）
//!
//! ## 服务端验证流程
//!
//!   1. 从 KeyShare 扩展提取客户端 x25519 临时公钥（ecdhe_pub）
//!   2. raw_auth_key = x25519(server_private, ecdhe_pub)
//!   3. auth_key     = HKDF-SHA256(ikm=raw_auth_key, salt=random[:20], info="REALITY")
//!   4. 根据 cipher suites 选择 AEAD 算法（AES-GCM 或 ChaCha20-Poly1305）解密 Session ID：
//!      - nonce     = random[20:32]（12 字节）
//!      - AAD       = 整个 ClientHello record（含 TLS record header）
//!      - plaintext = AEAD-Decrypt(key=auth_key, nonce, ciphertext=session_id)
//!   5. 解密后的 plaintext[8:8+n] 即为 short_id，与配置比对

use std::net::SocketAddr;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::config::RealityConfig;

// ── 公开入口 ───────────────────────────────────────────────────────────────────

pub async fn accept(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &RealityConfig,
    tls_acceptor: Arc<TlsAcceptor>,
) -> Result<RealityStream> {
    let mut peek_buf = [0u8; 2048];
    let n = peek_client_hello(&stream, &mut peek_buf).await?;
    let client_hello = &peek_buf[..n];

    match verify_reality_client(client_hello, cfg) {
        Ok(()) => {
            debug!("[reality] {peer} short-ID 验证通过，接受为 Reality 客户端");
            let tls_stream = tls_acceptor
                .accept(stream)
                .await
                .context("Reality TLS handshake failed")?;
            Ok(RealityStream(Box::new(tls_stream)))
        }
        Err(e) => {
            debug!("[reality] {peer} 非 Reality 客户端（{e}），转发到 dest");
            forward_to_dest(stream, cfg).await?;
            bail!("reality: non-Reality client forwarded to dest")
        }
    }
}

// ── Stream 包装 ───────────────────────────────────────────────────────────────

pub struct RealityStream(Box<tokio_rustls::server::TlsStream<TcpStream>>);

impl AsyncRead for RealityStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for RealityStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().0).poll_shutdown(cx)
    }
}

// ── ClientHello Peek ──────────────────────────────────────────────────────────

async fn peek_client_hello(stream: &TcpStream, buf: &mut [u8]) -> Result<usize> {
    stream.readable().await?;
    let n = {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let ret = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        if ret < 0 {
            bail!("peek ClientHello: {}", std::io::Error::last_os_error());
        }
        ret as usize
    };
    Ok(n)
}

// ── TLS ClientHello 布局常量 ──────────────────────────────────────────────────
//
// TLS record header: [0]=content_type [1..3]=legacy_ver [3..5]=length  → 5 bytes
// Handshake header:  [5]=type [6..9]=length(3B)                        → 4 bytes
// ClientHello body:  [9..11]=legacy_ver                                 → 2 bytes
//                    [11..43]=random                                     → 32 bytes
//                    [43]=session_id_len, [44..76]=session_id

const RECORD_HDR: usize = 5;
const HANDSHAKE_HDR: usize = 4;
const LEGACY_VER_LEN: usize = 2;
const RANDOM_OFFSET: usize = RECORD_HDR + HANDSHAKE_HDR + LEGACY_VER_LEN; // 11
const RANDOM_LEN: usize = 32;
const SID_LEN_OFFSET: usize = RANDOM_OFFSET + RANDOM_LEN; // 43
const SID_OFFSET: usize = SID_LEN_OFFSET + 1; // 44

// ── 核心验证逻辑 ──────────────────────────────────────────────────────────────

fn verify_reality_client(record: &[u8], cfg: &RealityConfig) -> Result<()> {
    // 基础格式检查
    if record.len() < SID_OFFSET + 32 + 4 {
        bail!("record 太短，不是合法 ClientHello");
    }
    if record[0] != 0x16 {
        bail!("非 TLS Handshake record (type={:#x})", record[0]);
    }
    if record[RECORD_HDR] != 0x01 {
        bail!("非 ClientHello");
    }
    if record[SID_LEN_OFFSET] != 32 {
        bail!(
            "session_id_len={} != 32，不是 uTLS Reality 客户端",
            record[SID_LEN_OFFSET]
        );
    }

    let random = &record[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN];
    let session_id = &record[SID_OFFSET..SID_OFFSET + 32];

    // ── 步骤 1：从 KeyShare 扩展提取客户端 x25519 ECDHE 公钥 ─────────────────
    let ecdhe_pub =
        extract_x25519_from_key_share(record).context("从 KeyShare 扩展提取 x25519 公钥失败")?;

    // ── 步骤 2：x25519 ECDH → raw_auth_key ───────────────────────────────────
    let priv_bytes = base64_url_decode(&cfg.private_key).context("解码 private_key")?;
    anyhow::ensure!(
        priv_bytes.len() == 32,
        "private_key 须为 32 字节（实际 {} 字节）",
        priv_bytes.len()
    );
    let server_private: [u8; 32] = priv_bytes.try_into().unwrap();
    let raw_auth_key = x25519_dh(&server_private, &ecdhe_pub);

    // ── 步骤 3：HKDF-SHA256 派生 auth_key ────────────────────────────────────
    //   IKM  = raw_auth_key
    //   salt = random[:20]
    //   info = "REALITY"
    let hk = Hkdf::<Sha256>::new(Some(&random[..20]), &raw_auth_key);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand 失败"))?;

    // ── 步骤 4：AEAD 解密 Session ID ─────────────────────────────────────────
    //   key    = auth_key（32 字节）
    //   nonce  = random[20:32]（12 字节）
    //   AAD    = 整个 TLS record（含 record header）
    //   密文   = session_id（32 字节 = 16 字节明文 + 16 字节 tag）
    //
    //   算法选择：与 Xray/sing-box 保持一致：
    //     - 若客户端 cipher suites 中 AES-GCM 排在 ChaCha20 前面 → AES-256-GCM
    //     - 否则 → ChaCha20-Poly1305
    let nonce_bytes = &random[20..32];
    let use_aes = cipher_suite_prefers_aes(record);

    let plaintext = if use_aes {
        let aes_key = Key::<Aes256Gcm>::from_slice(&auth_key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: session_id,
                    aad: record,
                },
            )
            .map_err(|_| anyhow::anyhow!("AES-GCM 解密失败，非 Reality 客户端"))?
    } else {
        let cha_key = ChaKey::<ChaCha20Poly1305>::from_slice(&auth_key);
        let cipher = ChaCha20Poly1305::new(cha_key);
        let nonce = ChaNonce::from_slice(nonce_bytes);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: session_id,
                    aad: record,
                },
            )
            .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 解密失败，非 Reality 客户端"))?
    };

    // 解密后 plaintext 为 16 字节：
    //   [0..8]    = 客户端时间戳等（服务端不验证）
    //   [8..8+n]  = short_id（n = len(short_id)）

    // ── 步骤 5：比对 short_id ─────────────────────────────────────────────────
    for sid_hex in &cfg.short_ids {
        let sid_bytes =
            hex::decode(sid_hex).with_context(|| format!("解码 short_id '{sid_hex}'"))?;
        anyhow::ensure!(sid_bytes.len() <= 8, "short_id '{sid_hex}' 超过 8 字节");

        let n = sid_bytes.len();
        if n == 0 {
            // 空 short_id 匹配所有客户端
            return Ok(());
        }
        if plaintext.len() >= 8 + n && &plaintext[8..8 + n] == sid_bytes.as_slice() {
            return Ok(());
        }
    }

    bail!("short_id 不匹配")
}

// ── 判断客户端是否首选 AES-GCM ───────────────────────────────────────────────
//
// 与 Xray/sing-box 逻辑一致：遍历 cipher suites，看 AES-GCM 系列（0x1301/0x1302/
// 0x009c/0x009d 等）是否在 ChaCha20（0x1303/0xcca8/0xcca9）之前出现。
// 若找不到任何已知算法，默认使用 AES-GCM。

fn cipher_suite_prefers_aes(record: &[u8]) -> bool {
    let pos = SID_OFFSET + 32; // cipher_suites 紧跟在 session_id 之后
    if pos + 2 > record.len() {
        return true;
    }
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    let cs_start = pos + 2;
    if cs_start + cs_len > record.len() || cs_len < 2 {
        return true;
    }

    let mut i = cs_start;
    while i + 1 < cs_start + cs_len {
        let suite = u16::from_be_bytes([record[i], record[i + 1]]);
        match suite {
            // AES-GCM cipher suites
            0x1301 | 0x1302 | 0x009c | 0x009d | 0xc02b | 0xc02c | 0xc02f | 0xc030 => {
                return true;
            }
            // ChaCha20-Poly1305
            0x1303 | 0xcca8 | 0xcca9 => {
                return false;
            }
            _ => {}
        }
        i += 2;
    }
    true // 默认 AES
}

// ── 从 KeyShare 扩展提取 x25519 公钥 ─────────────────────────────────────────
//
// TLS 1.3 KeyShare 扩展（type = 0x0033）格式：
//   2B  client_shares_length
//   [
//     2B  group             (0x001d = x25519)
//     2B  key_exchange_len
//     NB  key_exchange
//   ]...

fn extract_x25519_from_key_share(record: &[u8]) -> Result<[u8; 32]> {
    // 扩展列表从 session_id 结束处开始
    let mut pos = SID_OFFSET + 32;

    // cipher_suites (2B length + data)
    if pos + 2 > record.len() {
        bail!("record 在 cipher_suites 前截断");
    }
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // compression_methods (1B length + data)
    if pos + 1 > record.len() {
        bail!("record 在 compression_methods 前截断");
    }
    let cm_len = record[pos] as usize;
    pos += 1 + cm_len;

    // extensions (2B total length)
    if pos + 2 > record.len() {
        bail!("record 在 extensions_length 前截断");
    }
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() {
        bail!("extensions 超出 record 边界");
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            bail!("extension 数据超出边界");
        }

        if ext_type == 0x0033 {
            // KeyShare
            return parse_x25519_key_share(&record[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    bail!("未找到 KeyShare 扩展（0x0033）")
}

fn parse_x25519_key_share(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() < 2 {
        bail!("KeyShare data 太短");
    }
    let shares_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let end = (2 + shares_len).min(data.len());

    while pos + 4 <= end {
        let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ke_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ke_len > end {
            bail!("KeyShare entry 超出边界");
        }

        // x25519 = 0x001d，公钥恒 32 字节
        if group == 0x001d && ke_len == 32 {
            let mut pub_key = [0u8; 32];
            pub_key.copy_from_slice(&data[pos..pos + 32]);
            return Ok(pub_key);
        }

        pos += ke_len;
    }

    bail!("KeyShare 中未找到 x25519（0x001d）")
}

// ── x25519 Diffie-Hellman ─────────────────────────────────────────────────────

fn x25519_dh(server_private: &[u8; 32], client_public: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*server_private);
    let public = PublicKey::from(*client_public);
    secret.diffie_hellman(&public).to_bytes()
}

// ── 透明转发到 dest ────────────────────────────────────────────────────────────

async fn forward_to_dest(mut inbound: TcpStream, cfg: &RealityConfig) -> Result<()> {
    let mut outbound = tokio::net::TcpStream::connect(&cfg.dest)
        .await
        .with_context(|| format!("连接 dest {} 失败", cfg.dest))?;

    let (mut in_r, mut in_w) = inbound.split();
    let (mut out_r, mut out_w) = outbound.split();

    let _ = tokio::join!(
        tokio::io::copy(&mut in_r, &mut out_w),
        tokio::io::copy(&mut out_r, &mut in_w),
    );
    Ok(())
}

// ── 构建 Reality TLS acceptor ─────────────────────────────────────────────────

pub fn build(cfg: &RealityConfig) -> Result<rustls::ServerConfig> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    info!("[reality/tls] 为 SNI '{}' 生成自签名证书", cfg.server_name);

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![cfg.server_name.clone()])
            .with_context(|| format!("生成自签名证书失败 ({})", cfg.server_name))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("序列化私钥失败: {e}"))?;

    let mut sc = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("构建 rustls ServerConfig 失败")?;

    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(sc)
}

// ── base64 解码（兼容 URL-safe no-pad 和标准格式）────────────────────────────

fn base64_url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let s = s.trim();
    if let Ok(v) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s) {
        return Ok(v);
    }
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 解码失败")
}
