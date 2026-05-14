//! VLESS + Reality TLS layer — 修复版
//!
//! ## 原始实现的两个核心缺陷
//!
//! ### 缺陷 1：生成错误类型的证书（导致代理完全无法工作）
//!
//! 原代码用 rcgen::generate_simple_self_signed 生成普通 RSA/ECDSA 自签名证书。
//! Reality 客户端（Xray/sing-box）在 VerifyPeerCertificate 中验证的是：
//!
//!   cert.PublicKey 类型必须是 ed25519.PublicKey
//!   cert.Signature == HMAC-SHA512(auth_key, cert.PublicKey)
//!
//! 普通自签名证书无法通过此验证，TLS 握手直接断开，代理完全无法使用。
//!
//! ### 缺陷 2：全局预生成证书（auth_key 是 per-connection 的）
//!
//! auth_key 由客户端 ECDHE 临时公钥推导而来，每个连接不同。
//! 因此 Reality 专用证书必须在每次握手前实时生成，不能全局复用。
//!
//! ## 修复方案
//!
//! 1. accept() 函数：验证成功后，用 auth_key 实时生成 Reality 专用证书，
//!    构建 per-connection TlsAcceptor，再做 TLS 握手。
//!
//! 2. build() 函数：只做配置验证和日志，返回占位配置（Reality 分支实际上
//!    在 accept() 内部自建 per-connection acceptor，不用全局 acceptor）。
//!
//! ## Reality 证书构造（参考 Xray github.com/xtls/reality 库）
//!
//! Xray reality 服务端生成证书的逻辑（reality.go）：
//!   certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)  // 或 ed25519
//!   cert.Signature = HMAC-SHA512(authKey, cert.PublicKey)
//!
//! 客户端验证（reality.go VerifyPeerCertificate）：
//!   h := hmac.New(sha512.New, c.AuthKey)
//!   h.Write(pub)  // pub = ed25519.PublicKey (32 bytes)
//!   if bytes.Equal(h.Sum(nil), certs[0].Signature) { verified = true }
//!
//! 所以服务端必须：
//!   - 用 ed25519 密钥
//!   - 把证书的 Signature 字段设为 HMAC-SHA512(auth_key, ed25519_pub_key_bytes)

use std::net::SocketAddr;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::config::RealityConfig;

// ── 公开入口 ───────────────────────────────────────────────────────────────────
//
// 注意：签名去掉了 tls_acceptor 参数，因为 Reality 必须 per-connection 生成 acceptor。
// listener.rs 中 Reality 分支需要相应修改。

pub async fn accept(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &RealityConfig,
) -> Result<RealityStream> {
    let mut peek_buf = [0u8; 2048];
    let n = peek_client_hello(&stream, &mut peek_buf).await?;
    let client_hello = &peek_buf[..n];

    match verify_reality_client(client_hello, cfg) {
        Ok(auth_key) => {
            debug!("[reality] {peer} short-ID 验证通过，接受为 Reality 客户端");

            // ── 关键修复：用 auth_key 实时生成 Reality 专用证书 ──────────────
            // auth_key 每连接不同，证书的 Signature（HMAC-SHA512）也每连接不同
            let sc = build_per_connection_config(cfg, &auth_key)
                .context("构建 Reality per-connection TLS config 失败")?;
            let acceptor = Arc::new(TlsAcceptor::from(Arc::new(sc)));

            let tls_stream = acceptor
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

const RECORD_HDR: usize = 5;
const HANDSHAKE_HDR: usize = 4;
const LEGACY_VER_LEN: usize = 2;
const RANDOM_OFFSET: usize = RECORD_HDR + HANDSHAKE_HDR + LEGACY_VER_LEN; // 11
const RANDOM_LEN: usize = 32;
const SID_LEN_OFFSET: usize = RANDOM_OFFSET + RANDOM_LEN; // 43
const SID_OFFSET: usize = SID_LEN_OFFSET + 1; // 44

// ── 核心验证逻辑，返回 auth_key ───────────────────────────────────────────────

fn verify_reality_client(record: &[u8], cfg: &RealityConfig) -> Result<[u8; 32]> {
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

    let ecdhe_pub =
        extract_x25519_from_key_share(record).context("从 KeyShare 扩展提取 x25519 公钥失败")?;

    let priv_bytes = base64_url_decode(&cfg.private_key).context("解码 private_key")?;
    anyhow::ensure!(priv_bytes.len() == 32, "private_key 须为 32 字节");
    let server_private: [u8; 32] = priv_bytes.try_into().unwrap();
    let raw_auth_key = x25519_dh(&server_private, &ecdhe_pub);

    let hk = Hkdf::<Sha256>::new(Some(&random[..20]), &raw_auth_key);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand 失败"))?;

    let nonce_bytes = &random[20..32];
    let use_aes = cipher_suite_prefers_aes(record);

    let plaintext = if use_aes {
        let aes_key = Key::<Aes256Gcm>::from_slice(&auth_key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, Payload { msg: session_id, aad: record })
            .map_err(|_| anyhow::anyhow!("AES-GCM 解密失败，非 Reality 客户端"))?
    } else {
        let cipher = ChaCha20Poly1305::new_from_slice(&auth_key)
            .map_err(|_| anyhow::anyhow!("ChaCha20 key 长度错误"))?;
        let nonce = ChaNonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, Payload { msg: session_id, aad: record })
            .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 解密失败，非 Reality 客户端"))?
    };

    for sid_hex in &cfg.short_ids {
        let sid_bytes =
            hex::decode(sid_hex).with_context(|| format!("解码 short_id '{sid_hex}'"))?;
        anyhow::ensure!(sid_bytes.len() <= 8, "short_id '{sid_hex}' 超过 8 字节");
        let n = sid_bytes.len();
        if n == 0 {
            return Ok(auth_key);
        }
        if plaintext.len() >= 8 + n && &plaintext[8..8 + n] == sid_bytes.as_slice() {
            return Ok(auth_key);
        }
    }

    bail!("short_id 不匹配")
}

// ── 构建 Reality 协议专用 per-connection TLS ServerConfig ─────────────────────
//
// Reality 客户端（Xray/sing-box）VerifyPeerCertificate 验证逻辑：
//
//   if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
//       h := hmac.New(sha512.New, authKey)
//       h.Write(pub)                         // pub = 32 bytes raw ed25519 public key
//       if bytes.Equal(h.Sum(nil), certs[0].Signature) {
//           verified = true
//           return nil                        // 验证通过，跳过 CA 链检查
//       }
//   }
//
// 因此服务端必须发一张满足以下条件的证书：
//   1. SubjectPublicKeyInfo 中包含 ed25519 公钥（OID 1.3.101.112）
//   2. Certificate.signatureValue（DER 中最外层的 BIT STRING）= HMAC-SHA512(auth_key, pub_key_32_bytes)
//
// auth_key 每连接不同，所以必须 per-connection 生成，不能全局预建。

fn build_per_connection_config(
    cfg: &RealityConfig,
    auth_key: &[u8; 32],
) -> Result<rustls::ServerConfig> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // 1. 生成 ed25519 密钥对（rcgen 封装）
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)
        .context("rcgen 生成 ed25519 密钥对失败")?;

    // 2. 提取原始 ed25519 公钥（32 字节）
    //    rcgen KeyPair::public_key_raw() 返回 SubjectPublicKeyInfo DER，
    //    ed25519 的原始公钥在 SPKI 的最后 32 字节
    let spki = key_pair.public_key_raw();
    if spki.len() < 32 {
        bail!("ed25519 SPKI 太短：{} bytes", spki.len());
    }
    let pub_key_32 = &spki[spki.len() - 32..]; // SubjectPublicKey BIT STRING 内容

    // 3. HMAC-SHA512(auth_key, pub_key_32) → Reality Signature
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key)
        .map_err(|_| anyhow::anyhow!("HMAC-SHA512 初始化失败"))?;
    mac.update(pub_key_32);
    let reality_sig: Vec<u8> = mac.finalize().into_bytes().to_vec(); // 64 bytes

    // 4. 用 rcgen 生成基础 ed25519 自签名证书，然后替换 signatureValue
    let mut params = CertificateParams::new(vec![cfg.server_name.clone()])
        .context("构建 CertificateParams 失败")?;
    params.key_pair = Some(key_pair);

    // rcgen self_signed 需要一个签名密钥，我们传同一个 key_pair 即可
    // 但 rcgen 0.13 的 self_signed 消耗 params，需要重建
    let key_pair2 = KeyPair::generate_for(&PKCS_ED25519)
        .context("rcgen 生成签名密钥对失败")?;
    let cert = params.self_signed(&key_pair2)
        .context("rcgen 自签名失败")?;

    // 5. 获取 DER 并替换 signatureValue
    let mut der_bytes = cert.der().to_vec();
    replace_signature_in_cert_der(&mut der_bytes, &reality_sig)
        .context("替换证书 signatureValue 失败")?;

    // 6. 构建 rustls ServerConfig
    //    注意：rustls 会用 key_pair2 来真正签名握手消息（TLS 层），
    //    证书里的 signatureValue 只是给 Reality 客户端 VerifyPeerCertificate 看的。
    //    客户端设置了 InsecureSkipVerify=true，不做 CA 链验证，只做 HMAC 验证。
    let cert_der = CertificateDer::from(der_bytes);
    let key_der = PrivateKeyDer::try_from(key_pair2.serialize_der())
        .map_err(|e| anyhow::anyhow!("序列化私钥失败: {e}"))?;

    let mut sc = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("构建 rustls ServerConfig 失败")?;

    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(sc)
}

// ── 替换 X.509 Certificate DER 中的 signatureValue ───────────────────────────
//
// Certificate DER 结构（RFC 5280）：
//   SEQUENCE {                    ← Certificate
//     SEQUENCE { ... }            ← tbsCertificate
//     SEQUENCE { OID, ... }       ← signatureAlgorithm
//     BIT STRING { 0x00, <sig> }  ← signatureValue  ← 我们要替换这个
//   }
//
// Go 的 x509.Certificate.Signature 就是 BIT STRING 去掉 unused-bits(0x00) 后的内容。
// Reality 客户端把这个值和 HMAC-SHA512(auth_key, pub_key) 比较。

fn replace_signature_in_cert_der(der: &mut Vec<u8>, new_sig: &[u8]) -> Result<()> {
    // 解析外层 SEQUENCE
    if der.is_empty() || der[0] != 0x30 {
        bail!("DER 首字节不是 SEQUENCE (0x30)");
    }
    let outer_content_start = der_tlv_content_start(der, 0)?;

    // 在 outer content 中找第三个 TLV（signatureValue BIT STRING）
    let mut pos = outer_content_start;
    for field_idx in 0..3usize {
        if pos >= der.len() {
            bail!("DER 结构不完整：找不到第 {} 个字段", field_idx + 1);
        }
        let (total, _content) = der_tlv_lens(der, pos)?;
        if field_idx == 2 {
            // 第三个字段 = signatureValue，应该是 BIT STRING (0x03)
            if der[pos] != 0x03 {
                bail!("signatureValue 不是 BIT STRING，tag={:#x}", der[pos]);
            }
            // 构造新 BIT STRING：0x00 + new_sig（unused bits = 0）
            let mut new_content = vec![0x00u8];
            new_content.extend_from_slice(new_sig);
            let new_tlv = der_encode_tlv(0x03, &new_content);

            // 替换 der[pos..pos+total]
            der.splice(pos..pos + total, new_tlv);

            // 修正外层 SEQUENCE 的 length 字段
            der_fix_outer_sequence_length(der)?;
            return Ok(());
        }
        pos += total;
    }
    bail!("DER 中未找到 signatureValue（第三个字段）")
}

/// 返回 (total_tlv_bytes, content_bytes)
fn der_tlv_lens(data: &[u8], pos: usize) -> Result<(usize, usize)> {
    if pos + 1 >= data.len() {
        bail!("TLV 解析越界 pos={pos}");
    }
    let (content_len, len_field_bytes) = der_decode_length(data, pos + 1)?;
    Ok((1 + len_field_bytes + content_len, content_len))
}

fn der_tlv_content_start(data: &[u8], pos: usize) -> Result<usize> {
    let (_content_len, len_field_bytes) = der_decode_length(data, pos + 1)?;
    Ok(pos + 1 + len_field_bytes)
}

fn der_decode_length(data: &[u8], pos: usize) -> Result<(usize, usize)> {
    if pos >= data.len() {
        bail!("DER length 字节越界 pos={pos}");
    }
    let first = data[pos];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || pos + 1 + n > data.len() {
        bail!("DER 非法 multi-byte length");
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | data[pos + 1 + i] as usize;
    }
    Ok((len, 1 + n))
}

fn der_encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let len = content.len();
    if len < 0x80 {
        v.push(len as u8);
    } else if len < 0x100 {
        v.extend_from_slice(&[0x81, len as u8]);
    } else if len < 0x10000 {
        v.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
    } else {
        v.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, (len & 0xff) as u8]);
    }
    v.extend_from_slice(content);
    v
}

fn der_fix_outer_sequence_length(der: &mut Vec<u8>) -> Result<()> {
    if der[0] != 0x30 {
        bail!("DER 首字节不是 SEQUENCE");
    }
    let old_content_start = der_tlv_content_start(der, 0)?;
    let new_content_len = der.len() - old_content_start;

    let new_len_field = if new_content_len < 0x80 {
        vec![new_content_len as u8]
    } else if new_content_len < 0x100 {
        vec![0x81, new_content_len as u8]
    } else {
        vec![0x82, (new_content_len >> 8) as u8, (new_content_len & 0xff) as u8]
    };

    // der[1..old_content_start] 是旧的 length field
    der.splice(1..old_content_start, new_len_field);
    Ok(())
}

// ── AES/ChaCha20 选择 ─────────────────────────────────────────────────────────

fn cipher_suite_prefers_aes(record: &[u8]) -> bool {
    let pos = SID_OFFSET + 32;
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
            0x1301 | 0x1302 | 0x009c | 0x009d | 0xc02b | 0xc02c | 0xc02f | 0xc030 => return true,
            0x1303 | 0xcca8 | 0xcca9 => return false,
            _ => {}
        }
        i += 2;
    }
    true
}

// ── KeyShare 提取 ─────────────────────────────────────────────────────────────

fn extract_x25519_from_key_share(record: &[u8]) -> Result<[u8; 32]> {
    let mut pos = SID_OFFSET + 32;

    if pos + 2 > record.len() { bail!("record 在 cipher_suites 前截断"); }
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > record.len() { bail!("record 在 compression_methods 前截断"); }
    let cm_len = record[pos] as usize;
    pos += 1 + cm_len;

    if pos + 2 > record.len() { bail!("record 在 extensions_length 前截断"); }
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() { bail!("extensions 超出 record 边界"); }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end { bail!("extension 数据超出边界"); }
        if ext_type == 0x0033 {
            return parse_x25519_key_share(&record[pos..pos + ext_len]);
        }
        pos += ext_len;
    }
    bail!("未找到 KeyShare 扩展（0x0033）")
}

fn parse_x25519_key_share(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() < 2 { bail!("KeyShare data 太短"); }
    let shares_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let end = (2 + shares_len).min(data.len());
    while pos + 4 <= end {
        let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ke_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + ke_len > end { bail!("KeyShare entry 超出边界"); }
        if group == 0x001d && ke_len == 32 {
            let mut pub_key = [0u8; 32];
            pub_key.copy_from_slice(&data[pos..pos + 32]);
            return Ok(pub_key);
        }
        pos += ke_len;
    }
    bail!("KeyShare 中未找到 x25519（0x001d）")
}

// ── x25519 DH ─────────────────────────────────────────────────────────────────

fn x25519_dh(server_private: &[u8; 32], client_public: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*server_private);
    let public = PublicKey::from(*client_public);
    secret.diffie_hellman(&public).to_bytes()
}

// ── 转发到 dest ───────────────────────────────────────────────────────────────

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

// ── 启动时配置验证（兼容 listener.rs 现有结构，返回占位 ServerConfig） ─────────
//
// Reality 模式下，listener.rs 中的全局 TlsAcceptor 不会被用于实际握手：
// accept() 函数会在验证 ClientHello 后自建 per-connection acceptor。
// 这里只做配置合法性检查，返回占位证书让 rustls 满意。

pub fn build(cfg: &RealityConfig) -> Result<rustls::ServerConfig> {
    let priv_bytes = base64_url_decode(&cfg.private_key).context("解码 private_key")?;
    anyhow::ensure!(priv_bytes.len() == 32, "private_key 须为 32 字节");
    for sid_hex in &cfg.short_ids {
        let sid = hex::decode(sid_hex).with_context(|| format!("解码 short_id '{sid_hex}'"))?;
        anyhow::ensure!(sid.len() <= 8, "short_id '{sid_hex}' 超过 8 字节");
    }

    info!(
        "[reality/tls] 配置验证通过，SNI='{}', dest='{}', short_ids={:?}",
        cfg.server_name, cfg.dest, cfg.short_ids
    );
    info!(
        "[reality/tls] Reality 证书按连接实时生成（auth_key per-connection），启动时无需预生成证书"
    );

    // 返回占位配置（Reality 分支实际 accept 时不使用此 acceptor）
    build_placeholder_config(cfg)
}

fn build_placeholder_config(cfg: &RealityConfig) -> Result<rustls::ServerConfig> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![cfg.server_name.clone()])
            .context("生成占位证书失败")?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("序列化占位私钥失败: {e}"))?;
    let mut sc = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("构建占位 rustls ServerConfig 失败")?;
    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(sc)
}

// ── base64 解码 ───────────────────────────────────────────────────────────────

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
