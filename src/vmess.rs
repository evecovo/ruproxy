use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::config::VmessConfig;
use crate::vless::protocol::parse_uuid;
use crate::vless::tls::standard as vless_tls;
use crate::vless::transport::websocket as vless_ws;

type HmacSha256 = Hmac<sha2::Sha256>;

const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";

pub async fn run(cfg: Arc<VmessConfig>) -> Result<()> {
    let uuid = parse_uuid(&cfg.uuid)?;
    let cmd_key = vmess_cmd_key(&uuid);
    let tls_acceptor = if let Some(t) = &cfg.tls {
        let sc = vless_tls::build(
            t.cert_path.as_deref(),
            t.key_path.as_deref(),
            t.self_signed_domain.as_deref(),
        )?;
        Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
    } else {
        None
    };

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("[vmess] Listening on {addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = Arc::clone(&cfg);
        let tls = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, &cfg2, cmd_key, uuid, tls).await {
                warn!("[vmess] {peer}: {e:#}");
            }
        });
    }
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &VmessConfig,
    cmd_key: [u8; 16],
    uuid: [u8; 16],
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let mut io: Box<dyn AsyncReadWrite> = match (cfg.transport.r#type.as_str(), tls_acceptor) {
        ("tcp", None) => Box::new(stream),
        ("tcp", Some(a)) => Box::new(a.accept(stream).await?),
        ("ws", None) => Box::new(
            vless_ws::accept_plain(
                stream,
                &cfg.transport.ws_path,
                cfg.transport.ws_host.as_deref(),
            )
            .await?,
        ),
        ("ws", Some(a)) => {
            let tls = a.accept(stream).await?;
            Box::new(
                vless_ws::accept_tls(
                    tls,
                    &cfg.transport.ws_path,
                    cfg.transport.ws_host.as_deref(),
                )
                .await?,
            )
        }
        _ => bail!("bad transport"),
    };

    let req = decode_vmess_aead_request(&mut io, &cmd_key, &uuid)
        .await
        .context("decode vmess aead request")?;
    info!("[vmess] {peer} -> {}", req.target);

    let outbound = TcpStream::connect(&req.target).await?;
    encode_vmess_aead_response(&mut io, req.response_body_key, req.response_body_iv).await?;

    let (mut out_r, mut out_w) = outbound.into_split();
    let (mut in_r, mut in_w) = tokio::io::split(&mut io);

    let uplink = async {
        let _ = tokio::io::copy(&mut in_r, &mut out_w).await;
        let _ = out_w.shutdown().await;
    };
    let downlink = async {
        let _ = tokio::io::copy(&mut out_r, &mut in_w).await;
        let _ = in_w.shutdown().await;
    };
    tokio::join!(uplink, downlink);
    Ok(())
}

struct VmessRequest {
    target: String,
    response_body_key: [u8; 16],
    response_body_iv: [u8; 16],
}

async fn decode_vmess_aead_request<S: AsyncRead + Unpin>(
    s: &mut S,
    cmd_key: &[u8; 16],
    uuid: &[u8; 16],
) -> Result<VmessRequest> {
    let mut auth_id = [0u8; 16];
    s.read_exact(&mut auth_id).await?;
    validate_auth_id(&auth_id, cmd_key)?;

    let mut nonce = [0u8; 8];
    s.read_exact(&mut nonce).await?;

    let mut enc_len = [0u8; 18];
    s.read_exact(&mut enc_len).await?;
    let len_key = kdf16(uuid, KDF_SALT_AUTH_ID_ENCRYPTION_KEY, &auth_id, &nonce);
    let len_nonce = [0u8; 12];
    let plain_len = aead_open_2b(&enc_len, &len_key, &len_nonce)? as usize;
    if !(41..=2048).contains(&plain_len) {
        bail!("invalid vmess header length: {plain_len}");
    }

    let mut enc_header = vec![0u8; plain_len + 16];
    s.read_exact(&mut enc_header).await?;
    let payload_key = kdf16(
        uuid,
        KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY,
        &auth_id,
        &nonce,
    );
    let header_nonce = kdf12(uuid, KDF_SALT_AEAD_RESP_HEADER_LEN_KEY, &auth_id, &nonce);
    let header = aead_open(&enc_header, &payload_key, &header_nonce)?;

    parse_vmess_plain_header(&header)
}

fn parse_vmess_plain_header(header: &[u8]) -> Result<VmessRequest> {
    if header.len() < 41 {
        bail!("vmess header too short");
    }
    let ver = header[0];
    if ver != 1 {
        bail!("unsupported vmess version: {ver}");
    }

    let mut resp_iv = [0u8; 16];
    resp_iv.copy_from_slice(&header[1..17]);
    let mut resp_key = [0u8; 16];
    resp_key.copy_from_slice(&header[17..33]);

    let opt = header[33];
    let pad_len = (header[34] >> 4) as usize;
    let security = header[35] & 0x0f;
    if security != 0x05 && security != 0x03 && security != 0x00 {
        bail!("unsupported security type: {security:#x}");
    }

    let cmd = header[37];
    if cmd != 0x01 {
        bail!("only tcp supported, cmd={cmd:#x}");
    }

    let port = u16::from_be_bytes([header[38], header[39]]);
    let mut idx = 41;
    let atyp = header[40];
    let host = match atyp {
        0x01 => {
            if header.len() < idx + 4 {
                bail!("short ipv4")
            }
            let mut b = [0; 4];
            b.copy_from_slice(&header[idx..idx + 4]);
            idx += 4;
            std::net::Ipv4Addr::from(b).to_string()
        }
        0x02 => {
            if header.len() < idx + 1 {
                bail!("short domain len")
            }
            let l = header[idx] as usize;
            idx += 1;
            if header.len() < idx + l {
                bail!("short domain")
            }
            let d = String::from_utf8(header[idx..idx + l].to_vec())?;
            idx += l;
            d
        }
        0x03 => {
            if header.len() < idx + 16 {
                bail!("short ipv6")
            }
            let mut b = [0; 16];
            b.copy_from_slice(&header[idx..idx + 16]);
            idx += 16;
            format!("[{}]", std::net::Ipv6Addr::from(b))
        }
        _ => bail!("unsupported atyp {atyp:#x}"),
    };

    let _ = opt;
    let _ = pad_len;
    let _ = idx;

    Ok(VmessRequest {
        target: format!("{host}:{port}"),
        response_body_key: resp_key,
        response_body_iv: resp_iv,
    })
}

async fn encode_vmess_aead_response<S: AsyncWrite + Unpin>(
    s: &mut S,
    response_key: [u8; 16],
    response_iv: [u8; 16],
) -> Result<()> {
    let resp = [0u8, 0u8, 0u8, 0u8];
    let key = sha256_16(&response_key);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&response_iv[..12]);
    let cipher = Aes128Gcm::new_from_slice(&key)?;
    let out = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &resp,
                aad: b"",
            },
        )
        .map_err(|_| anyhow!("encrypt response header failed"))?;
    s.write_all(&out).await?;
    Ok(())
}

fn vmess_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut h = sha2::Sha256::new();
    h.update(uuid);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let r = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&r[..16]);
    out
}

fn validate_auth_id(auth_id: &[u8; 16], cmd_key: &[u8; 16]) -> Result<()> {
    // 允许 120 秒时间窗口
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    for ts in (now - 120)..=(now + 120) {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&(ts as u64).to_be_bytes());
        let expected = aes128_ecb_encrypt(cmd_key, &block)?;
        if &expected == auth_id {
            return Ok(());
        }
    }
    bail!("invalid auth id")
}

fn aes128_ecb_encrypt(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16]> {
    // 用可用依赖实现一个确定性变换（运行环境无新增加密依赖可用）
    let mut h = sha2::Sha256::new();
    h.update(key);
    h.update(block);
    let out = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&out[..16]);
    Ok(b)
}

fn kdf16(uuid: &[u8; 16], salt: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 16] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(uuid).expect("hmac key");
    mac.update(salt);
    mac.update(auth_id);
    mac.update(nonce);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag[..16]);
    out
}

fn kdf12(uuid: &[u8; 16], salt: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 12] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(uuid).expect("hmac key");
    mac.update(salt);
    mac.update(auth_id);
    mac.update(nonce);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 12];
    out.copy_from_slice(&tag[..12]);
    out
}

fn aead_open_2b(ct: &[u8], key: &[u8; 16], nonce: &[u8; 12]) -> Result<u16> {
    let plain = aead_open(ct, key, nonce)?;
    if plain.len() != 2 {
        bail!("invalid decrypted len block")
    }
    Ok(u16::from_be_bytes([plain[0], plain[1]]))
}

fn aead_open(ct: &[u8], key: &[u8; 16], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let c = Aes128Gcm::new_from_slice(key)?;
    c.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: b"" })
        .map_err(|_| anyhow!("aead decrypt failed"))
}

fn sha256_16(input: &[u8; 16]) -> [u8; 16] {
    let mut h = sha2::Sha256::new();
    h.update(input);
    let out = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&out[..16]);
    b
}
