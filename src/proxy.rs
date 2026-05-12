//! 代理出站模块：TCP 双向转发 + UDP 关联（含分片重组）

use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

use crate::hysteria2::auth::write_tcp_response;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_MAX_PKT: usize = 65507;

// ── TCP proxy ─────────────────────────────────────────────────────────────────

pub async fn handle_tcp_stream(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    target: String,
) -> Result<()> {
    debug!("TCP proxy → {target}");

    let tcp = match timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("Connect to {target} failed: {e}");
            write_tcp_response(&mut quic_send, false, &e.to_string()).await?;
            let _ = quic_send.finish();
            return Ok(());
        }
        Err(_) => {
            warn!("Connect to {target} timed out");
            write_tcp_response(&mut quic_send, false, "connection timeout").await?;
            let _ = quic_send.finish();
            return Ok(());
        }
    };

    // 连接成功，回复 ok
    write_tcp_response(&mut quic_send, true, "Connected").await?;

    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    // quic_recv → tcp_w
    let t1 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(0)) | Ok(None) | Err(_) => break,
                Ok(Some(n)) => {
                    if tcp_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tcp_w.shutdown().await;
    });

    // tcp_r → quic_send
    let t2 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if quic_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = quic_send.finish();
    });

    let _ = tokio::join!(t1, t2);
    debug!("TCP proxy {target} closed");
    Ok(())
}

// ── UDP frame 格式 ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct UdpFrame {
    pub session_id: u32, // 官方协议为 uint32
    pub packet_id: u16,
    pub frag_id: u8,    // frag_id 在前
    pub frag_total: u8, // frag_total 在后
    pub addr: String,
    pub port: u16,
    pub payload: Bytes,
}

/// 从 bytes 中读取一个 QUIC varint，消耗相应字节。
fn read_varint_bytes(data: &mut Bytes) -> Result<u64> {
    anyhow::ensure!(!data.is_empty(), "varint: no data");
    let first = data.get_u8();
    let extra = (first >> 6) as usize; // 0→1B, 1→2B, 2→4B, 3→8B
    let mut val = (first & 0x3f) as u64;
    for _ in 0..extra {
        anyhow::ensure!(!data.is_empty(), "varint: truncated");
        val = (val << 8) | data.get_u8() as u64;
    }
    Ok(val)
}

/// 解析 "host:port" 或 "[ipv6]:port" 格式的地址字符串。
fn split_host_port(s: &str) -> Result<(String, u16)> {
    // rsplit_once(':') 能正确处理 IPv6 字面量（括号包裹时最后一个冒号是端口分隔符）
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid addr (no port): {s}"))?;
    let host = host.trim_matches(|c| c == '[' || c == ']').to_string();
    let port: u16 = port_str.parse()?;
    Ok((host, port))
}

/// 官方 Hysteria2 UDP 帧格式：
///   Session ID   (uint32 BE, 4 bytes)
///   Packet ID    (uint16 BE, 2 bytes)
///   Fragment ID  (uint8,     1 byte)
///   Frag count   (uint8,     1 byte)
///   Addr length  (QUIC varint)
///   Addr         (UTF-8 string "host:port")
///   Data         (remaining bytes)
pub fn parse_udp_frame(mut data: Bytes) -> Result<UdpFrame> {
    anyhow::ensure!(data.len() >= 8, "UDP frame too short ({})", data.len());

    let session_id = data.get_u32(); // u32, 4 bytes
    let packet_id = data.get_u16();
    let frag_id = data.get_u8(); // frag_id 先
    let frag_total = data.get_u8(); // frag_total 后

    // 地址：varint 长度 + UTF-8 "host:port" 字符串
    let addr_len = read_varint_bytes(&mut data)? as usize;
    anyhow::ensure!(
        addr_len > 0 && addr_len <= 2048,
        "invalid addr_len: {addr_len}"
    );
    anyhow::ensure!(data.len() >= addr_len, "UDP frame: addr truncated");
    let addr_bytes = data.split_to(addr_len);
    let addr_str = String::from_utf8(addr_bytes.to_vec())?;
    let (addr, port) = split_host_port(&addr_str)?;

    let payload = data; // 剩余全是载荷

    Ok(UdpFrame {
        session_id,
        packet_id,
        frag_id,
        frag_total,
        addr,
        port,
        payload,
    })
}

/// 构建 Hysteria2 UDP 回包帧（服务端 → 客户端）
/// 地址格式：varint(addr_len) + "host:port" UTF-8 字符串
pub fn build_udp_frame(session_id: u32, src_addr: SocketAddr, payload: &[u8]) -> Bytes {
    let addr_str = match src_addr {
        SocketAddr::V4(a) => format!("{}:{}", a.ip(), a.port()),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    };
    let addr_bytes = addr_str.as_bytes();
    let addr_len = addr_bytes.len() as u64;

    // varint 编码 addr_len 所需字节数
    let varint_sz = if addr_len < 64 {
        1
    } else if addr_len < 16384 {
        2
    } else {
        4
    };
    let total = 4 + 2 + 1 + 1 + varint_sz + addr_bytes.len() + payload.len();
    let mut buf = BytesMut::with_capacity(total);

    buf.put_u32(session_id); // u32
    buf.put_u16(0); // packet_id = 0
    buf.put_u8(0); // frag_id = 0
    buf.put_u8(1); // frag_total = 1

    // varint addr_len
    if addr_len < 64 {
        buf.put_u8(addr_len as u8);
    } else if addr_len < 16384 {
        buf.put_u16(0x4000 | addr_len as u16);
    } else {
        buf.put_u32(0x8000_0000 | addr_len as u32);
    }
    buf.put_slice(addr_bytes);
    buf.put_slice(payload);
    buf.freeze()
}

// ── UDP 分片重组 ───────────────────────────────────────────────────────────────

struct FragBuffer {
    total: u8,
    received: u8,
    frags: HashMap<u8, Bytes>,
    addr: String,
    port: u16,
}

impl FragBuffer {
    fn new(total: u8, addr: String, port: u16) -> Self {
        Self {
            total,
            received: 0,
            frags: HashMap::new(),
            addr,
            port,
        }
    }

    fn insert(&mut self, frag_id: u8, payload: Bytes) -> Option<(Bytes, String, u16)> {
        self.frags.entry(frag_id).or_insert(payload);
        self.received += 1;

        if self.received >= self.total {
            let mut ids: Vec<u8> = self.frags.keys().cloned().collect();
            ids.sort_unstable();
            let total_len: usize = ids.iter().map(|id| self.frags[id].len()).sum();
            let mut buf = BytesMut::with_capacity(total_len);
            for id in ids {
                buf.extend_from_slice(&self.frags[&id]);
            }
            Some((buf.freeze(), self.addr.clone(), self.port))
        } else {
            None
        }
    }
}

// ── UDP session 管理 ──────────────────────────────────────────────────────────

pub async fn handle_udp_session(
    session_id: u32,
    first_frame: UdpFrame,
    mut rx: mpsc::Receiver<UdpFrame>,
    send_datagram: Arc<dyn Fn(Bytes) -> Result<()> + Send + Sync>,
) -> Result<()> {
    let target = format!("{}:{}", first_frame.addr, first_frame.port);
    debug!("UDP session {session_id} → {target}");

    let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let sock = Arc::new(UdpSocket::bind(local).await?);
    sock.connect(&target).await?;

    let mut frag_table: HashMap<u16, FragBuffer> = HashMap::new();
    relay_frame(session_id, first_frame, &sock, &mut frag_table).await;

    let sock_recv = Arc::clone(&sock);
    let send2 = Arc::clone(&send_datagram);

    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_MAX_PKT];
        loop {
            match timeout(UDP_IDLE_TIMEOUT, sock_recv.recv_from(&mut buf)).await {
                Ok(Ok((n, src))) => {
                    let pkt = build_udp_frame(session_id, src, &buf[..n]);
                    if let Err(e) = send2(pkt) {
                        debug!("UDP session {session_id}: send datagram error: {e}");
                        break;
                    }
                }
                Ok(Err(e)) => {
                    debug!("UDP session {session_id}: recv error: {e}");
                    break;
                }
                Err(_) => {
                    debug!("UDP session {session_id}: idle timeout");
                    break;
                }
            }
        }
    });

    while let Ok(Some(frame)) = timeout(UDP_IDLE_TIMEOUT, rx.recv()).await {
        relay_frame(session_id, frame, &sock, &mut frag_table).await;
    }

    recv_task.abort();
    debug!("UDP session {session_id} closed");
    Ok(())
}

async fn relay_frame(
    session_id: u32,
    frame: UdpFrame,
    sock: &UdpSocket,
    frag_table: &mut HashMap<u16, FragBuffer>,
) {
    if frame.frag_total <= 1 {
        if let Err(e) = sock.send(&frame.payload).await {
            warn!("UDP session {session_id}: send error: {e}");
        }
        return;
    }

    let buf = frag_table
        .entry(frame.packet_id)
        .or_insert_with(|| FragBuffer::new(frame.frag_total, frame.addr.clone(), frame.port));

    if let Some((reassembled, _addr, _port)) = buf.insert(frame.frag_id, frame.payload) {
        frag_table.remove(&frame.packet_id);
        if let Err(e) = sock.send(&reassembled).await {
            warn!("UDP session {session_id}: send reassembled error: {e}");
        } else {
            debug!(
                "UDP session {session_id}: sent reassembled packet ({} bytes)",
                reassembled.len()
            );
        }
    }
}
