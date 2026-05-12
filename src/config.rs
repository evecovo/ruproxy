use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    pub hysteria2: Option<Hysteria2Config>,
    pub vless: Option<VlessConfig>,
}

// ── Hysteria2 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Hysteria2Config {
    #[serde(default = "default_true")]
    pub enable: bool,
    pub listen: String,
    pub tls: Hy2TlsConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub bandwidth: BandwidthConfig,
    #[serde(default)]
    pub masquerade: MasqueradeConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Hy2TlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
    #[serde(default = "default_self_signed_domain")]
    pub self_signed_domain: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    Password { password: String },
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BandwidthConfig {
    pub up: Option<String>,
    pub down: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MasqueradeConfig {
    #[serde(default = "default_masquerade_type")]
    pub r#type: String,
    pub proxy: Option<MasqueradeProxy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MasqueradeProxy {
    pub url: String,
    #[serde(default)]
    pub rewrite_host: bool,
}

// ── VLESS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VlessConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
    /// TCP listen address, e.g. "0.0.0.0:8443"
    pub listen: String,
    /// Single UUID for authentication (matches Xray single-user model)
    pub uuid: String,
    #[serde(default)]
    pub transport: VlessTransportConfig,
}

/// Transport layer configuration.
///
/// Four valid combinations (mirrors Xray transport options):
///   type=tcp,  tls=false  -> plain TCP
///   type=tcp,  tls=true   -> TCP + TLS
///   type=ws,   tls=false  -> WebSocket (no TLS, suitable behind CDN/nginx)
///   type=ws,   tls=true   -> WebSocket + TLS
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VlessTransportConfig {
    /// "tcp" or "ws"
    #[serde(default = "default_transport_type")]
    pub r#type: String,
    /// Whether to wrap the transport with TLS
    #[serde(default)]
    pub tls: bool,
    /// TLS certificate file (PEM). Required when tls=true.
    pub cert: Option<String>,
    /// TLS private key file (PEM). Required when tls=true.
    pub key: Option<String>,
    /// WebSocket path. Only used when type="ws". Default "/".
    #[serde(default = "default_ws_path")]
    pub ws_path: String,
    /// TLS SNI / self-signed domain fallback.
    #[serde(default = "default_self_signed_domain")]
    pub self_signed_domain: String,
}

impl Default for VlessTransportConfig {
    fn default() -> Self {
        Self {
            r#type: default_transport_type(),
            tls: false,
            cert: None,
            key: None,
            ws_path: default_ws_path(),
            self_signed_domain: default_self_signed_domain(),
        }
    }
}

// ── Shared ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self { level: default_log_level() }
    }
}

impl BandwidthConfig {
    pub fn parse_bps(s: &str) -> Option<u64> {
        let s = s.trim().to_lowercase().replace(' ', "");
        if let Some(n) = s.strip_suffix("gbps") {
            n.parse::<f64>().ok().map(|v| (v * 1e9 / 8.0) as u64)
        } else if let Some(n) = s.strip_suffix("mbps") {
            n.parse::<f64>().ok().map(|v| (v * 1e6 / 8.0) as u64)
        } else if let Some(n) = s.strip_suffix("kbps") {
            n.parse::<f64>().ok().map(|v| (v * 1e3 / 8.0) as u64)
        } else if let Some(n) = s.strip_suffix("bps") {
            n.parse::<u64>().ok()
        } else {
            None
        }
    }
    pub fn up_bps(&self) -> Option<u64> { self.up.as_deref().and_then(Self::parse_bps) }
    pub fn down_bps(&self) -> Option<u64> { self.down.as_deref().and_then(Self::parse_bps) }
}

fn default_true() -> bool { true }
fn default_log_level() -> String { "info".to_string() }
fn default_self_signed_domain() -> String { "localhost".to_string() }
fn default_masquerade_type() -> String { "none".to_string() }
fn default_transport_type() -> String { "tcp".to_string() }
fn default_ws_path() -> String { "/".to_string() }

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(Path::new(path))
        .with_context(|| format!("cannot read config file: {path}"))?;
    let cfg: Config =
        serde_yaml::from_str(&content).with_context(|| format!("invalid YAML in {path}"))?;
    Ok(cfg)
}
