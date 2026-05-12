//! 伪装模块（Masquerade）
//!
//! 当普通 HTTPS 客户端（浏览器、爬虫等）连接到服务器时，
//! 服务器应返回正常的 HTTP 响应，而不是直接拒绝，
//! 以避免被流量分析识别为代理服务器。
//!
//! 支持两种模式：
//! - `none`：直接返回 404
//! - `proxy`：反向代理到目标 URL（如真实网站）

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HOST, LOCATION};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::MasqueradeConfig;

// ── 公共入口 ──────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub async fn handle_masquerade(
    stream: TokioIo<TcpStream>,
    peer: SocketAddr,
    cfg: Arc<MasqueradeConfig>,
) {
    let cfg2 = Arc::clone(&cfg);
    let svc = service_fn(move |req: Request<Incoming>| {
        let cfg3 = Arc::clone(&cfg2);
        async move { dispatch(req, cfg3).await }
    });

    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(stream, svc)
        .await
    {
        debug!("Masquerade connection {peer} error: {e}");
    }
}

// ── 请求分发 ──────────────────────────────────────────────────────────────────

async fn dispatch(
    req: Request<Incoming>,
    cfg: Arc<MasqueradeConfig>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match cfg.r#type.as_str() {
        "proxy" => {
            if let Some(proxy_cfg) = &cfg.proxy {
                match reverse_proxy(req, &proxy_cfg.url, proxy_cfg.rewrite_host).await {
                    Ok(resp) => Ok(resp),
                    Err(e) => {
                        warn!("Masquerade proxy error: {e}");
                        Ok(error_response(StatusCode::BAD_GATEWAY, "Bad Gateway"))
                    }
                }
            } else {
                Ok(error_response(StatusCode::NOT_FOUND, "Not Found"))
            }
        }
        _ => Ok(not_found_response()),
    }
}

// ── 反向代理实现 ──────────────────────────────────────────────────────────────

async fn reverse_proxy(
    req: Request<Incoming>,
    target_base: &str,
    rewrite_host: bool,
) -> Result<Response<Full<Bytes>>> {
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let target_url = format!("{}{}", target_base.trim_end_matches('/'), path_and_query);

    debug!("Masquerade proxy → {target_url}");

    let target_uri: hyper::Uri = target_url
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid target URI: {e}"))?;

    let mut builder = Request::builder()
        .method(req.method())
        .uri(target_uri.clone());

    for (name, value) in req.headers() {
        if name == HOST && rewrite_host {
            continue;
        }
        builder = builder.header(name, value);
    }

    if rewrite_host {
        if let Some(host) = target_uri.host() {
            let host_val = if let Some(port) = target_uri.port_u16() {
                format!("{host}:{port}")
            } else {
                host.to_string()
            };
            builder = builder.header(HOST, host_val);
        }
    }

    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("read request body: {e}"))?
        .to_bytes();

    let outgoing_req = builder
        .body(Full::new(body_bytes))
        .map_err(|e| anyhow::anyhow!("build proxy request: {e}"))?;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    let proxy_resp = client
        .request(outgoing_req)
        .await
        .map_err(|e| anyhow::anyhow!("proxy request failed: {e}"))?;

    if proxy_resp.status().is_redirection() {
        let mut resp = Response::builder().status(proxy_resp.status());
        if let Some(loc) = proxy_resp.headers().get(LOCATION) {
            resp = resp.header(LOCATION, loc);
        }
        return resp
            .body(Full::new(Bytes::new()))
            .map_err(|e| anyhow::anyhow!("{e}"));
    }

    let status = proxy_resp.status();
    let headers = proxy_resp.headers().clone();
    let body = proxy_resp
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("read proxy response: {e}"))?
        .to_bytes();

    let mut resp = Response::builder().status(status);
    for (name, value) in &headers {
        if name.as_str().to_lowercase() == "transfer-encoding" {
            continue;
        }
        resp = resp.header(name, value);
    }

    resp.body(Full::new(body))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

// ── 静态响应 ──────────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn not_found_response() -> Response<Full<Bytes>> {
    let body = r#"<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body>
</html>"#;
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Server", "nginx/1.24.0")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

#[allow(dead_code)]
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap()
}
