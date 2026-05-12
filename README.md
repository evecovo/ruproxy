# ruhy

Rust 实现的 [Hysteria2](https://v2.hysteria.network/) 服务端。基于 QUIC 协议，支持 TCP/UDP 代理、Brutal 拥塞控制和 HTTP 伪装。

## 特性

- **Hysteria2 协议兼容**：与官方客户端（hysteria2、sing-box、clash.meta 等）完全兼容
- **TCP & UDP 代理**：完整的 TCP 双向转发 + UDP 关联（含分片重组）
- **Brutal 拥塞控制**：固定速率发送，容忍丢包，适合高延迟/高丢包网络
- **TLS 灵活配置**：支持加载已有证书，或自动生成自签名证书
- **HTTP 伪装**：可将普通 HTTPS 流量反向代理到真实网站
- **多认证模式**：密码认证 / 开放模式
- **单二进制**：无运行时依赖，静态链接版本开箱即用

## 快速开始

### 从 Release 下载

在 [Releases](../../releases) 页面下载对应平台的预编译二进制：

| 平台 | 文件名 |
|------|--------|
| Linux x86_64 (musl) | `ruhy-linux-amd64` |
| Linux ARM64 | `ruhy-linux-arm64` |
| macOS x86_64 | `ruhy-macos-amd64` |
| macOS Apple Silicon | `ruhy-macos-arm64` |
| Windows x86_64 | `ruhy-windows-amd64.exe` |

### 从源码编译

```bash
# 需要 Rust 1.75+
git clone https://github.com/yourname/ruhy
cd ruhy
cargo build --release
./target/release/ruhy config.yaml
```

### 配置

复制并编辑配置文件：

```bash
cp config.yaml my-config.yaml
# 编辑 my-config.yaml
```

最小配置示例：

```yaml
server:
  listen: "0.0.0.0:443"

tls:
  self_signed_domain: "example.com"

auth:
  type: password
  password: "your-password"
```

完整配置说明见 [`config.yaml`](config.yaml)。

### 启动

```bash
# 使用默认配置文件 config.yaml
./ruhy

# 指定配置文件路径
./ruhy /etc/ruhy/config.yaml

# 调整日志级别
RUST_LOG=debug ./ruhy config.yaml
```

## 客户端配置示例

### sing-box

```json
{
  "outbounds": [{
    "type": "hysteria2",
    "server": "your-server-ip",
    "server_port": 443,
    "password": "your-password",
    "tls": {
      "enabled": true,
      "insecure": true
    }
  }]
}
```

### Clash Meta / Mihomo

```yaml
proxies:
  - name: ruhy
    type: hysteria2
    server: your-server-ip
    port: 443
    password: your-password
    skip-cert-verify: true
```

> **注意**：使用自签名证书时需开启 `skip-cert-verify` / `insecure`。  
> 生产环境建议配置真实 TLS 证书（如 Let's Encrypt）。

## 配置说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `server.listen` | string | 监听地址，如 `0.0.0.0:443` |
| `server.max_streams` | int | 最大并发流数（默认 64） |
| `server.idle_timeout_secs` | int | 连接空闲超时秒数（默认 60） |
| `tls.cert` | string? | PEM 证书路径，留空则自签名 |
| `tls.key` | string? | PEM 私钥路径 |
| `tls.self_signed_domain` | string | 自签名域名（默认 localhost） |
| `auth.type` | string | `password` 或 `none` |
| `auth.password` | string | 认证密码 |
| `bandwidth.up` | string? | 上行带宽，如 `100 mbps` |
| `bandwidth.down` | string? | 下行带宽 |
| `masquerade.type` | string | `proxy` 或 `none` |
| `masquerade.proxy.url` | string | 反向代理目标 URL |
| `masquerade.proxy.rewrite_host` | bool | 是否重写 Host 头 |
| `log.level` | string | 日志级别（默认 `info`） |

## 开发

```bash
# 运行测试
cargo test

# 代码检查
cargo clippy

# 格式化
cargo fmt
```

## License

MIT
