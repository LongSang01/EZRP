# EZRP — 反向代理隧道工具

基于 Go 语言实现的反向代理隧道工具，用于穿透 NAT/防火墙，从公网访问内网服务

完全使用[MiMo-v2.5-pro](http://mimo.xiaomi.com/zh/mi)实现，`0% 人工代码`，`100 %AI 生成`

功能实现近似于[FRP](https://github.com/fatedier/frp)的以下配置

```toml
 [[proxies]]
 name = "plugin_socks5"
 type = "tcp"
 remotePort = 22337
 [proxies.plugin]
 type = "socks5"
 username = "admin"
 password = "admin@123"
```

## 架构概述

```
外部用户 ──SOCKS5──> 服务端(公网) <══隧道══ 客户端(内网) ──> 内网目标
```

- **服务端 (Server)**：部署在公网，监听服务端口和 SOCKS5 端口。
- **客户端 (Agent)**：部署在内网，主动连接服务端隧道端口，保持长连接。收到服务端指令后，请求内网目标并转发数据。
- **SOCKS5 代理**：外部用户通过 SOCKS5 接入服务端接口，请求被透明地转发到客户端所在的内网目标。

## 目录结构

```
├── cmd/
│   ├── client/main.go      # 客户端入口
│   └── server/main.go      # 服务端入口
├── config/
│   ├── client.json          # 客户端示例配置
│   └── server.json          # 服务端示例配置
├── internal/
│   ├── auth/auth.go         # 认证：SHA-256 哈希 + 时间戳校验
│   ├── config/config.go     # 配置加载与默认值
│   ├── crypto/scramble.go   # 加密：ChaCha20-Poly1305 AEAD
│   ├── protocol/message.go  # 协议：报文编解码与加密帧
│   ├── socks5/server.go     # SOCKS5 代理服务
│   └── tunnel/
│       ├── client.go        # 隧道客户端（Agent）
│       ├── connpipe.go      # net.Conn 适配与双向数据转发
│       ├── pool.go          # 连接池与逻辑连接管理
│       └── server.go        # 隧道服务端
├── go.mod
└── README.md
```

## 快速开始

### 编译

```bash
go build -o ezrps ./cmd/server
go build -o ezrpc ./cmd/client
```

### 生成默认配置

```bash
./ezrps -gen-config > config/server.json
./ezrpc -gen-config > config/client.json
```

### 启动服务端

```bash
./ezrps -c config/server.json -log debug
```

服务端将监听：

- `0.0.0.0:22336` — 隧道端口
- `0.0.0.0:22337` — SOCKS5 代理端口

### 启动客户端

```bash
./ezrpc -c config/client.json -log debug
```

客户端将主动连接服务端隧道端口，等待 CONNECT 指令。

### 默认配置启动

允许单文件启动，通过修改`internal/config/config.go`内的默认配置`DefaultServerConfig`，`DefaultClientConfig`即可无需配置文件独立启动

```
./ezrps
./ezrpc
```

### 使用 SOCKS5 代理

通过任意 SOCKS5 客户端连接服务端的 SOCKS5 端口（默认 `22337`），使用配置文件中的用户名/密码认证，即可访问客户端所在内网的目标服务：

```bash
curl --socks5 admin:'admin@123'@公网IP:22337 http://192.168.1.100:80
```

## 配置说明

### 服务端配置 (`config/server.json`)

| 字段                   | 类型   | 说明                                |
| ---------------------- | ------ | ----------------------------------- |
| `tunnel_addr`          | string | 隧道监听地址，如 `0.0.0.0:22336`    |
| `socks_addr`           | string | SOCKS5 监听地址，如 `0.0.0.0:22337` |
| `socks_user`           | string | SOCKS5 用户名                       |
| `socks_pass`           | string | SOCKS5 密码                         |
| `token`                | string | 隧道认证令牌（客户端需相同）        |
| `auth_drift_tolerance` | string | 认证时间戳容差，如 `60s`            |
| `heartbeat_interval`   | string | 心跳发送间隔，如 `10s`              |
| `heartbeat_timeout`    | string | 心跳超时断连时间，如 `30s`          |
| `max_agents`           | int    | 最大 Agent 连接数                   |

### 客户端配置 (`config/client.json`)

| 字段                  | 类型   | 说明                              |
| --------------------- | ------ | --------------------------------- |
| `server_addr`         | string | 服务端隧道地址，如 `公网IP:22336` |
| `token`               | string | 认证令牌（需与服务端一致）        |
| `reconnect_interval`  | string | 断线重连间隔，如 `5s`             |
| `max_reconnect`       | int    | 最大重连次数，`0` 表示无限重试    |
| `heartbeat_interval`  | string | 心跳发送间隔，如 `10s`            |
| `max_conns_per_agent` | int    | 单 Agent 最大并发连接数           |
