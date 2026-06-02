package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ServerConfig 服务端配置
type ServerConfig struct {
	// 隧道服务监听地址
	TunnelAddr string `json:"tunnel_addr"` // IP:端口 默认使用 0.0.0.0:22336

	// SOCKS5 代理监听地址
	SocksAddr string `json:"socks_addr"` // IP:端口 默认使用 0.0.0.0:22337
	SocksUser string `json:"socks_user"` // SOCKS5 认证用户名
	SocksPass string `json:"socks_pass"` // SOCKS5 认证密码

	// 隧道认证令牌（客户端需相同）
	Token string `json:"token"` // 随便填即可

	// 认证时间戳容差
	AuthDriftTolerance Duration `json:"auth_drift_tolerance"` // 如 "60s"

	// 心跳配置
	HeartbeatInterval Duration `json:"heartbeat_interval"` // 如 "10s"
	HeartbeatTimeout  Duration `json:"heartbeat_timeout"`  // 如 "30s"

	// 最大 Agent 连接数
	MaxAgents int `json:"max_agents"` // 如 10
}

// ClientConfig 客户端配置
type ClientConfig struct {
	// 服务端隧道地址
	ServerAddr string `json:"server_addr"` //  服务端IP:端口"

	// 认证令牌（需与服务端一致）
	Token string `json:"token"` // 随便填即可，要和服务端的配置一样

	// 断线重连配置
	ReconnectInterval Duration `json:"reconnect_interval"` // 如 "5s"
	MaxReconnect      int      `json:"max_reconnect"`      // 0 表示无限重试

	// 心跳发送间隔
	HeartbeatInterval Duration `json:"heartbeat_interval"` // 如 "10s"

	// 单 Agent 最大并发连接数
	MaxConnsPerAgent int `json:"max_conns_per_agent"` // 如 100
}

// Duration 封装 time.Duration，支持 JSON 序列化为字符串（如 "60s"）或纳秒整数
type Duration struct {
	time.Duration
}

// MarshalJSON 实现 json.Marshaler，输出人类可读的持续时间字符串
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON 实现 json.Unmarshaler，支持字符串（如 "60s"）和整数（纳秒）两种格式
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		// 尝试作为纳秒整数解析
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return err
		}
		d.Duration = time.Duration(n)
		return nil
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", v, err)
	}
	d.Duration = parsed
	return nil
}

// 服务端默认配置
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		TunnelAddr:         "0.0.0.0:22336",
		SocksAddr:          "0.0.0.0:22337",
		SocksUser:          "admin",
		SocksPass:          "admin@123",
		Token:              "2e0a419a-213e-41f7-b553-ec21425c6d66",
		AuthDriftTolerance: Duration{60 * time.Second},
		HeartbeatInterval:  Duration{10 * time.Second},
		HeartbeatTimeout:   Duration{30 * time.Second},
		MaxAgents:          10,
	}
}

// 客户端默认配置
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerAddr:        "127.0.0.1:22336",
		Token:             "2e0a419a-213e-41f7-b553-ec21425c6d66",
		ReconnectInterval: Duration{5 * time.Second},
		MaxReconnect:      0,
		HeartbeatInterval: Duration{10 * time.Second},
		MaxConnsPerAgent:  100,
	}
}

// LoadServerConfig 从 JSON 文件加载服务端配置，未指定字段使用默认值填充
func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := DefaultServerConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// LoadClientConfig 从 JSON 文件加载客户端配置，未指定字段使用默认值填充
func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg := DefaultClientConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
