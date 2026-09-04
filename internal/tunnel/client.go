package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"EZRP/internal/auth"
	"EZRP/internal/config"
	"EZRP/internal/crypto"
	"EZRP/internal/protocol"

	log "github.com/sirupsen/logrus"
)

// Client 隧道客户端（Agent），连接服务端并转发内网流量
type Client struct {
	cfg       *config.ClientConfig
	codec     *protocol.Codec
	conn      net.Conn
	pool      *ConnPool
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	connected bool
}

// NewClient 创建新的隧道客户端
func NewClient(cfg *config.ClientConfig) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg:    cfg,
		pool:   NewConnPool(),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start 启动隧道客户端（带自动重连）
func (c *Client) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	c.connectLoop()
	return nil
}

// Stop 停止隧道客户端
func (c *Client) Stop() {
	c.cancel()

	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.connected = false
	c.mu.Unlock()

	c.pool.Close()
	log.Info("[Client] Shutdown complete")
}

func (c *Client) connectLoop() {
	// 断线重连循环
	attempt := 0
	maxReconnect := c.cfg.MaxReconnect

	for {
		if maxReconnect > 0 && attempt >= maxReconnect {
			log.Errorf("[Client] Max reconnect attempts (%d) reached", maxReconnect)
			return
		}

		select {
		case <-c.ctx.Done():
			return
		default:
		}

		attempt++
		log.Infof("[Client] Connecting to %s (attempt %d)...", c.cfg.ServerAddr, attempt)

		if err := c.connect(); err != nil {
			log.Errorf("[Client] Connection failed: %v", err)

			select {
			case <-c.ctx.Done():
				return
			case <-time.After(c.cfg.ReconnectInterval.Duration):
				continue
			}
		}

		attempt = 0 // 连接成功，重置重试次数
		log.Info("[Client] Connected successfully")

		// 运行事件循环
		err := c.eventLoop()
		if err != nil {
			log.Errorf("[Client] Disconnected: %v", err)
		}

		// 清理连接池
		c.pool.Close()
		c.pool = NewConnPool()

		c.mu.Lock()
		c.connected = false
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.mu.Unlock()
	}
}

func (c *Client) connect() error {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.DialContext(c.ctx, "tcp", c.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
		tc.SetReadBuffer(4 * 1024 * 1024)  // 4MB 接收缓冲区
		tc.SetWriteBuffer(4 * 1024 * 1024) // 4MB 发送缓冲区
	}

	c.mu.Lock()
	c.conn = conn
	c.codec = protocol.NewCodec(conn)
	c.mu.Unlock()

	// 执行认证
	if err := c.auth(); err != nil {
		conn.Close()
		return fmt.Errorf("auth: %w", err)
	}

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	return nil
}

func (c *Client) auth() error {
	timestamp := time.Now().Unix()
	hash := auth.GenerateHash(c.cfg.Token, timestamp)

	payload := protocol.AuthPayload{
		Token:     "",
		Timestamp: timestamp,
		Hash:      hash,
	}
	data, _ := json.Marshal(payload)

	msg := &protocol.Message{
		Type:    protocol.TypeAuth,
		Payload: data,
	}

	c.mu.Lock()
	codec := c.codec
	c.mu.Unlock()

	if err := codec.WriteMessage(msg); err != nil {
		return fmt.Errorf("send AUTH: %w", err)
	}

	// 读取服务端响应
	resp, err := codec.ReadMessage()
	if err != nil {
		return fmt.Errorf("read AUTH response: %w", err)
	}

	switch resp.Type {
	case protocol.TypeAuthOK:
		// AUTH 握手成功后启用 ChaCha20-Poly1305 加密保护后续消息
		scrambleKey := crypto.DeriveKey(c.cfg.Token)
		c.mu.Lock()
		c.codec.EnableEncryption(scrambleKey, crypto.SideClient)
		c.mu.Unlock()
		log.Info("[Client] Scramble enabled")
		return nil
	case protocol.TypeAuthFail:
		return fmt.Errorf("authentication failed")
	default:
		return fmt.Errorf("unexpected auth response: 0x%02x", resp.Type)
	}
}

func (c *Client) eventLoop() error {
	// 启动心跳协程
	hbCtx, hbCancel := context.WithCancel(c.ctx)
	defer hbCancel()
	go c.heartbeatLoop(hbCtx)

	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}

		c.mu.Lock()
		codec := c.codec
		c.mu.Unlock()

		if codec == nil {
			return fmt.Errorf("connection lost")
		}

		msg, err := codec.ReadMessage()
		if err != nil {
			return fmt.Errorf("read message: %w", err)
		}

		switch msg.Type {
		case protocol.TypeHeartbeat:
			// 回复心跳
			reply := &protocol.Message{Type: protocol.TypeHeartbeat}
			if err := codec.WriteMessage(reply); err != nil {
				return fmt.Errorf("send heartbeat: %w", err)
			}
			msg.Release()

		case protocol.TypeConnect:
			// handleConnect 在 goroutine 中运行，由其负责 Release
			go c.handleConnect(msg)

		case protocol.TypeData:
			// 同步分发：eventLoop 按 TCP 收到的顺序依次调用 SendData，
			// 保证同一 connID 的数据严格有序写入 readCh。
			connID := msg.ConnID
			payload := msg.Payload
			msg.Release()
			tc, ok := c.pool.Get(connID)
			if ok {
				if !tc.SendData(c.ctx, payload) {
					log.Warnf("[Client] conn %d SendData failed", connID)
				}
			}

		case protocol.TypeClose:
			// TypeData 已改为同步调用，不存在异步写入竞争，
			// 直接移除连接即可。
			connID := msg.ConnID
			msg.Release()
			c.pool.Remove(connID)

		default:
			log.Warnf("[Client] Unknown message type: 0x%02x", msg.Type)
			msg.Release()
		}
	}
}

func (c *Client) handleConnect(msg *protocol.Message) {
	var cp protocol.ConnectPayload
	if err := json.Unmarshal(msg.Payload, &cp); err != nil {
		log.Errorf("[Client] Parse CONNECT payload: %v", err)
		c.sendConnectFail(msg.ConnID, err.Error())
		msg.Release()
		return
	}

	connID := msg.ConnID
	msg.Release() // Payload 已 Unmarshal，Message 可归还池

	log.Infof("[Client] CONNECT request: connID=%d target=%s", connID, cp.Target)

	// 拨号本地网络目标
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.DialContext(c.ctx, "tcp", cp.Target)
	if err != nil {
		log.Errorf("[Client] Failed to connect to %s: %v", cp.Target, err)
		c.sendConnectFail(connID, err.Error())
		return
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
		tc.SetReadBuffer(4 * 1024 * 1024)  // 4MB 接收缓冲区
		tc.SetWriteBuffer(4 * 1024 * 1024) // 4MB 发送缓冲区
	}

	// 发送 CONNECT_OK
	if err := c.sendConnectOK(connID); err != nil {
		conn.Close()
		return
	}

	// 创建隧道连接并启动转发
	tc := NewTunnelConn(connID)
	c.pool.Put(tc)

	c.mu.Lock()
	codec := c.codec
	c.mu.Unlock()

	// 全双工数据转发（bufSize=0 使用默认64KB，由 CopyData 内部缓冲区池提供）
	err = CopyData(c.ctx, conn, tc, codec, 0)

	conn.Close()
	c.pool.Remove(connID)

	// 发送 CLOSE
	closeMsg := &protocol.Message{
		Type:   protocol.TypeClose,
		ConnID: connID,
	}
	codec.WriteMessage(closeMsg)

	if err != nil && err != c.ctx.Err() {
		log.Debugf("[Client] Conn %d data forwarding ended: %v", connID, err)
	}
}

func (c *Client) sendConnectOK(connID uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	msg := &protocol.Message{
		Type:   protocol.TypeConnectOK,
		ConnID: connID,
	}
	return c.codec.WriteMessage(msg)
}

func (c *Client) sendConnectFail(connID uint64, errMsg string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, _ := json.Marshal(protocol.ConnectPayload{
		ConnID:   connID,
		ErrorMsg: errMsg,
	})
	msg := &protocol.Message{
		Type:    protocol.TypeConnectFail,
		ConnID:  connID,
		Payload: data,
	}
	return c.codec.WriteMessage(msg)
}

func (c *Client) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.HeartbeatInterval.Duration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			codec := c.codec
			connected := c.connected
			c.mu.Unlock()

			if !connected || codec == nil {
				return
			}

			msg := &protocol.Message{Type: protocol.TypeHeartbeat}
			if err := codec.WriteMessage(msg); err != nil {
				log.Warnf("[Client] Send heartbeat: %v", err)
				return
			}
		}
	}
}
