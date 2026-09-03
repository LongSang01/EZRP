package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"EZRP/internal/auth"
	"EZRP/internal/config"
	"EZRP/internal/crypto"
	"EZRP/internal/protocol"

	log "github.com/sirupsen/logrus"
)

// Agent 表示已连接的客户端 Agent
type Agent struct {
	ID       uint64
	conn     net.Conn
	codec    *protocol.Codec
	pool     *ConnPool
	lastBeat time.Time
	mu       sync.Mutex
}

// Server 隧道服务端，接受 Agent 连接并管理连接池
type Server struct {
	cfg         *config.ServerConfig
	listener    net.Listener
	agents      sync.Map // agentID -> *Agent
	agentCount  atomic.Int32
	nextAgentID atomic.Uint64
	mu          sync.RWMutex
	closed      bool
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewServer 创建新的隧道服务端
func NewServer(cfg *config.ServerConfig) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start 启动隧道服务端
func (s *Server) Start(ctx context.Context) error {
	var lc net.ListenConfig
	lc.KeepAlive = 30 * time.Second

	listener, err := lc.Listen(ctx, "tcp", s.cfg.TunnelAddr)
	if err != nil {
		return fmt.Errorf("tunnel listen: %w", err)
	}
	s.listener = listener

	log.Infof("[Tunnel] Server listening on %s", s.cfg.TunnelAddr)

	go s.acceptLoop()
	go s.heartbeatLoop()

	return nil
}

// Stop 优雅停止隧道服务端
func (s *Server) Stop() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	// 关闭所有 Agent
	s.agents.Range(func(key, value interface{}) bool {
		agent := value.(*Agent)
		agent.conn.Close()
		agent.pool.Close()
		return true
	})

	log.Info("[Tunnel] Server stopped")
}

// Connect 通过可用的 Agent 向指定目标发起隧道连接
// 返回 net.Conn 接口，底层由隧道支撑，适用于双向数据转发
func (s *Server) Connect(target string) (net.Conn, error) {
	// 获取可用的 Agent
	var selected *Agent
	s.agents.Range(func(key, value interface{}) bool {
		agent := value.(*Agent)
		selected = agent
		return false
	})

	if selected == nil {
		return nil, fmt.Errorf("no agent available")
	}

	// 注册 TunnelConn，为 CONNECT 结果创建专用 readCh
	connID := selected.pool.GetCounter()

	// 创建带有超时的上下文，等待 CONNECT 结果
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()

	tc := NewTunnelConn(connID)
	selected.pool.Put(tc)

	payload := protocol.ConnectPayload{
		ConnID: connID,
		Target: target,
	}
	data, _ := json.Marshal(payload)
	msg := &protocol.Message{
		Type:    protocol.TypeConnect,
		ConnID:  connID,
		Payload: data,
	}

	if err := selected.codec.WriteMessage(msg); err != nil {
		selected.pool.Remove(connID)
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}

	// 等待 Agent 发回 CONNECT_OK 或 CONNECT_FAIL
	// 读取循环将数据发到 tc.readCh(OK) 或 closeCh(FAIL)
	select {
	case <-ctx.Done():
		selected.pool.Remove(connID)
		return nil, fmt.Errorf("timeout waiting for CONNECT result")
	case <-tc.closeCh:
		selected.pool.Remove(connID)
		return nil, fmt.Errorf("connection failed at agent")
	case data, ok := <-tc.readCh:
		if !ok {
			selected.pool.Remove(connID)
			return nil, fmt.Errorf("tunnel connection closed")
		}
		// CONNECT_OK 信号：检查内嵌的错误信息
		if len(data) > 0 {
			var cp protocol.ConnectPayload
			if json.Unmarshal(data, &cp) == nil && cp.ErrorMsg != "" {
				selected.pool.Remove(connID)
				return nil, fmt.Errorf("agent connect error: %s", cp.ErrorMsg)
			}
		}
		// CONNECT_OK 确认——数据转发由返回的 ConnPipe 控制
	}

	// 返回 ConnPipe 包装隧道连接
	return NewConnPipe(tc, selected.codec), nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.RLock()
			closed := s.closed
			s.mu.RUnlock()
			if closed {
				return
			}
			log.Errorf("[Tunnel] Accept error: %v", err)
			continue
		}

		if int(s.agentCount.Load()) >= s.cfg.MaxAgents {
			log.Warnf("[Tunnel] Max agents reached, rejecting %s", conn.RemoteAddr())
			conn.Close()
			continue
		}

		go s.handleAgent(conn)
	}
}

func (s *Server) handleAgent(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Infof("[Tunnel] New connection from %s", remoteAddr)

	// 设置 TCP keepalive 和内核缓冲区（参考 frp KCP 4MB buffer 策略）
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
		tc.SetReadBuffer(4 * 1024 * 1024)  // 4MB 接收缓冲区
		tc.SetWriteBuffer(4 * 1024 * 1024) // 4MB 发送缓冲区
	}

	codec := protocol.NewCodec(conn)

	// 等待 AUTH 报文
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	msg, err := codec.ReadMessage()
	if err != nil {
		log.Errorf("[Tunnel] Read AUTH from %s: %v", remoteAddr, err)
		conn.Close()
		return
	}

	if msg.Type != protocol.TypeAuth {
		log.Errorf("[Tunnel] Expected AUTH from %s, got 0x%02x", remoteAddr, msg.Type)
		conn.Close()
		return
	}

	// 验证认证
	var authPayload protocol.AuthPayload
	if err := json.Unmarshal(msg.Payload, &authPayload); err != nil {
		log.Errorf("[Tunnel] Parse AUTH payload from %s: %v", remoteAddr, err)
		conn.Close()
		return
	}

	if err := auth.ValidateHash(s.cfg.Token, authPayload.Hash, authPayload.Timestamp, 60*time.Second); err != nil {
		log.Warnf("[Tunnel] Auth failed from %s: %v", remoteAddr, err)
		failMsg := &protocol.Message{Type: protocol.TypeAuthFail}
		codec.WriteMessage(failMsg)
		conn.Close()
		return
	}

	// 认证成功
	agentID := s.nextAgentID.Add(1)
	agent := &Agent{
		ID:       agentID,
		conn:     conn,
		codec:    codec,
		pool:     NewConnPool(),
		lastBeat: time.Now(),
	}

	s.agents.Store(agentID, agent)
	s.agentCount.Add(1)
	conn.SetReadDeadline(time.Time{}) // 清除读取超时

	log.Infof("[Tunnel] Agent %d connected from %s", agentID, remoteAddr)

	// 发送 AUTH_OK
	okMsg := &protocol.Message{Type: protocol.TypeAuthOK}
	if err := codec.WriteMessage(okMsg); err != nil {
		log.Errorf("[Tunnel] Send AUTH_OK to %s: %v", remoteAddr, err)
		s.removeAgent(agentID)
		return
	}

	// AUTH 握手成功后启用 ChaCha20-Poly1305 加密保护后续消息
	scrambleKey := crypto.DeriveKey(s.cfg.Token)
	codec.EnableEncryption(scrambleKey, crypto.SideServer)
	log.Infof("[Tunnel] Scramble enabled for agent %d", agentID)

	// 进入读循环
	s.agentReadLoop(agent)
}

func (s *Server) agentReadLoop(agent *Agent) {
	defer func() {
		s.removeAgent(agent.ID)
	}()

	for {
		msg, err := agent.codec.ReadMessage()
		if err != nil {
			log.Warnf("[Tunnel] Agent %d read error: %v", agent.ID, err)
			return
		}

		agent.lastBeat = time.Now()

		switch msg.Type {
		case protocol.TypeHeartbeat:
			// 心跳响应异步发送，避免写阻塞卡住整个读循环
			go agent.codec.WriteMessage(&protocol.Message{Type: protocol.TypeHeartbeat})
			msg.Release()

		case protocol.TypeConnectOK:
			tc, ok := agent.pool.Get(msg.ConnID)
			if ok {
				// 发送空载荷表示 CONNECT_OK 信号
				tc.SendData(s.ctx, msg.Payload)
			}
			msg.Release()

		case protocol.TypeConnectFail:
			tc, ok := agent.pool.Get(msg.ConnID)
			if ok {
				tc.Close()
			}
			msg.Release()

		case protocol.TypeData:
			// 异步分发：避免单个连接的 SendData 阻塞整个 agent 的消息循环
			// 每个连接的数据处理在独立 goroutine 中进行
			connID := msg.ConnID
			payload := msg.Payload
			msg.Release() // Message struct 归还池，payload 由 SendData 消费
			tc, ok := agent.pool.Get(connID)
			if ok {
				go func() {
					if !tc.SendData(s.ctx, payload) {
						log.Warnf("[Tunnel] Agent %d conn %d SendData failed, consumer may be slow", agent.ID, connID)
					}
				}()
			}

		case protocol.TypeClose:
			agent.pool.Remove(msg.ConnID)
			msg.Release()

		default:
			log.Warnf("[Tunnel] Agent %d: unknown message type 0x%02x", agent.ID, msg.Type)
			msg.Release()
		}
	}
}

func (s *Server) removeAgent(agentID uint64) {
	if _, loaded := s.agents.LoadAndDelete(agentID); loaded {
		s.agentCount.Add(-1)
		log.Infof("[Tunnel] Agent %d disconnected", agentID)
	}
}

func (s *Server) heartbeatLoop() {
	ticker := time.NewTicker(s.cfg.HeartbeatTimeout.Duration)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.agents.Range(func(key, value interface{}) bool {
				agent := value.(*Agent)
				if now.Sub(agent.lastBeat) > s.cfg.HeartbeatTimeout.Duration {
					log.Warnf("[Tunnel] Agent %d heartbeat timeout, disconnecting", agent.ID)
					agent.conn.Close()
					s.removeAgent(agent.ID)
				}
				return true
			})
		}
	}
}
