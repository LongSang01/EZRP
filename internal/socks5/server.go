package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"EZRP/internal/config"

	log "github.com/sirupsen/logrus"
)

// SOCKS5 协议常量
const (
	socks5Version = 0x05

	authMethodUserPass     = 0x02 // 用户名/密码认证方法
	authMethodNoAcceptable = 0xFF // 无可用认证方法

	cmdConnect = 0x01 // CONNECT 命令

	addrTypeIPv4   = 0x01 // IPv4 地址类型
	addrTypeDomain = 0x03 // 域名地址类型
	addrTypeIPv6   = 0x04 // IPv6 地址类型

	repSuccess         = 0x00 // 成功响应
	repGeneralFailure  = 0x01 // 通用错误
	repCmdNotSupported = 0x07 // 不支持的命令

	userPassVersion = 0x01 // 用户名/密码子协商版本号
)

// RemoteDialer 通过反向隧道拨号目标的函数类型
// 返回双向连通的 net.Conn
type RemoteDialer func(ctx context.Context, target string) (net.Conn, error)

// Server 实现 SOCKS5 代理，通过反向隧道转发 CONNECT 请求
type Server struct {
	cfg    config.ServerConfig
	ctx    context.Context
	cancel context.CancelFunc
	lis    net.Listener
	dial   RemoteDialer
}

// NewServer 创建 SOCKS5 服务端
func NewServer(cfg *config.ServerConfig, dial RemoteDialer) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:    *cfg,
		ctx:    ctx,
		cancel: cancel,
		dial:   dial,
	}
}

// Start 启动 SOCKS5 监听与连接接受
func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	var lc net.ListenConfig
	lc.KeepAlive = 30 * time.Second

	lis, err := lc.Listen(ctx, "tcp", s.cfg.SocksAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	s.lis = lis

	log.Infof("[SOCKS5] Server listening on %s", s.cfg.SocksAddr)
	go s.acceptLoop()
	return nil
}

// Stop 停止 SOCKS5 服务端
func (s *Server) Stop() {
	s.cancel()
	if s.lis != nil {
		s.lis.Close()
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.lis.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Errorf("[SOCKS5] Accept error: %v", err)
				continue
			}
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Debugf("[SOCKS5] Connection from %s", remote)

	// SOCKS5 握手（用户名/密码认证）
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := s.doHandshake(conn); err != nil {
		log.Errorf("[SOCKS5] Handshake failed %s: %v", remote, err)
		return
	}

	// 读取 CONNECT 请求
	target, err := s.readConnect(conn)
	if err != nil {
		log.Errorf("[SOCKS5] Read connect from %s: %v", remote, err)
		return
	}
	conn.SetDeadline(time.Time{}) // 清除超时，进入数据转发阶段

	log.Infof("[SOCKS5] CONNECT %s -> %s", remote, target)

	// 通过反向隧道拨号目标
	tunnelConn, err := s.dial(s.ctx, target)
	if err != nil {
		log.Errorf("[SOCKS5] Tunnel dial %s: %v", target, err)
		s.writeReply(conn, repGeneralFailure, nil, 0)
		return
	}
	defer tunnelConn.Close()

	// 发送成功响应
	if err := s.writeReply(conn, repSuccess, net.IPv4zero, 0); err != nil {
		log.Errorf("[SOCKS5] Write reply to %s: %v", remote, err)
		return
	}

	log.Infof("[SOCKS5] Tunnel established %s <-> %s", remote, target)

	// 全双工转发
	s.relay(conn, tunnelConn, remote, target)
}

func (s *Server) doHandshake(conn net.Conn) error {
	// VER NMETHODS METHODS（版本 + 支持的认证方法列表）
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("bad version: 0x%02x", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	ok := false
	for _, m := range methods {
		if m == authMethodUserPass {
			ok = true
			break
		}
	}
	if !ok {
		conn.Write([]byte{socks5Version, authMethodNoAcceptable})
		return fmt.Errorf("no acceptable auth method")
	}

	// 确认支持用户名/密码认证
	if _, err := conn.Write([]byte{socks5Version, authMethodUserPass}); err != nil {
		return err
	}

	// 子协商（RFC 1929 用户名/密码认证）
	ver := make([]byte, 1)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return err
	}
	if ver[0] != userPassVersion {
		conn.Write([]byte{userPassVersion, 0x01})
		return fmt.Errorf("bad sub-negotiation version")
	}

	uLenB := make([]byte, 1)
	if _, err := io.ReadFull(conn, uLenB); err != nil {
		return err
	}
	uLen := int(uLenB[0])
	user := make([]byte, uLen)
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}

	pLenB := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenB); err != nil {
		return err
	}
	pLen := int(pLenB[0])
	pass := make([]byte, pLen)
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	if string(user) != s.cfg.SocksUser || string(pass) != s.cfg.SocksPass {
		conn.Write([]byte{userPassVersion, 0x01})
		return fmt.Errorf("bad credentials")
	}
	_, err := conn.Write([]byte{userPassVersion, 0x00})
	return err
}

func (s *Server) readConnect(conn net.Conn) (string, error) {
	// VER CMD RSV ATYP（版本 + 命令 + 保留 + 地址类型）
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", err
	}
	if hdr[0] != socks5Version {
		return "", fmt.Errorf("bad version")
	}
	if hdr[1] != cmdConnect {
		s.writeReply(conn, repCmdNotSupported, nil, 0)
		return "", fmt.Errorf("cmd %d not supported", hdr[1])
	}

	var host string
	switch hdr[3] {
	case addrTypeIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case addrTypeDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", err
		}
		domain := make([]byte, length[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case addrTypeIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		s.writeReply(conn, repCmdNotSupported, nil, 0)
		return "", fmt.Errorf("addr type %d not supported", hdr[3])
	}

	portB := make([]byte, 2)
	if _, err := io.ReadFull(conn, portB); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portB)

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (s *Server) writeReply(conn net.Conn, reply byte, bind net.IP, bindPort uint16) error {
	if bind == nil {
		bind = net.IPv4zero
	}
	var resp []byte
	if bind.To4() != nil {
		resp = make([]byte, 10)
		resp[3] = addrTypeIPv4
		copy(resp[4:8], bind.To4())
	} else {
		resp = make([]byte, 22)
		resp[3] = addrTypeIPv6
		copy(resp[4:20], bind.To16())
	}
	resp[0] = socks5Version
	resp[1] = reply
	resp[2] = 0x00
	binary.BigEndian.PutUint16(resp[len(resp)-2:], bindPort)
	_, err := conn.Write(resp)
	return err
}

func (s *Server) relay(left, right net.Conn, leftAddr, rightAddr string) {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			src.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, err := src.Read(buf)
			if n > 0 {
				dst.SetWriteDeadline(time.Now().Add(60 * time.Second))
				if _, ew := dst.Write(buf[:n]); ew != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	go cp(right, left)
	go cp(left, right)

	wg.Wait()
	log.Infof("[SOCKS5] Relay closed %s <-> %s", leftAddr, rightAddr)
}
