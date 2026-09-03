package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"EZRP/internal/crypto"
)

// 报文类型定义
const (
	TypeAuth        uint8 = 0x01 // 客户端→服务端: 认证请求
	TypeAuthOK      uint8 = 0x02 // 服务端→客户端: 认证成功
	TypeAuthFail    uint8 = 0x03 // 服务端→客户端: 认证失败
	TypeHeartbeat   uint8 = 0x10 // 双向: 心跳保活
	TypeConnect     uint8 = 0x20 // 服务端→客户端: 请求连接目标
	TypeConnectOK   uint8 = 0x21 // 客户端→服务端: 连接已建立
	TypeConnectFail uint8 = 0x22 // 客户端→服务端: 连接失败
	TypeData        uint8 = 0x30 // 双向: 数据传输
	TypeClose       uint8 = 0x40 // 双向: 关闭连接
)

// HeaderSize 报文头部长度: Type(1) + ConnID(8) + Side(1) + Length(4) = 14 字节
const HeaderSize = 14

// Message 协议报文结构
type Message struct {
	Type    uint8  // 报文类型
	ConnID  uint64 // 连接 ID
	Length  uint32 // 载荷长度
	Payload []byte // 载荷数据
}

// String 返回报文的人类可读表示
func (m *Message) String() string {
	return fmt.Sprintf("Message{Type=0x%02x, ConnID=%d, Length=%d}", m.Type, m.ConnID, m.Length)
}

// TypeName 返回报文类型的名称字符串
func (m *Message) TypeName() string {
	switch m.Type {
	case TypeAuth:
		return "AUTH"
	case TypeAuthOK:
		return "AUTH_OK"
	case TypeAuthFail:
		return "AUTH_FAIL"
	case TypeHeartbeat:
		return "HEARTBEAT"
	case TypeConnect:
		return "CONNECT"
	case TypeConnectOK:
		return "CONNECT_OK"
	case TypeConnectFail:
		return "CONNECT_FAIL"
	case TypeData:
		return "DATA"
	case TypeClose:
		return "CLOSE"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", m.Type)
	}
}

// Codec 协议编解码器，负责报文的序列化、反序列化与加解密
type Codec struct {
	rw io.ReadWriter

	// 加密相关字段 —— 在 AUTH 握手成功后启用
	// 读写分别使用独立的互斥锁，允许全双工操作。
	// 每把锁覆盖各自的序列号递增和 I/O 操作，防止序列号与字节流顺序不匹配。
	encMu   sync.Mutex
	decMu   sync.Mutex
	enabled bool   // EnableEncryption 调用后为 true
	key     []byte // 32 字节密钥，由 DeriveKey(token) 派生
	sendSeq uint64 // 出帧计数器（单调递增）
	recvSeq uint64 // 入帧计数器（单调递增）
	side    uint8  // crypto.SideClient 或 crypto.SideServer

	// 写缓冲区复用：writeFrame 不再每次 make，而是复用此切片
	// 减少高频数据转发路径上的内存分配和 GC 压力
	writeBuf []byte

	// 读头部缓冲区复用：ReadMessage 每帧复用14字节头部缓冲区
	readHeader []byte
}

// NewCodec 创建新的协议编解码器
func NewCodec(rw io.ReadWriter) *Codec {
	return &Codec{rw: rw}
}

// EnableEncryption 启用 ChaCha20-Poly1305 加密保护后续所有报文。
// 双端必须在 AUTH 握手成功后使用相同的令牌调用此方法。
// side: 客户端使用 crypto.SideClient，服务端使用 crypto.SideServer。
func (c *Codec) EnableEncryption(key []byte, side uint8) {
	c.encMu.Lock()
	defer c.encMu.Unlock()
	c.key = key
	c.side = side
	c.sendSeq = 0
	c.recvSeq = 0
	c.enabled = true
}

// writeFrame 写入一帧报文的通用实现。
// encMu 锁覆盖整个加密+写入路径，确保序列号与字节流顺序一致。
func (c *Codec) writeFrame(msgType uint8, connID uint64, payload []byte) error {
	c.encMu.Lock()
	defer c.encMu.Unlock()

	if c.enabled && len(payload) > 0 {
		encPayload, err := crypto.Encrypt(c.key, connID, c.sendSeq, c.side, payload)
		if err != nil {
			return fmt.Errorf("encrypt payload: %w", err)
		}
		payload = encPayload
		c.sendSeq++
	}

	// 报文头（始终为明文）: Type(1) + ConnID(8) + Side(1) + Length(4)
	// 复用 c.writeBuf 避免每次分配，仅在容量不足时扩容
	need := HeaderSize + len(payload)
	if cap(c.writeBuf) >= need {
		c.writeBuf = c.writeBuf[:need]
	} else {
		// 容量不足：按2倍扩容以减少后续扩容次数（参考 frp 的缓冲策略）
		newCap := cap(c.writeBuf) * 2
		if newCap < need {
			newCap = need
		}
		c.writeBuf = make([]byte, need, newCap)
	}

	buf := c.writeBuf
	buf[0] = msgType
	binary.BigEndian.PutUint64(buf[1:9], connID)
	buf[9] = c.side
	binary.BigEndian.PutUint32(buf[10:14], uint32(len(payload)))
	copy(buf[14:], payload)

	_, err := c.rw.Write(buf)
	return err
}

// WriteMessage 写入一条协议报文。
// 当加密启用时，载荷将使用 ChaCha20-Poly1305 加密。
func (c *Codec) WriteMessage(msg *Message) error {
	return c.writeFrame(msg.Type, msg.ConnID, msg.Payload)
}

// WriteData 高效写入数据报文
func (c *Codec) WriteData(connID uint64, data []byte) error {
	return c.writeFrame(TypeData, connID, data)
}

// ReadMessage 从底层读取并解码一条协议报文。
// decMu 锁覆盖整个读取+解密路径，确保序列号与字节流顺序一致。
func (c *Codec) ReadMessage() (*Message, error) {
	c.decMu.Lock()
	defer c.decMu.Unlock()

	// 复用 header 缓冲区，避免每帧分配14字节
	if cap(c.readHeader) >= HeaderSize {
		c.readHeader = c.readHeader[:HeaderSize]
	} else {
		c.readHeader = make([]byte, HeaderSize)
	}
	header := c.readHeader

	if _, err := io.ReadFull(c.rw, header); err != nil {
		return nil, err
	}

	// 从池中获取 Message struct，减少 GC 压力
	msg := msgPool.Get().(*Message)
	msg.Type = header[0]
	msg.ConnID = binary.BigEndian.Uint64(header[1:9])
	msg.Length = binary.BigEndian.Uint32(header[10:14])
	msg.Payload = nil // 重置 Payload，后续由 make 分配新切片

	// 从头部字节 [9] 提取发送方标识（用于还原正确的解密 nonce）
	msgSide := header[9]

	var seq uint64

	if msg.Length > 0 {
		if msg.Length > 16*1024*1024 { // 最大报文体 16MB（参考 frp 大窗口设计）
			return nil, fmt.Errorf("message too large: %d bytes", msg.Length)
		}
		msg.Payload = make([]byte, msg.Length)
		if _, err := io.ReadFull(c.rw, msg.Payload); err != nil {
			return nil, err
		}
	}

	// 仅当 payload 非空时递增 recvSeq 并解密，
	// 与 writeFrame 中 sendSeq 仅在 payload 非空时递增保持对称。
	if c.enabled && msg.Length > 0 {
		seq = c.recvSeq
		c.recvSeq++

		plaintext, err := crypto.Decrypt(c.key, msg.ConnID, seq, msgSide, msg.Payload)
		if err != nil {
			return nil, fmt.Errorf("decrypt payload: %w", err)
		}
		msg.Payload = plaintext
	}

	// 更新 Length 为实际载荷长度（供调用方检查）
	msg.Length = uint32(len(msg.Payload))
	return msg, nil
}

// msgPool 池化 Message struct，减少高频读取路径上的内存分配
var msgPool = sync.Pool{
	New: func() interface{} {
		return &Message{}
	},
}

// Release 将 Message 归还到对象池，调用方应确保不再使用此 Message 及其 Payload
func (m *Message) Release() {
	m.Payload = nil // 防止池中对象持有大切片引用
	msgPool.Put(m)
}

// AuthPayload 用于 TypeAuth 报文的认证载荷
type AuthPayload struct {
	Token     string `json:"token"`
	Timestamp int64  `json:"timestamp"`
	Hash      string `json:"hash"` // SHA-256(token + timestamp)
}

// ConnectPayload 用于 TypeConnect 报文的连接载荷
type ConnectPayload struct {
	ConnID   uint64 `json:"conn_id"`
	Target   string `json:"target"`          // 目标地址，如 "192.168.1.100:80"
	ErrorMsg string `json:"error,omitempty"` // 错误信息（可选）
}
