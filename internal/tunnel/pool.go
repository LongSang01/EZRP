package tunnel

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// ConnPool 管理活动的 Agent 连接池，用于连接多路复用
type ConnPool struct {
	mu      sync.RWMutex
	conns   map[uint64]*TunnelConn // connID -> 隧道连接
	closed  bool
	counter atomic.Uint64
}

// TunnelConn 表示隧道内的单条逻辑连接
type TunnelConn struct {
	ConnID  uint64
	ctx     context.Context
	cancel  context.CancelFunc
	readCh  chan []byte
	closeCh chan struct{}
	closed  atomic.Bool
	mu      sync.Mutex
}

// GetCounter 原子递增并返回计数器值，用于分配全局唯一的 connID
func (cp *ConnPool) GetCounter() uint64 {
	return cp.counter.Add(1)
}

// NewConnPool 创建新的连接池
func NewConnPool() *ConnPool {
	return &ConnPool{
		conns: make(map[uint64]*TunnelConn),
	}
}

// NewTunnelConn 创建新的隧道逻辑连接
func NewTunnelConn(connID uint64) *TunnelConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &TunnelConn{
		ConnID:  connID,
		ctx:     ctx,
		cancel:  cancel,
		readCh:  make(chan []byte, 4096),
		closeCh: make(chan struct{}),
	}
}

// SendData 向此隧道连接发送数据（写入 readCh 缓冲区）
// 使用完全阻塞写入实现背压：当消费端读取慢时，发送端会阻塞等待，
// 由异步 goroutine 承载等待开销，绝不会丢弃数据。
// 返回 false 表示连接已关闭或上下文取消。
func (tc *TunnelConn) SendData(ctx context.Context, data []byte) bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.closed.Load() {
		return false
	}

	// 首先尝试非阻塞发送（正常路径，缓冲区有空间时零开销）
	select {
	case tc.readCh <- data:
		return true
	default:
	}

	// 缓冲区满——完全阻塞等待空间释放，绝不丢数据
	// 异步 goroutine 会承载此阻塞，不影响 agentReadLoop 处理其他连接
	// 连接关闭时通过 closeCh 解除阻塞
	select {
	case tc.readCh <- data:
		return true
	case <-tc.closeCh:
		return false
	case <-ctx.Done():
		return false
	}
}

// ReadData 从隧道连接读取数据（阻塞直到有数据可用或连接关闭）
func (tc *TunnelConn) ReadData(buf []byte) (int, error) {
	select {
	case data, ok := <-tc.readCh:
		if !ok {
			return 0, fmt.Errorf("connection closed")
		}
		n := copy(buf, data)
		return n, nil
	case <-tc.closeCh:
		return 0, fmt.Errorf("connection closed")
	case <-tc.ctx.Done():
		return 0, tc.ctx.Err()
	}
}

// Close 关闭此隧道连接，释放所有资源
func (tc *TunnelConn) Close() {
	if tc.closed.CompareAndSwap(false, true) {
		tc.cancel()
		close(tc.closeCh)
		// 排空 readCh 中残留的数据
		for {
			select {
			case <-tc.readCh:
			default:
				return
			}
		}
	}
}

// Get 根据连接 ID 获取隧道连接
func (cp *ConnPool) Get(connID uint64) (*TunnelConn, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	tc, ok := cp.conns[connID]
	return tc, ok
}

// Put 向连接池添加一条隧道连接
func (cp *ConnPool) Put(tc *TunnelConn) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.closed {
		tc.Close()
		return
	}
	cp.conns[tc.ConnID] = tc
}

// Remove 从连接池移除并关闭一条隧道连接
func (cp *ConnPool) Remove(connID uint64) {
	cp.mu.Lock()
	tc, ok := cp.conns[connID]
	if ok {
		delete(cp.conns, connID)
	}
	cp.mu.Unlock()

	if ok {
		tc.Close()
	}
}

// Close 关闭连接池中的所有连接
func (cp *ConnPool) Close() {
	cp.mu.Lock()
	cp.closed = true
	conns := cp.conns
	cp.conns = make(map[uint64]*TunnelConn)
	cp.mu.Unlock()

	for _, tc := range conns {
		tc.Close()
	}
}

// Count 返回活动连接数量
func (cp *ConnPool) Count() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.conns)
}
