package tunnel

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"EZRP/internal/protocol"
)

// ConnPipe 将 TunnelConn 包装为 net.Conn 接口，供服务端 SOCKS5 使用
// 用于表示流经反向隧道的连接
type ConnPipe struct {
	tc    *TunnelConn
	codec *protocol.Codec
	mu    sync.Mutex

	// readBuf 暂存读取缓冲区剩余数据（来自 readCh 的部分读取）
	readBuf []byte
}

// NewConnPipe 创建 ConnPipe，包装 TunnelConn 和 Codec
func NewConnPipe(tc *TunnelConn, codec *protocol.Codec) *ConnPipe {
	return &ConnPipe{
		tc:    tc,
		codec: codec,
	}
}

// Read 从隧道读取数据（来自远端发送方/Agent）
// 当 closeCh 关闭后（连接已关闭），优先排空 readCh 中的剩余数据再返回 EOF
func (cp *ConnPipe) Read(buf []byte) (int, error) {
	// 暂存未读完的数据行先读出
	if len(cp.readBuf) > 0 {
		n := copy(buf, cp.readBuf)
		cp.readBuf = cp.readBuf[n:]
		return n, nil
	}

	// storeRemainder 将 data 中超出 buf 的部分暂存到 readBuf
	storeRemainder := func(data []byte, n int) {
		if n < len(data) {
			if cap(cp.readBuf) >= len(data)-n {
				cp.readBuf = cp.readBuf[:len(data)-n]
			} else {
				cp.readBuf = make([]byte, len(data)-n)
			}
			copy(cp.readBuf, data[n:])
		}
	}

	for {
		// 优先尝试非阻塞读取，确保不会因 closeCh 随机选中而丢失数据
		select {
		case data, ok := <-cp.tc.readCh:
			if !ok {
				return 0, io.EOF
			}
			n := copy(buf, data)
			storeRemainder(data, n)
			return n, nil
		default:
		}

		// 无数据可读，等待新数据、关闭信号或取消
		select {
		case data, ok := <-cp.tc.readCh:
			if !ok {
				return 0, io.EOF
			}
			n := copy(buf, data)
			storeRemainder(data, n)
			return n, nil
		case <-cp.tc.closeCh:
			// 连接已关闭，但 readCh 中可能还有未读完的数据（来自异步 SendData goroutine），
			// 继续排空 readCh 直到为空才返回 EOF
			select {
			case data, ok := <-cp.tc.readCh:
				if !ok {
					return 0, io.EOF
				}
				n := copy(buf, data)
				storeRemainder(data, n)
				return n, nil
			default:
				return 0, io.EOF
			}
		case <-cp.tc.ctx.Done():
			return 0, cp.tc.ctx.Err()
		}
	}
}

// Write 将数据写入隧道（转发至远端 Agent）
func (cp *ConnPipe) Write(data []byte) (int, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if err := cp.codec.WriteData(cp.tc.ConnID, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// Close 关闭隧道连接并发送 CLOSE 报文
func (cp *ConnPipe) Close() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	cp.tc.Close()

	// 向对端发送 CLOSE 报文
	_ = cp.codec.WriteMessage(&protocol.Message{
		Type:   protocol.TypeClose,
		ConnID: cp.tc.ConnID,
	})
	return nil
}

// LocalAddr 返回占位本地地址（隧道无实际本地地址）
func (cp *ConnPipe) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// RemoteAddr 返回占位远端地址（使用 connID 映射端口号）
func (cp *ConnPipe) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: int(cp.tc.ConnID % 65535)}
}

// SetDeadline 空操作（超时由读循环内部处理）
func (cp *ConnPipe) SetDeadline(_ time.Time) error {
	return nil
}

// SetReadDeadline 空操作
func (cp *ConnPipe) SetReadDeadline(_ time.Time) error {
	return nil
}

// SetWriteDeadline 空操作
func (cp *ConnPipe) SetWriteDeadline(_ time.Time) error {
	return nil
}

// TunnelWriter 实现 io.Writer，通过 DATA 报文向隧道写入数据
// 注意：不需要额外的 mu 锁，因为 Codec.writeFrame 内部已有 encMu 保护写操作
type TunnelWriter struct {
	connID uint64
	codec  *protocol.Codec
}

// NewTunnelWriter 创建 TunnelWriter
func NewTunnelWriter(connID uint64, codec *protocol.Codec) *TunnelWriter {
	return &TunnelWriter{
		connID: connID,
		codec:  codec,
	}
}

// Write 实现 io.Writer 接口
func (tw *TunnelWriter) Write(p []byte) (int, error) {
	if err := tw.codec.WriteData(tw.connID, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// TunnelReader 实现 io.Reader，从 TunnelConn 读取数据
type TunnelReader struct {
	tc *TunnelConn
}

// NewTunnelReader 创建 TunnelReader
func NewTunnelReader(tc *TunnelConn) *TunnelReader {
	return &TunnelReader{tc: tc}
}

// Read 实现 io.Reader 接口
func (tr *TunnelReader) Read(p []byte) (int, error) {
	return tr.tc.ReadData(p)
}

// CopyData 实现本地连接与隧道之间的全双工数据转发
// local: 本地目标连接，tc: 隧道连接，codec: 协议编解码器，bufSize: 缓冲区大小
func CopyData(ctx context.Context, local net.Conn, tc *TunnelConn, codec *protocol.Codec, bufSize int) error {
	if bufSize <= 0 {
		bufSize = 64 * 1024 // 默认 64KB（相比原 32KB 翻倍，参考 frp 大缓冲策略）
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	var srcErr, dstErr error

	// local → tunnel（本地读取 → 隧道写入）
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := copyBufPoolGet(bufSize)
		defer copyBufPoolPut(buf)
		tw := NewTunnelWriter(tc.ConnID, codec)
		for {
			select {
			case <-ctx.Done():
				srcErr = ctx.Err()
				return
			default:
			}

			local.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := local.Read(buf)
			if n > 0 {
				if _, wErr := tw.Write(buf[:n]); wErr != nil {
					srcErr = wErr
					return
				}
			}
			if err != nil {
				srcErr = err
				return
			}
		}
	}()

	// tunnel → local（隧道读取 → 本地写入）
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := copyBufPoolGet(bufSize)
		defer copyBufPoolPut(buf)
		tr := NewTunnelReader(tc)
		for {
			select {
			case <-ctx.Done():
				dstErr = ctx.Err()
				return
			default:
			}

			n, err := tr.Read(buf)
			if n > 0 {
				local.SetWriteDeadline(time.Now().Add(60 * time.Second))
				if _, wErr := local.Write(buf[:n]); wErr != nil {
					dstErr = wErr
					return
				}
			}
			if err != nil {
				dstErr = err
				return
			}
		}
	}()

	wg.Wait()

	// 返回更有意义的错误
	if srcErr != nil && srcErr != context.Canceled {
		return srcErr
	}
	if dstErr != nil && dstErr != context.Canceled {
		return dstErr
	}
	return nil
}

// copyBufPool 池化 CopyData 使用的读写缓冲区（64KB），减少 GC 压力
// 使用 *[]byte 避免 interface{} 装箱开销
var copyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 64*1024)
		return &b
	},
}

func copyBufPoolGet(size int) []byte {
	p := copyBufPool.Get().(*[]byte)
	buf := *p
	if cap(buf) >= size {
		return buf[:size]
	}
	// 池中缓冲区太小，分配新的（不放回池中，由调用方自行处理）
	return make([]byte, size)
}

func copyBufPoolPut(buf []byte) {
	if cap(buf) >= 64*1024 {
		copyBufPool.Put(&buf)
	}
}
