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
func (cp *ConnPipe) Read(buf []byte) (int, error) {
	// 暂存未读完的数据行先读出
	if len(cp.readBuf) > 0 {
		n := copy(buf, cp.readBuf)
		cp.readBuf = cp.readBuf[n:]
		return n, nil
	}
	for {
		select {
		case data, ok := <-cp.tc.readCh:
			if !ok {
				return 0, io.EOF
			}
			n := copy(buf, data)
			// 剩余数据暂存到 readBuf
			if n < len(data) {
				cp.readBuf = data[n:]
			}
			return n, nil
		case <-cp.tc.closeCh:
			return 0, io.EOF
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
type TunnelWriter struct {
	connID uint64
	codec  *protocol.Codec
	mu     sync.Mutex
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
	tw.mu.Lock()
	defer tw.mu.Unlock()
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
		bufSize = 32 * 1024
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
		buf := make([]byte, bufSize)
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
		buf := make([]byte, bufSize)
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
