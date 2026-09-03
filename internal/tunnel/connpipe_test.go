package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"EZRP/internal/protocol"
)

// ============================================================
// ConnPipe 基础读写测试
// ============================================================

func TestConnPipe_BasicReadWrite(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	rw1, _ := net.Pipe()
	defer rw1.Close()
	codec := protocol.NewCodec(rw1)
	cp := NewConnPipe(tc, codec)

	testData := []byte("hello connpipe")
	tc.SendData(context.Background(), testData)

	buf := make([]byte, 128)
	n, err := cp.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello connpipe" {
		t.Fatalf("expected 'hello connpipe', got %q", string(buf[:n]))
	}
}

func TestConnPipe_LargeReadWithBuffering(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	rw1, _ := net.Pipe()
	defer rw1.Close()
	codec := protocol.NewCodec(rw1)
	cp := NewConnPipe(tc, codec)

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	tc.SendData(context.Background(), payload)

	// 用256字节的小缓冲区读取，测试 readBuf 缓冲机制
	smallBuf := make([]byte, 256)
	totalRead := 0
	for totalRead < len(payload) {
		n, err := cp.Read(smallBuf)
		if err != nil {
			t.Fatalf("Read at %d: %v", totalRead, err)
		}
		for i := 0; i < n; i++ {
			expected := byte((totalRead + i) % 256)
			if smallBuf[i] != expected {
				t.Fatalf("byte %d: expected %d, got %d", totalRead+i, expected, smallBuf[i])
			}
		}
		totalRead += n
	}

	if totalRead != len(payload) {
		t.Fatalf("total read: expected %d, got %d", len(payload), totalRead)
	}
}

func TestConnPipe_ReadEOF(t *testing.T) {
	tc := NewTunnelConn(1)
	rw1, _ := net.Pipe()
	defer rw1.Close()
	codec := protocol.NewCodec(rw1)
	cp := NewConnPipe(tc, codec)

	tc.Close()

	buf := make([]byte, 128)
	_, err := cp.Read(buf)
	// 关闭后可能返回 EOF 或 context.Canceled，取决于 select 选择顺序
	if err != io.EOF && err != context.Canceled {
		t.Fatalf("expected EOF or context.Canceled, got %v", err)
	}
}

func TestConnPipe_ReadMultipleChunks(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	rw1, _ := net.Pipe()
	defer rw1.Close()
	codec := protocol.NewCodec(rw1)
	cp := NewConnPipe(tc, codec)

	chunks := [][]byte{
		bytes.Repeat([]byte("A"), 100),
		bytes.Repeat([]byte("B"), 500),
		bytes.Repeat([]byte("C"), 1000),
	}

	go func() {
		for _, c := range chunks {
			tc.SendData(context.Background(), c)
		}
	}()

	for i, expected := range chunks {
		buf := make([]byte, 2048)
		totalRead := 0
		for totalRead < len(expected) {
			n, err := cp.Read(buf[totalRead:])
			if err != nil {
				t.Fatalf("chunk %d read: %v", i, err)
			}
			totalRead += n
		}
		if !bytes.Equal(buf[:totalRead], expected) {
			t.Fatalf("chunk %d: data mismatch", i)
		}
	}
}

// ============================================================
// ConnPipe 地址和 Deadline 方法
// ============================================================

func TestConnPipe_AddrMethods(t *testing.T) {
	tc := NewTunnelConn(42)
	defer tc.Close()

	rw1, _ := net.Pipe()
	defer rw1.Close()
	codec := protocol.NewCodec(rw1)
	cp := NewConnPipe(tc, codec)

	if cp.LocalAddr() == nil {
		t.Fatal("LocalAddr should not be nil")
	}
	if cp.RemoteAddr() == nil {
		t.Fatal("RemoteAddr should not be nil")
	}
}

func TestConnPipe_DeadlineMethods(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	rw1, _ := net.Pipe()
	defer rw1.Close()
	codec := protocol.NewCodec(rw1)
	cp := NewConnPipe(tc, codec)

	if err := cp.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := cp.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := cp.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
}

// ============================================================
// CopyData 本地→隧道 方向测试
// ============================================================

func TestCopyData_LocalToTunnel(t *testing.T) {
	localR, localW := net.Pipe()
	defer localR.Close()
	defer localW.Close()

	tc := NewTunnelConn(1)
	defer tc.Close()

	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()
	codec := protocol.NewCodec(rw1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 从 rw2 读取 CopyData 通过 codec 写出的数据
	received := make(chan []byte, 100)
	go func() {
		peerCodec := protocol.NewCodec(rw2)
		for {
			msg, err := peerCodec.ReadMessage()
			if err != nil {
				close(received)
				return
			}
			if msg.Type == protocol.TypeData {
				payload := make([]byte, len(msg.Payload))
				copy(payload, msg.Payload)
				received <- payload
			}
			msg.Release()
		}
	}()

	go CopyData(ctx, localR, tc, codec, 0)

	testChunks := [][]byte{
		bytes.Repeat([]byte("A"), 1024),
		bytes.Repeat([]byte("B"), 4096),
		bytes.Repeat([]byte("C"), 32*1024),
	}
	expectedTotal := 1024 + 4096 + 32*1024

	go func() {
		for _, chunk := range testChunks {
			localW.Write(chunk)
		}
	}()

	// 收集通过隧道写出的数据
	var receivedData []byte
	timeout := time.After(10 * time.Second)
	for len(receivedData) < expectedTotal {
		select {
		case data, ok := <-received:
			if !ok {
				t.Fatalf("channel closed at %d/%d bytes", len(receivedData), expectedTotal)
			}
			receivedData = append(receivedData, data...)
		case <-timeout:
			t.Fatalf("timeout: received %d/%d bytes", len(receivedData), expectedTotal)
		}
	}

	expectedData := []byte{}
	for _, chunk := range testChunks {
		expectedData = append(expectedData, chunk...)
	}
	if !bytes.Equal(receivedData, expectedData) {
		t.Fatalf("data mismatch: received %d bytes, expected %d", len(receivedData), len(expectedData))
	}

	cancel()
}

// ============================================================
// CopyData 大文件传输数据完整性测试
// ============================================================

func TestCopyData_LargeTransferIntegrity(t *testing.T) {
	totalSize := 16 * 1024 * 1024 // 16MB

	localR, localW := net.Pipe()
	defer localR.Close()
	defer localW.Close()

	tc := NewTunnelConn(1)
	defer tc.Close()

	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()
	codec := protocol.NewCodec(rw1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 从 rw2 读取 CopyData 写出的数据并计算校验和
	var receivedBytes int64
	var receivedChecksum byte
	var checksumMu sync.Mutex

	go func() {
		peerCodec := protocol.NewCodec(rw2)
		for {
			msg, err := peerCodec.ReadMessage()
			if err != nil {
				return
			}
			if msg.Type == protocol.TypeData {
				atomic.AddInt64(&receivedBytes, int64(len(msg.Payload)))
				checksumMu.Lock()
				for _, b := range msg.Payload {
					receivedChecksum ^= b
				}
				checksumMu.Unlock()
			}
			msg.Release()
		}
	}()

	go CopyData(ctx, localR, tc, codec, 0)

	// 生成随机测试数据
	testData := make([]byte, totalSize)
	rand.Read(testData)
	var expectedChecksum byte
	for _, b := range testData {
		expectedChecksum ^= b
	}

	go func() {
		chunkSize := 64 * 1024
		for offset := 0; offset < totalSize; offset += chunkSize {
			end := offset + chunkSize
			if end > totalSize {
				end = totalSize
			}
			_, err := localW.Write(testData[offset:end])
			if err != nil {
				return
			}
		}
	}()

	deadline := time.After(30 * time.Second)
	for atomic.LoadInt64(&receivedBytes) < int64(totalSize) {
		select {
		case <-deadline:
			t.Fatalf("timeout: received %d/%d bytes", atomic.LoadInt64(&receivedBytes), totalSize)
		case <-time.After(50 * time.Millisecond):
		}
	}

	checksumMu.Lock()
	actualChecksum := receivedChecksum
	checksumMu.Unlock()

	if expectedChecksum != actualChecksum {
		t.Fatalf("checksum mismatch: expected 0x%02x, got 0x%02x", expectedChecksum, actualChecksum)
	}

	t.Logf("Large transfer: %d bytes, checksum OK (0x%02x)", totalSize, actualChecksum)
	cancel()
}

// ============================================================
// CopyData 多连接并发测试（小流量高并发）
// ============================================================

func TestCopyData_ConcurrentConnections(t *testing.T) {
	numConns := 50
	msgsPerConn := 100
	msgSize := 1024

	var wg sync.WaitGroup
	var errCount atomic.Int32

	for c := 0; c < numConns; c++ {
		wg.Add(1)
		go func(connIdx int) {
			defer wg.Done()

			localR, localW := net.Pipe()
			defer localR.Close()
			defer localW.Close()

			tc := NewTunnelConn(uint64(connIdx))
			defer tc.Close()

			rw1, rw2 := net.Pipe()
			defer rw1.Close()
			defer rw2.Close()
			codec := protocol.NewCodec(rw1)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			received := make(chan []byte, 1000)
			go func() {
				peerCodec := protocol.NewCodec(rw2)
				for {
					msg, err := peerCodec.ReadMessage()
					if err != nil {
						close(received)
						return
					}
					if msg.Type == protocol.TypeData {
						payload := make([]byte, len(msg.Payload))
						copy(payload, msg.Payload)
						received <- payload
					}
					msg.Release()
				}
			}()

			go CopyData(ctx, localR, tc, codec, 0)

			for m := 0; m < msgsPerConn; m++ {
				data := make([]byte, msgSize)
				for i := range data {
					data[i] = byte((connIdx + m + i) % 256)
				}
				_, err := localW.Write(data)
				if err != nil {
					t.Errorf("conn %d msg %d write: %v", connIdx, m, err)
					errCount.Add(1)
					return
				}
			}

			totalReceived := 0
			expectedTotal := msgsPerConn * msgSize
			timeout := time.After(10 * time.Second)
			for totalReceived < expectedTotal {
				select {
				case data, ok := <-received:
					if !ok {
						t.Errorf("conn %d: channel closed at %d bytes", connIdx, totalReceived)
						errCount.Add(1)
						return
					}
					totalReceived += len(data)
				case <-timeout:
					t.Errorf("conn %d: timeout at %d/%d bytes", connIdx, totalReceived, expectedTotal)
					errCount.Add(1)
					return
				}
			}
		}(c)
	}

	wg.Wait()

	if errCount.Load() > 0 {
		t.Fatalf("%d errors during concurrent connections test", errCount.Load())
	}
	t.Logf("Concurrent connections: %d × %d msgs × %d bytes = all OK", numConns, msgsPerConn, msgSize)
}

// ============================================================
// CopyData 连接关闭后正确退出
// ============================================================

func TestCopyData_ContextCancel(t *testing.T) {
	localR, localW := net.Pipe()
	defer localW.Close()

	tc := NewTunnelConn(1)
	defer tc.Close()

	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()
	codec := protocol.NewCodec(rw1)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyData(ctx, localR, tc, codec, 0)
	}()

	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("expected nil or context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CopyData did not exit after context cancel")
	}
}

// ============================================================
// ConnPipe 顺序写入 + readBuf 正确性压力测试
// ============================================================

func TestConnPipe_SequentialIntegrity(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	rw1, _ := net.Pipe()
	defer rw1.Close()
	codec := protocol.NewCodec(rw1)
	cp := NewConnPipe(tc, codec)

	// 发送100个不同的块，每块带序号
	numChunks := 100
	chunkSize := 512

	go func() {
		for i := 0; i < numChunks; i++ {
			chunk := make([]byte, chunkSize)
			for j := range chunk {
				chunk[j] = byte((i*7 + j) % 256)
			}
			tc.SendData(context.Background(), chunk)
		}
	}()

	// 用随机大小的小缓冲区读取，验证数据顺序
	rng := byte(42)
	var allData []byte

	for len(allData) < numChunks*chunkSize {
		// 每次用不同大小的缓冲区
		readSize := 50 + int(rng)%50
		rng += 7
		buf := make([]byte, readSize)
		n, err := cp.Read(buf)
		if err != nil {
			t.Fatalf("Read at %d: %v", len(allData), err)
		}
		allData = append(allData, buf[:n]...)
	}

	// 验证全部数据的顺序正确
	for i := 0; i < numChunks; i++ {
		for j := 0; j < chunkSize; j++ {
			offset := i*chunkSize + j
			expected := byte((i*7 + j) % 256)
			if allData[offset] != expected {
				t.Fatalf("byte mismatch at chunk %d offset %d (total %d): expected %d, got %d",
					i, j, offset, expected, allData[offset])
			}
		}
	}

	t.Logf("Sequential integrity: %d bytes in %d chunks verified", numChunks*chunkSize, numChunks)
}
