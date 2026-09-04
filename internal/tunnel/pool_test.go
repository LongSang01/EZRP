package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"EZRP/internal/protocol"
)

// ============================================================
// TunnelConn 基础功能测试
// ============================================================

func TestTunnelConn_BasicSendReceive(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	payload := []byte("hello world")
	if !tc.SendData(context.Background(), payload) {
		t.Fatal("SendData failed")
	}

	buf := make([]byte, 128)
	n, err := tc.ReadData(buf)
	if err != nil {
		t.Fatalf("ReadData: %v", err)
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("expected 'hello world', got %q", string(buf[:n]))
	}
}

func TestTunnelConn_MultipleMessages(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	count := 100
	go func() {
		for i := 0; i < count; i++ {
			data := []byte(fmt.Sprintf("msg-%d", i))
			tc.SendData(context.Background(), data)
		}
	}()

	for i := 0; i < count; i++ {
		buf := make([]byte, 128)
		n, err := tc.ReadData(buf)
		if err != nil {
			t.Fatalf("ReadData %d: %v", i, err)
		}
		expected := fmt.Sprintf("msg-%d", i)
		if string(buf[:n]) != expected {
			t.Fatalf("msg %d: expected %q, got %q", i, expected, string(buf[:n]))
		}
	}
}

func TestTunnelConn_SendAfterClose(t *testing.T) {
	tc := NewTunnelConn(1)
	tc.Close()

	if tc.SendData(context.Background(), []byte("data")) {
		t.Fatal("SendData should return false after Close")
	}
}

func TestTunnelConn_ReadAfterClose(t *testing.T) {
	tc := NewTunnelConn(1)
	tc.Close()

	buf := make([]byte, 128)
	_, err := tc.ReadData(buf)
	if err == nil {
		t.Fatal("ReadData should return error after Close")
	}
}

func TestTunnelConn_DoubleClose(t *testing.T) {
	tc := NewTunnelConn(1)
	tc.Close()
	tc.Close() // 不应 panic
}

func TestTunnelConn_ContextCancel(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	// 先填满 channel，让 SendData 进入阻塞的 select 路径
	for i := 0; i < 4096; i++ {
		if !tc.SendData(context.Background(), []byte("fill")) {
			t.Fatal("fill send failed")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	// 缓冲区已满 + context 已取消 → 应立即返回 false
	if tc.SendData(ctx, []byte("data")) {
		t.Fatal("SendData should return false on cancelled context with full channel")
	}
}

// ============================================================
// 并发发送测试（小流量高并发核心场景）
// ============================================================

func TestTunnelConn_ConcurrentSenders(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	numSenders := 100
	msgsPerSender := 200
	totalMsgs := numSenders * msgsPerSender

	// 接收端：逐条读取并校验
	received := make(map[string]int)
	var mu sync.Mutex
	var wgRecv sync.WaitGroup
	wgRecv.Add(1)
	go func() {
		defer wgRecv.Done()
		for i := 0; i < totalMsgs; i++ {
			buf := make([]byte, 128)
			n, err := tc.ReadData(buf)
			if err != nil {
				t.Errorf("ReadData: %v", err)
				return
			}
			mu.Lock()
			received[string(buf[:n])]++
			mu.Unlock()
		}
	}()

	// 发送端：并发发送
	var wgSend sync.WaitGroup
	for s := 0; s < numSenders; s++ {
		wgSend.Add(1)
		go func(sender int) {
			defer wgSend.Done()
			for m := 0; m < msgsPerSender; m++ {
				data := fmt.Sprintf("sender%d-msg%d", sender, m)
				if !tc.SendData(context.Background(), []byte(data)) {
					t.Errorf("sender %d msg %d: SendData failed", sender, m)
					return
				}
			}
		}(s)
	}

	wgSend.Wait()
	wgRecv.Wait()

	// 验证所有消息都收到了，且没有丢失
	mu.Lock()
	total := 0
	for s := 0; s < numSenders; s++ {
		for m := 0; m < msgsPerSender; m++ {
			key := fmt.Sprintf("sender%d-msg%d", s, m)
			if received[key] != 1 {
				t.Errorf("message %q: expected count 1, got %d", key, received[key])
			}
			total += received[key]
		}
	}
	mu.Unlock()

	if total != totalMsgs {
		t.Fatalf("total messages: expected %d, got %d", totalMsgs, total)
	}
}

// ============================================================
// 背压测试（关键：数据绝不丢失）
// ============================================================

func TestTunnelConn_Backpressure_NoDataLoss(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	// 不读取任何数据，模拟消费端完全停止
	// readCh 容量 4096，发送 5000 条消息
	// 前4096 条应该立即成功（非阻塞），剩余的应该阻塞等待
	sent := int64(0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	numMsgs := 5000
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numMsgs; i++ {
			data := []byte(fmt.Sprintf("msg-%06d", i))
			if !tc.SendData(ctx, data) {
				return
			}
			atomic.AddInt64(&sent, 1)
		}
	}()

	// 等待一会儿让 goroutine 阻塞
	time.Sleep(200 * time.Millisecond)
	sentSoFar := atomic.LoadInt64(&sent)
	t.Logf("Sent %d/%d before blocking (channel cap 4096)", sentSoFar, numMsgs)

	// 现在开始消费，验证数据完整性
	received := 0
	for received < numMsgs {
		buf := make([]byte, 64)
		n, err := tc.ReadData(buf)
		if err != nil {
			t.Fatalf("ReadData at %d: %v", received, err)
		}
		expected := fmt.Sprintf("msg-%06d", received)
		if string(buf[:n]) != expected {
			t.Fatalf("msg %d: expected %q, got %q", received, expected, string(buf[:n]))
		}
		received++
	}

	wg.Wait()

	if int(atomic.LoadInt64(&sent)) != numMsgs {
		t.Fatalf("expected all %d messages sent, got %d", numMsgs, atomic.LoadInt64(&sent))
	}
	t.Logf("All %d messages received in order with backpressure", numMsgs)
}

func TestTunnelConn_Backpressure_SlowConsumer(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	numMsgs := 10000
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 生产者：快速发送
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numMsgs; i++ {
			data := []byte(fmt.Sprintf("%08d", i))
			if !tc.SendData(ctx, data) {
				t.Errorf("SendData failed at %d", i)
				return
			}
		}
	}()

	// 消费者：故意慢读（每100条暂停一次）
	received := 0
	for received < numMsgs {
		if received%100 == 0 && received > 0 {
			time.Sleep(10 * time.Millisecond) // 模拟慢消费
		}
		buf := make([]byte, 64)
		n, err := tc.ReadData(buf)
		if err != nil {
			t.Fatalf("ReadData at %d: %v", received, err)
		}
		expected := fmt.Sprintf("%08d", received)
		if string(buf[:n]) != expected {
			t.Fatalf("msg %d: expected %q, got %q", received, expected, string(buf[:n]))
		}
		received++
	}

	wg.Wait()
	t.Logf("Slow consumer: all %d messages received correctly", numMsgs)
}

func TestTunnelConn_CloseWhileBlocked(t *testing.T) {
	tc := NewTunnelConn(1)

	// 填满 channel
	for i := 0; i < 4096; i++ {
		if !tc.SendData(context.Background(), []byte("fill")) {
			t.Fatal("fill send failed")
		}
	}

	// 启动阻塞的发送者
	blocked := make(chan struct{})
	go func() {
		close(blocked)
		tc.SendData(context.Background(), []byte("should-unblock"))
	}()

	<-blocked
	time.Sleep(50 * time.Millisecond) // 确保 goroutine 已阻塞

	// 关闭连接，应该解除阻塞
	tc.Close()

	// 等一下确保 goroutine 退出
	time.Sleep(100 * time.Millisecond)
}

// ============================================================
// ConnPool 测试
// ============================================================

func TestConnPool_BasicOperations(t *testing.T) {
	pool := NewConnPool()

	tc := NewTunnelConn(42)
	pool.Put(tc)

	got, ok := pool.Get(42)
	if !ok || got != tc {
		t.Fatal("Get failed")
	}

	if pool.Count() != 1 {
		t.Fatalf("Count: expected 1, got %d", pool.Count())
	}

	pool.Remove(42)
	_, ok = pool.Get(42)
	if ok {
		t.Fatal("Get should fail after Remove")
	}
}

func TestConnPool_ConcurrentAccess(t *testing.T) {
	pool := NewConnPool()
	numConns := 100

	var wg sync.WaitGroup

	// 并发 Put
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			tc := NewTunnelConn(id)
			pool.Put(tc)
		}(uint64(i))
	}
	wg.Wait()

	if pool.Count() != numConns {
		t.Fatalf("Count: expected %d, got %d", numConns, pool.Count())
	}

	// 并发 Get
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			tc, ok := pool.Get(id)
			if !ok {
				t.Errorf("Get(%d) failed", id)
				return
			}
			_ = tc
		}(uint64(i))
	}
	wg.Wait()

	// 并发 Remove
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			pool.Remove(id)
		}(uint64(i))
	}
	wg.Wait()

	if pool.Count() != 0 {
		t.Fatalf("Count: expected 0, got %d", pool.Count())
	}
}

func TestConnPool_PutAfterClose(t *testing.T) {
	pool := NewConnPool()
	pool.Close()

	tc := NewTunnelConn(1)
	pool.Put(tc) // 应该自动关闭 tc

	if !tc.closed.Load() {
		t.Fatal("tc should be closed after Put to closed pool")
	}
}

func TestConnPool_Close(t *testing.T) {
	pool := NewConnPool()
	conns := make([]*TunnelConn, 50)

	for i := range conns {
		conns[i] = NewTunnelConn(uint64(i))
		pool.Put(conns[i])
	}

	pool.Close()

	for _, tc := range conns {
		if !tc.closed.Load() {
			t.Fatalf("conn %d should be closed after pool.Close()", tc.ConnID)
		}
	}
}

// ============================================================
// 大数据量测试（模拟大文件下载）
// ============================================================

func TestTunnelConn_LargePayloads(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	// 发送多个64KB负载（模拟文件数据块）
	chunkSize := 64 * 1024
	numChunks := 1000 // 64MB 总量
	totalSize := chunkSize * numChunks

	go func() {
		for i := 0; i < numChunks; i++ {
			chunk := make([]byte, chunkSize)
			// 填充可验证的数据模式
			for j := range chunk {
				chunk[j] = byte((i + j) % 256)
			}
			tc.SendData(context.Background(), chunk)
		}
	}()

	// 接收并验证
	received := 0
	buf := make([]byte, chunkSize+1024) // 稍大一些以容纳部分读取
	totalBytes := 0

	for totalBytes < totalSize {
		n, err := tc.ReadData(buf)
		if err != nil {
			t.Fatalf("ReadData at byte %d: %v", totalBytes, err)
		}

		// 验证数据模式
		chunkIdx := totalBytes / chunkSize
		offset := totalBytes % chunkSize
		for i := 0; i < n; i++ {
			expectedByte := byte((chunkIdx + offset + i) % 256)
			if buf[i] != expectedByte {
				t.Fatalf("byte mismatch at total offset %d: expected %d, got %d",
					totalBytes+i, expectedByte, buf[i])
			}
		}
		totalBytes += n
		received++
	}

	t.Logf("Large payloads: received %d total bytes in %d reads", totalBytes, received)
}

// ============================================================
// ReadData 边界行为测试
// ============================================================

func TestTunnelConn_ReadData_ReturnsAvailableBytes(t *testing.T) {
	tc := NewTunnelConn(1)
	defer tc.Close()

	// 发送一个1024字节的负载
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	tc.SendData(context.Background(), payload)

	// ReadData 是底层接口，copy 返回 min(buf, data) 字节
	// 注意：ReadData 不做部分缓冲，剩余数据丢失（由 ConnPipe.Read 负责缓冲）
	bigBuf := make([]byte, 2048)
	n, err := tc.ReadData(bigBuf)
	if err != nil {
		t.Fatalf("ReadData: %v", err)
	}
	if n != 1024 {
		t.Fatalf("expected 1024 bytes, got %d", n)
	}
	for i := 0; i < n; i++ {
		expected := byte(i % 256)
		if bigBuf[i] != expected {
			t.Fatalf("byte %d: expected %d, got %d", i, expected, bigBuf[i])
		}
	}
}

func TestTunnelConn_ReadData_CloseUnblocksReader(t *testing.T) {
	tc := NewTunnelConn(1)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		_, err := tc.ReadData(buf)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond) // 确保 goroutine 已阻塞
	tc.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadData did not unblock after Close")
	}
}

// ============================================================
// 关键回归测试：Close() 不丢弃 readCh 中未读数据
// 这是图片加载截断 bug 的直接回归测试
// ============================================================

// TestTunnelConn_DataPreservedAfterClose 验证 Close() 不会丢弃 readCh 中的数据。
// 场景：异步 goroutine 发送数据到 readCh，然后 Close() 被调用。
// 消费端应能读取到所有数据后才看到 EOF。
func TestTunnelConn_DataPreservedAfterClose(t *testing.T) {
	tc := NewTunnelConn(1)
	msgCount := 100

	// 模拟服务端异步分发：多个 goroutine 发送数据
	var wg sync.WaitGroup
	for i := 0; i < msgCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf("data-%04d", idx))
			tc.SendData(context.Background(), data)
		}(i)
	}

	// 等待所有发送 goroutine 完成（模拟 pendingWrites）
	wg.Wait()

	// Close 不再排空 readCh
	tc.Close()

	// 消费端应能读取所有数据
	received := 0
	buf := make([]byte, 128)
	for {
		n, err := tc.ReadData(buf)
		if err != nil {
			break // EOF 或 connection closed
		}
		received++
		_ = string(buf[:n])
	}

	if received != msgCount {
		t.Fatalf("expected %d messages after Close, got %d (DATA LOSS!)", msgCount, received)
	}
}

// TestConnPipe_DataDrainedAfterClose 验证 ConnPipe.Read 在 closeCh 关闭后
// 仍能排空 readCh 中的剩余数据。模拟真实场景：服务端收到 TypeClose 时
// readCh 中还有未读数据。
func TestConnPipe_DataDrainedAfterClose(t *testing.T) {
	tc := NewTunnelConn(1)
	// 创建真实 codec（测试只使用 Read 路径，Write 路径不影响）
	codec := protocol.NewCodec(&bytes.Buffer{})
	cp := NewConnPipe(tc, codec)

	msgCount := 200

	// 先把数据全部放入 readCh
	for i := 0; i < msgCount; i++ {
		data := []byte(fmt.Sprintf("chunk-%04d", i))
		tc.SendData(context.Background(), data)
	}

	// 关闭连接（模拟 TypeClose 到达）
	tc.Close()

	// ConnPipe 应能读取所有数据
	received := 0
	buf := make([]byte, 128)
	for {
		n, err := cp.Read(buf)
		if err != nil {
			break
		}
		received++
		_ = string(buf[:n])
	}

	if received != msgCount {
		t.Fatalf("expected %d messages, got %d (DATA LOSS!)", msgCount, received)
	}
}

// TestConnPipe_DataDeliveredWithAsyncClose 模拟最接近真实 bug 的场景：
// 异步 goroutine 发送数据的同时 Close() 被调用，验证数据不丢失。
func TestConnPipe_DataDeliveredWithAsyncClose(t *testing.T) {
	tc := NewTunnelConn(1)
	codec := protocol.NewCodec(&bytes.Buffer{})
	cp := NewConnPipe(tc, codec)

	msgCount := 500
	sent := make(chan struct{})

	// 模拟异步 TypeData goroutine
	go func() {
		for i := 0; i < msgCount; i++ {
			data := []byte(fmt.Sprintf("async-%04d", i))
			tc.SendData(context.Background(), data)
		}
		close(sent)
	}()

	// 等待所有数据发送完成（模拟 pendingWrites.Wait()）
	<-sent

	// 模拟 TypeClose 到达
	tc.Close()

	// 读取所有数据
	received := 0
	buf := make([]byte, 128)
	for {
		n, err := cp.Read(buf)
		if err != nil {
			break
		}
		received++
		_ = string(buf[:n])
	}

	if received != msgCount {
		t.Fatalf("expected %d messages, got %d (DATA LOSS with async close!)", msgCount, received)
	}
}
