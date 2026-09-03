package protocol

import (
	"bytes"
	"crypto/rand"
	"net"
	"sync"
	"testing"

	"EZRP/internal/crypto"
)

// ============================================================
// Codec 基础编解码测试
// ============================================================

func TestCodec_RoundTrip(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	testCases := []*Message{
		{Type: TypeAuth, ConnID: 1, Payload: []byte("auth payload")},
		{Type: TypeHeartbeat, ConnID: 0, Payload: nil},
		{Type: TypeConnect, ConnID: 42, Payload: []byte(`{"target":"192.168.1.1:80"}`)},
		{Type: TypeData, ConnID: 100, Payload: []byte("hello world data")},
		{Type: TypeClose, ConnID: 99, Payload: nil},
		{Type: TypeConnectOK, ConnID: 50, Payload: []byte("")},
	}

	for i, tc := range testCases {
		go func(msg *Message) {
			if err := writer.WriteMessage(msg); err != nil {
				t.Errorf("WriteMessage: %v", err)
			}
		}(tc)

		msg, err := reader.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage %d: %v", i, err)
		}
		defer msg.Release()

		if msg.Type != tc.Type {
			t.Errorf("msg %d: Type expected 0x%02x, got 0x%02x", i, tc.Type, msg.Type)
		}
		if msg.ConnID != tc.ConnID {
			t.Errorf("msg %d: ConnID expected %d, got %d", i, tc.ConnID, msg.ConnID)
		}
		if !bytes.Equal(msg.Payload, tc.Payload) {
			t.Errorf("msg %d: Payload mismatch", i)
		}
	}
}

func TestCodec_EmptyPayload(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	msg := &Message{Type: TypeHeartbeat, ConnID: 0}
	go func() {
		writer.WriteMessage(msg)
	}()

	got, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	defer got.Release()

	if got.Type != TypeHeartbeat {
		t.Errorf("Type: expected 0x%02x, got 0x%02x", TypeHeartbeat, got.Type)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload: expected empty, got %d bytes", len(got.Payload))
	}
}

func TestCodec_LargePayload(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	// 1MB 负载
	payload := make([]byte, 1024*1024)
	rand.Read(payload)

	go func() {
		writer.WriteData(42, payload)
	}()

	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	defer msg.Release()

	if msg.Type != TypeData {
		t.Errorf("Type: expected 0x%02x, got 0x%02x", TypeData, msg.Type)
	}
	if msg.ConnID != 42 {
		t.Errorf("ConnID: expected 42, got %d", msg.ConnID)
	}
	if !bytes.Equal(msg.Payload, payload) {
		t.Errorf("Payload: data mismatch (expected %d bytes, got %d)", len(payload), len(msg.Payload))
	}
}

func TestCodec_MaxPayload(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	// 8MB 负载（小于16MB 限制）
	payload := make([]byte, 8*1024*1024)
	rand.Read(payload)

	go func() {
		writer.WriteData(1, payload)
	}()

	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	defer msg.Release()

	if !bytes.Equal(msg.Payload, payload) {
		t.Errorf("Payload: data mismatch")
	}
}

// ============================================================
// Codec 加密测试
// ============================================================

func TestCodec_EncryptedRoundTrip(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	key := crypto.DeriveKey("test-token-12345")
	writer.EnableEncryption(key, crypto.SideClient)
	reader.EnableEncryption(key, crypto.SideServer)

	testCases := []*Message{
		{Type: TypeData, ConnID: 1, Payload: []byte("encrypted data")},
		{Type: TypeData, ConnID: 2, Payload: []byte("another message")},
		{Type: TypeHeartbeat, ConnID: 0, Payload: nil},              // 空载荷不加密
		{Type: TypeData, ConnID: 3, Payload: make([]byte, 64*1024)}, // 64KB
	}

	// 填充大负载
	rand.Read(testCases[3].Payload)

	for i, tc := range testCases {
		go func(msg *Message) {
			if err := writer.WriteMessage(msg); err != nil {
				t.Errorf("WriteMessage: %v", err)
			}
		}(tc)

		msg, err := reader.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage %d: %v", i, err)
		}
		defer msg.Release()

		if msg.Type != tc.Type {
			t.Errorf("msg %d: Type expected 0x%02x, got 0x%02x", i, tc.Type, msg.Type)
		}
		if msg.ConnID != tc.ConnID {
			t.Errorf("msg %d: ConnID expected %d, got %d", i, tc.ConnID, msg.ConnID)
		}
		if !bytes.Equal(msg.Payload, tc.Payload) {
			t.Errorf("msg %d: Payload mismatch", i)
		}
	}
}

func TestCodec_EncryptedMultipleMessages(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	key := crypto.DeriveKey("test-token")
	writer.EnableEncryption(key, crypto.SideClient)
	reader.EnableEncryption(key, crypto.SideServer)

	// 连续发送100条加密消息，验证序列号同步
	count := 100
	go func() {
		for i := 0; i < count; i++ {
			msg := &Message{
				Type:    TypeData,
				ConnID:  uint64(i),
				Payload: []byte{byte(i), byte(i >> 8)},
			}
			writer.WriteMessage(msg)
		}
	}()

	for i := 0; i < count; i++ {
		msg, err := reader.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage %d: %v", i, err)
		}
		if msg.ConnID != uint64(i) {
			t.Errorf("msg %d: ConnID expected %d, got %d", i, i, msg.ConnID)
		}
		if len(msg.Payload) != 2 || msg.Payload[0] != byte(i) || msg.Payload[1] != byte(i>>8) {
			t.Errorf("msg %d: Payload mismatch", i)
		}
		msg.Release()
	}
}

// ============================================================
// Codec 并发写入测试
// ============================================================

func TestCodec_ConcurrentWrites(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	numWriters := 10
	msgsPerWriter := 50

	// 接收端
	received := make(map[uint64]bool)
	var mu sync.Mutex
	var wgRecv sync.WaitGroup
	wgRecv.Add(1)
	totalExpected := numWriters * msgsPerWriter

	go func() {
		defer wgRecv.Done()
		for i := 0; i < totalExpected; i++ {
			msg, err := reader.ReadMessage()
			if err != nil {
				t.Errorf("ReadMessage: %v", err)
				return
			}
			mu.Lock()
			received[msg.ConnID] = true
			mu.Unlock()
			msg.Release()
		}
	}()

	// 并发写入
	var wgSend sync.WaitGroup
	for w := 0; w < numWriters; w++ {
		wgSend.Add(1)
		go func(writerID int) {
			defer wgSend.Done()
			for m := 0; m < msgsPerWriter; m++ {
				connID := uint64(writerID*1000 + m)
				msg := &Message{
					Type:    TypeData,
					ConnID:  connID,
					Payload: []byte{byte(writerID), byte(m)},
				}
				if err := writer.WriteMessage(msg); err != nil {
					t.Errorf("writer %d msg %d: %v", writerID, m, err)
					return
				}
			}
		}(w)
	}

	wgSend.Wait()
	wgRecv.Wait()

	mu.Lock()
	if len(received) != totalExpected {
		t.Errorf("received %d unique messages, expected %d", len(received), totalExpected)
	}
	mu.Unlock()
}

// ============================================================
// Codec 并发读写测试（全双工）
// ============================================================

func TestCodec_ConcurrentReadWrite(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	codec1 := NewCodec(rw1)
	codec2 := NewCodec(rw2)

	count := 200

	// codec1 → codec2
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			msg := &Message{Type: TypeData, ConnID: uint64(i), Payload: []byte{byte(i)}}
			if err := codec1.WriteMessage(msg); err != nil {
				t.Errorf("write to codec2: %v", err)
				return
			}
		}
	}()

	// codec2 → codec1
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			msg := &Message{Type: TypeData, ConnID: uint64(i + 10000), Payload: []byte{byte(i + 100)}}
			if err := codec2.WriteMessage(msg); err != nil {
				t.Errorf("write to codec1: %v", err)
				return
			}
		}
	}()

	// 从 codec2 读取
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			msg, err := codec2.ReadMessage()
			if err != nil {
				t.Errorf("read from codec2: %v", err)
				return
			}
			if msg.ConnID != uint64(i) {
				t.Errorf("codec2: expected ConnID %d, got %d", i, msg.ConnID)
			}
			msg.Release()
		}
	}()

	// 从 codec1 读取
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			msg, err := codec1.ReadMessage()
			if err != nil {
				t.Errorf("read from codec1: %v", err)
				return
			}
			if msg.ConnID != uint64(i+10000) {
				t.Errorf("codec1: expected ConnID %d, got %d", i+10000, msg.ConnID)
			}
			msg.Release()
		}
	}()

	wg.Wait()
}

// ============================================================
// Message 池测试
// ============================================================

func TestMessagePool_Release(t *testing.T) {
	msg := &Message{Type: TypeData, ConnID: 1, Payload: make([]byte, 1024)}
	msg.Release()

	// Release 后 Payload 应为 nil
	if msg.Payload != nil {
		t.Error("Payload should be nil after Release")
	}

	// 重新获取应该复用
	msg2 := msgPool.Get().(*Message)
	if msg2.Payload != nil {
		t.Error("recycled Message should have nil Payload")
	}
	msg2.Release()
}

// ============================================================
// WriteData 便捷方法测试
// ============================================================

func TestCodec_WriteData(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	data := []byte("test data via WriteData")
	go func() {
		writer.WriteData(99, data)
	}()

	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	defer msg.Release()

	if msg.Type != TypeData {
		t.Errorf("Type: expected 0x%02x, got 0x%02x", TypeData, msg.Type)
	}
	if msg.ConnID != 99 {
		t.Errorf("ConnID: expected 99, got %d", msg.ConnID)
	}
	if !bytes.Equal(msg.Payload, data) {
		t.Errorf("Payload mismatch")
	}
}

// ============================================================
// writeBuf 复用测试
// ============================================================

func TestCodec_WriteBufReuse(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	// 第一次写入小数据
	small := make([]byte, 100)
	rand.Read(small)
	go func() {
		writer.WriteData(1, small)
		writer.WriteData(2, small)
		writer.WriteData(3, small)
	}()

	for i := 0; i < 3; i++ {
		msg, err := reader.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage %d: %v", i, err)
		}
		if !bytes.Equal(msg.Payload, small) {
			t.Errorf("msg %d: payload mismatch", i)
		}
		msg.Release()
	}

	// 验证 writeBuf 被复用（内部切片地址应相同或更大容量）
	if cap(writer.writeBuf) < len(small)+HeaderSize {
		t.Error("writeBuf should have been allocated")
	}
}

// ============================================================
// TypeName 测试
// ============================================================

func TestMessage_TypeName(t *testing.T) {
	tests := []struct {
		msgType uint8
		want    string
	}{
		{TypeAuth, "AUTH"},
		{TypeAuthOK, "AUTH_OK"},
		{TypeAuthFail, "AUTH_FAIL"},
		{TypeHeartbeat, "HEARTBEAT"},
		{TypeConnect, "CONNECT"},
		{TypeConnectOK, "CONNECT_OK"},
		{TypeConnectFail, "CONNECT_FAIL"},
		{TypeData, "DATA"},
		{TypeClose, "CLOSE"},
		{0xFF, "UNKNOWN(0xff)"},
	}

	for _, tt := range tests {
		msg := &Message{Type: tt.msgType}
		if got := msg.TypeName(); got != tt.want {
			t.Errorf("Type 0x%02x: TypeName() = %q, want %q", tt.msgType, got, tt.want)
		}
	}
}

// ============================================================
// 大量消息顺序保证测试
// ============================================================

func TestCodec_SequentialOrder(t *testing.T) {
	rw1, rw2 := net.Pipe()
	defer rw1.Close()
	defer rw2.Close()

	writer := NewCodec(rw1)
	reader := NewCodec(rw2)

	key := crypto.DeriveKey("order-test")
	writer.EnableEncryption(key, crypto.SideClient)
	reader.EnableEncryption(key, crypto.SideServer)

	count := 1000
	go func() {
		for i := 0; i < count; i++ {
			msg := &Message{
				Type:    TypeData,
				ConnID:  uint64(i),
				Payload: []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)},
			}
			writer.WriteMessage(msg)
		}
	}()

	for i := 0; i < count; i++ {
		msg, err := reader.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage %d: %v", i, err)
		}
		expectedPayload := []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		if !bytes.Equal(msg.Payload, expectedPayload) {
			t.Fatalf("msg %d: payload mismatch", i)
		}
		msg.Release()
	}
}
