package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// GenerateHash 计算 SHA-256(token + timestamp) 的十六进制哈希值
func GenerateHash(token string, timestamp int64) string {
	data := token + strconv.FormatInt(timestamp, 10)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// ValidateHash 验证认证哈希值是否合法
// 检查逻辑: 1) 时间戳偏差是否在容差范围内; 2) 哈希值是否匹配
// 参数: token-认证令牌, hash-客户端提交的哈希值, timestamp-Unix时间戳, toleratedDrift-允许的最大时间偏差
func ValidateHash(token, hash string, timestamp int64, toleratedDrift time.Duration) error {
	// 检查时间偏差
	drift := time.Since(time.Unix(timestamp, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > toleratedDrift {
		return fmt.Errorf("timestamp drift too large: %v (tolerated: %v)", drift, toleratedDrift)
	}

	expected := GenerateHash(token, timestamp)
	if expected != hash {
		return fmt.Errorf("authentication hash mismatch")
	}

	return nil
}
