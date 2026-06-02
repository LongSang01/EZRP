package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize 加密密钥长度（32 字节，通过 SHA-256 派生）
	KeySize = 32

	// TagSize Poly1305 认证标签长度（16 字节）
	TagSize = chacha20poly1305.Overhead

	// NonceSize ChaCha20-Poly1305 nonce 长度（12 字节）
	NonceSize = chacha20poly1305.NonceSize

	// SideClient 标识客户端→服务端方向
	SideClient uint8 = 0x01

	// SideServer 标识服务端→客户端方向
	SideServer uint8 = 0x02
)

// DeriveKey 从共享认证令牌派生 32 字节对称密钥
// 双端必须使用相同的令牌才能得到相同的密钥
func DeriveKey(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// buildNonce 构造 12 字节 nonce
// 格式: connID(8字节, 与 side 异或) + seqNum(4字节截断)
// side 字节混入 connID 以确保客户端/服务端 nonce 空间不重叠
func buildNonce(connID uint64, seqNum uint64, side uint8) [NonceSize]byte {
	var nonce [NonceSize]byte
	// 字节 [0..7]: connID XOR side（确保每方向的 nonce 空间不同）
	binary.LittleEndian.PutUint64(nonce[0:8], connID^uint64(side))
	// 字节 [8..11]: 序列号（32 位截断——对单连接计数器已足够）
	binary.LittleEndian.PutUint32(nonce[8:12], uint32(seqNum))
	return nonce
}

// Encrypt 使用 ChaCha20-Poly1305 加密并认证明文
// 返回密文 || 16 字节 Poly1305 认证标签
// 密钥必须为 32 字节（通过 DeriveKey 派生）
// 同一密钥下 (connID, seqNum, side) 三元组不可重用
func Encrypt(key []byte, connID uint64, seqNum uint64, side uint8, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305 init: %w", err)
	}
	nonce := buildNonce(connID, seqNum, side)
	// Seal 在密文后附加 16 字节 Poly1305 认证标签
	return aead.Seal(nil, nonce[:], plaintext, nil), nil
}

// Decrypt 验证并解密密文（包含 16 字节 Poly1305 认证标签）
// 返回明文，或在认证失败时返回错误
func Decrypt(key []byte, connID uint64, seqNum uint64, side uint8, ciphertextWithTag []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305 init: %w", err)
	}
	nonce := buildNonce(connID, seqNum, side)
	plaintext, err := aead.Open(nil, nonce[:], ciphertextWithTag, nil)
	if err != nil {
		return nil, errors.New("authentication failed: tag mismatch")
	}
	return plaintext, nil
}
