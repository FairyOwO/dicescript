package dicescript

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

type ChaChaSource struct {
	key    [32]byte // ChaCha20 key
	nonce  [12]byte // ChaCha20 nonce
	stream []byte   // 缓存的随机字节
	pos    int      // 当前读取位置
}

// NewChaChaSource 创建一个新的ChaCha20随机源
func NewChaChaSource() *ChaChaSource {
	s := &ChaChaSource{}
	s.Seed(0) // 使用默认种子
	return s
}

// Seed 设置随机源的种子
// 为了向后兼容,这里只使用种子的低64位
func (s *ChaChaSource) Seed(seed uint64) {
	// 使用seed生成key和nonce
	var keyData [40]byte // 32字节key + 8字节seed
	binary.LittleEndian.PutUint64(keyData[32:], seed)

	// 如果没有提供种子,从系统随机源获取
	if seed == 0 {
		if _, err := rand.Read(keyData[:]); err != nil {
			panic(fmt.Sprintf("failed to read random seed: %v", err))
		}
	}

	copy(s.key[:], keyData[:32])
	copy(s.nonce[:], keyData[20:32]) // 使用key的一部分作为nonce

	// 重置stream
	s.stream = nil
	s.pos = 0
}

// Uint64 生成一个随机的uint64数字
func (s *ChaChaSource) Uint64() uint64 {
	// 确保有足够的随机字节
	if s.stream == nil || s.pos > len(s.stream)-8 {
		// 生成新的随机字节
		cipher, err := chacha20.NewUnauthenticatedCipher(s.key[:], s.nonce[:])
		if err != nil {
			panic(fmt.Sprintf("failed to create chacha20 cipher: %v", err))
		}

		// 生成1024字节的随机数据
		s.stream = make([]byte, 1024)
		cipher.XORKeyStream(s.stream, s.stream)
		s.pos = 0
	}

	// 从stream中读取uint64
	v := binary.LittleEndian.Uint64(s.stream[s.pos:])
	s.pos += 8
	return v
}

func (s *ChaChaSource) MarshalBinary() ([]byte, error) {
	data := make([]byte, len(s.key)+len(s.nonce))
	copy(data, s.key[:])
	copy(data[len(s.key):], s.nonce[:])
	return data, nil
}

func (s *ChaChaSource) UnmarshalBinary(data []byte) error {
	if len(data) != len(s.key)+len(s.nonce) {
		return fmt.Errorf("invalid data length for ChaChaSource: got %d, want %d", len(data), len(s.key)+len(s.nonce))
	}
	copy(s.key[:], data[:len(s.key)])
	copy(s.nonce[:], data[len(s.key):])
	s.stream = nil
	s.pos = 0
	return nil
}
