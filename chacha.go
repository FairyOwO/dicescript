package dicescript

import (
	"crypto/rand"
	"crypto/sha256"
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
func (s *ChaChaSource) Seed(seed uint64) {
	if seed == 0 {
		if _, err := rand.Read(s.key[:]); err != nil {
			panic(fmt.Sprintf("failed to read random bytes: %v", err))
		}
		if _, err := rand.Read(s.nonce[:]); err != nil {
			panic(fmt.Sprintf("failed to read random bytes: %v", err))
		}
	} else {
		seedBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(seedBytes, seed)

		keyDigest := sha256.Sum256(seedBytes)
		copy(s.key[:], keyDigest[:32])

		nonceInput := append([]byte("NONCE_PREFIX_SALT_FOR_CHACHA_"), seedBytes...) // 使用更独特的盐
		nonceDigest := sha256.Sum256(nonceInput)
		copy(s.nonce[:], nonceDigest[:12])
	}
	s.stream = nil
	s.pos = 0
}

// Uint64 生成一个随机的uint64数字
func (s *ChaChaSource) Uint64() uint64 {
	if s.stream == nil || s.pos > len(s.stream)-8 {

		if s.stream != nil {
			for i := 0; i < 12; i++ {
				s.nonce[i]++
				if s.nonce[i] != 0 {
					break
				}

				if i == 11 && s.nonce[i] == 0 {
					// 理论上，nonce有 2^96 种可能，不太可能在合理时间内耗尽。
					// 但作为安全措施，可以 panic 或记录警告。
					panic("ChaCha20 nonce (12-byte) has overflowed. Re-seed the generator or review usage.")
				}
			}
		}

		cipher, err := chacha20.NewUnauthenticatedCipher(s.key[:], s.nonce[:])
		if err != nil {
			panic(fmt.Sprintf("failed to create chacha20 cipher (key: %x, nonce: %x): %v", s.key, s.nonce, err))
		}

		if s.stream == nil {
			s.stream = make([]byte, 1024)
		}

		// 用 ChaCha20 的密钥流填充缓冲区。
		cipher.XORKeyStream(s.stream, s.stream)
		s.pos = 0 // 重置读取位置
	}

	// 从缓冲区中读取一个 uint64
	v := binary.LittleEndian.Uint64(s.stream[s.pos:])
	s.pos += 8 // 更新读取位置
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
