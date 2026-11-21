package fingerprint

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// murmur3_32 (x86, seed 0) - same as Python mmh3.hash().
func murmur3(data []byte, seed uint32) int32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data)
	nblocks := n / 4
	for i := 0; i < nblocks; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
		h = h<<13 | h>>19
		h = h*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = k1<<15 | k1>>17
		k1 *= c2
		h ^= k1
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// FaviconHash computes the Shodan-compatible favicon hash:
// mmh3(base64.encodebytes(icon)) where encodebytes wraps lines at 76 chars
// and terminates every line with "\n". Values are interoperable with
// Shodan/FOFA "http.favicon.hash" queries.
func FaviconHash(icon []byte) string {
	b64 := base64.StdEncoding.EncodeToString(icon)
	var sb strings.Builder
	for len(b64) > 76 {
		sb.WriteString(b64[:76])
		sb.WriteByte('\n')
		b64 = b64[76:]
	}
	sb.WriteString(b64)
	sb.WriteByte('\n')
	return strconv.FormatInt(int64(murmur3([]byte(sb.String()), 0)), 10)
}
