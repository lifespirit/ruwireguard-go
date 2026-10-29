// SPDX-License-Identifier: GPL-3.0-or-later
//
// The Ru-WireGuard data path uses Kuznyechik with MGM (not AES-GCM).
package mgm

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/bi-zone/ruwireguard-go/crypto/gosthopper"
)

func benchmarkKuznyechikMGM(b *testing.B, size int, decrypt bool) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	block, err := gosthopper.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	aead, err := NewMGM(block)
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, size)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	ad := make([]byte, 12) // Ru-WireGuard transport associated data
	var nonce [16]byte
	ciphertext := aead.Seal(nil, nonce[:], plaintext, ad)
	if decrypt {
		output := make([]byte, 0, size)
		b.SetBytes(int64(size))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out, err := aead.Open(output[:0], nonce[:], ciphertext, ad)
			if err != nil || len(out) != size {
				b.Fatalf("MGM decryption failed: %v", err)
			}
		}
		return
	}

	output := make([]byte, 0, size+aead.Overhead())
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Distinct nonces per key, even for benchmark iterations. These
		// ciphertexts are discarded; this is not a throughput tunnel test.
		binary.BigEndian.PutUint64(nonce[8:], uint64(i+1))
		out := aead.Seal(output[:0], nonce[:], plaintext, ad)
		if len(out) != size+aead.Overhead() {
			b.Fatal("MGM produced incorrect ciphertext length")
		}
	}
}

func BenchmarkRuWireGuardKuznyechikMGM(b *testing.B) {
	for _, size := range []int{64, 1280, 4096} {
		b.Run(fmt.Sprintf("Seal_%d", size), func(b *testing.B) {
			benchmarkKuznyechikMGM(b, size, false)
		})
		b.Run(fmt.Sprintf("Open_%d", size), func(b *testing.B) {
			benchmarkKuznyechikMGM(b, size, true)
		})
	}
}
