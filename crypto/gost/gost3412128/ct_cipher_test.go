// SPDX-License-Identifier: GPL-3.0-or-later
package gost3412128

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCTKuznyechikSboxParity(t *testing.T) {
	for i := 0; i < 256; i++ {
		var input [BlockSize]byte
		for j := range input {
			input[j] = byte(i)
		}
		s := input
		ctSubstituteForward(&s)
		for _, got := range s {
			if got != pi[i] {
				t.Fatalf("forward S-box input %d: got %d want %d", i, got, pi[i])
			}
		}
		ctSubstituteInverse(&s)
		if s != input {
			t.Fatalf("inverse S-box failed at %d", i)
		}
	}
}

func TestCTKuznyechikLinearParity(t *testing.T) {
	for i := 0; i < 64; i++ {
		var input [BlockSize]byte
		if _, err := rand.Read(input[:]); err != nil {
			t.Fatal(err)
		}
		want := input
		l(&want, 16) // Public test data, variable-time reference.
		got := input
		ctLinearForward(&got)
		if got != want {
			t.Fatalf("forward L transform mismatch for %x", input)
		}
		ctLinearInverse(&got)
		if got != input {
			t.Fatalf("L inverse mismatch for %x", input)
		}
	}
}

func TestCTKuznyechikPublishedVector(t *testing.T) {
	key := []byte{
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	plaintext := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	expected := []byte{0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd}
	c := NewCipher(key)
	ciphertext := make([]byte, BlockSize)
	c.Encrypt(ciphertext, plaintext)
	if !bytes.Equal(ciphertext, expected) {
		t.Fatalf("known answer mismatch: got %x want %x", ciphertext, expected)
	}
	recovered := make([]byte, BlockSize)
	c.Decrypt(recovered, ciphertext)
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("decryption round trip mismatch: got %x", recovered)
	}
}

func BenchmarkKuznyechikCTEncrypt(b *testing.B) {
	c := NewCipher(make([]byte, KeySize))
	var data [BlockSize]byte
	b.SetBytes(BlockSize)
	for i := 0; i < b.N; i++ {
		c.Encrypt(data[:], data[:])
	}
}
