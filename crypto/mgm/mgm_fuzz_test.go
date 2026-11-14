// SPDX-License-Identifier: GPL-3.0-or-later
package mgm

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3412128"
)

// FuzzMGMOpen covers attacker-controlled MGM nonces, AAD and ciphertexts.
// Seed corpus is always executed by 'go test'; continuous mutation needs -fuzz.
func FuzzMGMOpen(f *testing.F) {
	aead, err := NewMGM(gost3412128.NewCipher(make([]byte, 32)))
	if err != nil {
		f.Fatal(err)
	}
	validNonce := make([]byte, aead.NonceSize())
	valid := aead.Seal(nil, validNonce, []byte("packet"), []byte("associated"))
	f.Add(validNonce, valid, []byte("associated"))
	f.Add([]byte{0x80}, make([]byte, aead.Overhead()), []byte("a"))
	f.Add(validNonce, []byte{0x00}, []byte("associated"))
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, nonce, ciphertext, aad []byte) {
		if len(nonce) > 32 || len(ciphertext) > 2048 || len(aad) > 2048 {
			return
		}
		plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			if plaintext != nil {
				t.Fatal("MGM.Open returned plaintext after authentication failure")
			}
			return
		}
		if !bytes.Equal(aead.Seal(nil, nonce, plaintext, aad), ciphertext) {
			t.Fatal("authenticated MGM plaintext does not round-trip")
		}
	})
}

// Tampering with the authentication tag must never produce plaintext.
func FuzzMGMRejectsModifiedTag(f *testing.F) {
	f.Add(uint64(0), []byte("hello"))
	f.Add(uint64(1), []byte{})
	f.Add(uint64(42), bytes.Repeat([]byte{0x5a}, 1280))
	aead, err := NewMGM(gost3412128.NewCipher(make([]byte, 32)))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, sequence uint64, plaintext []byte) {
		if len(plaintext) > 2048 {
			return
		}
		var nonce [16]byte
		binary.LittleEndian.PutUint64(nonce[8:], sequence)
		aad := []byte("RuWireGuard transport")
		ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
		ciphertext[len(ciphertext)-1] ^= 1
		got, err := aead.Open(nil, nonce[:], ciphertext, aad)
		if err == nil || got != nil {
			t.Fatal("tampered authentication tag was accepted")
		}
	})
}
