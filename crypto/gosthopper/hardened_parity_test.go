// SPDX-License-Identifier: MIT
package gosthopper

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Legacy fused-table assembly remains as a reference oracle, but the VPN must
// receive the data-oblivious block implementation from NewCipher.
func TestHardenedBlockMatchesLegacyKuznyechik(t *testing.T) {
	InitCipher()
	for i := 0; i < 24; i++ {
		var key [32]byte
		var plaintext [BlockSize]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(plaintext[:]); err != nil {
			t.Fatal(err)
		}
		block, err := NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, unsafeLegacy := block.(*GOSTHopper); unsafeLegacy {
			t.Fatal("VPN NewCipher unexpectedly returned the secret-indexed legacy implementation")
		}
		roundKeys := StretchKey(key)
		expected := DoEncrypt(plaintext, roundKeys)
		var got [BlockSize]byte
		block.Encrypt(got[:], plaintext[:])
		if got != expected {
			t.Fatalf("cipher #%d: got %x want %x", i, got, expected)
		}
		var decrypted [BlockSize]byte
		block.Decrypt(decrypted[:], got[:])
		if !bytes.Equal(decrypted[:], plaintext[:]) {
			t.Fatalf("cipher #%d: decryption mismatch", i)
		}
	}
}
