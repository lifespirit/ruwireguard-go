// SPDX-License-Identifier: GPL-3.0-or-later
package mgm

import (
	"bytes"
	"testing"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3412128"
)

func TestOpenRejectsMalformedNetworkInputWithoutPanic(t *testing.T) {
	aead, err := NewMGM(gost3412128.NewCipher(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	valid := aead.Seal(nil, nonce, []byte("payload"), nil)
	tests := []struct {
		name string
		nonce []byte
		ciphertext []byte
	}{
		{"short nonce", nonce[:len(nonce)-1], valid},
		{"long nonce", append(bytes.Clone(nonce), 0), valid},
		{"forbidden nonce bit", append([]byte{0x80}, nonce[1:]...), valid},
		{"empty ciphertext", nonce, nil},
		{"short ciphertext", nonce, make([]byte, aead.Overhead()-1)},
		{"empty plaintext and aad", nonce, make([]byte, aead.Overhead())},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := aead.Open(nil, tc.nonce, tc.ciphertext, nil); err == nil {
				t.Fatal("malformed MGM input was accepted")
			}
		})
	}
	opened, err := aead.Open(nil, nonce, valid, nil)
	if err != nil || !bytes.Equal(opened, []byte("payload")) {
		t.Fatalf("valid MGM ciphertext not decrypted: %q, %v", opened, err)
	}
}
