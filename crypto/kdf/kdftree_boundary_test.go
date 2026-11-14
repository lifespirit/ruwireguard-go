// SPDX-License-Identifier: MIT
package kdf

import (
	"bytes"
	"testing"
)

func TestKDFTreeMaximumLengthDoesNotWrapCounter(t *testing.T) {
	const maxLength = 32 * 255
	key := bytes.Repeat([]byte{0x42}, 32)
	got := KDFTree(key, []byte("label"), []byte("seed"), maxLength)
	if len(got) != maxLength {
		t.Fatalf("output length = %d, want %d", len(got), maxLength)
	}
	if bytes.Equal(got[:32], got[maxLength-32:]) {
		t.Fatal("first and final KDF blocks unexpectedly match")
	}
}
