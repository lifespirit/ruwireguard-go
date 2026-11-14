// SPDX-License-Identifier: MIT
package gosthopper

import (
	"fmt"
	"sync"
	"testing"
)

// In particular, the first cipher construction may run concurrently in
// independent handshake workers. All entry points must observe complete tables.
func TestConcurrentFirstCipherInitialization(t *testing.T) {
	key := [32]byte{
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	plaintext := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	want := [16]byte{0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd}

	const workers = 64
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			switch i % 4 {
			case 0:
				block, err := NewCipher(key[:])
				if err != nil {
					errs <- err
					return
				}
				var got [16]byte
				block.Encrypt(got[:], plaintext[:])
				if got != want {
					errs <- fmt.Errorf("NewCipher produced %x, want %x", got, want)
				}
			case 1:
				if got := Encrypt(key, plaintext); got != want {
					errs <- fmt.Errorf("Encrypt produced %x, want %x", got, want)
				}
			case 2:
				if got := Decrypt(key, want); got != plaintext {
					errs <- fmt.Errorf("Decrypt produced %x, want %x", got, plaintext)
				}
			case 3:
				InitCipher()
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if !CipherInitialized {
		t.Fatal("Kuznyechik tables not initialized")
	}
}
