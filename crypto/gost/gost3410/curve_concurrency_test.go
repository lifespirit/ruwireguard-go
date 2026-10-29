// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Contributors.
// Concurrent scalar multiplication regression test.
package gost3410

import (
	"bytes"
	"math/big"
	"sync"
	"testing"
)

// TestConcurrentExpAndVKO exercises the same curve instance from multiple
// goroutines, as happens when Ru-WireGuard handles parallel handshakes.
// Prior to using invocation-local scratch in Curve.Exp, this raced on
// Curve.t, Curve.tx, and Curve.ty and could corrupt shared secret results.
func TestConcurrentExpAndVKO(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()

	var privateA, privateB [32]byte
	for i := range privateA {
		privateA[i] = byte(i + 1)
		privateB[i] = byte(i + 3)
	}

	expectedX, expectedY, err := c.ScalarBaseMult(privateA[:])
	if err != nil {
		t.Fatal(err)
	}
	peerX, peerY, err := c.ScalarBaseMult(privateB[:])
	if err != nil {
		t.Fatal(err)
	}
	expectedSecret, err := c.KEK2012256(privateA[:], peerX, peerY, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start

			for j := 0; j < 2; j++ {
				x, y, err := c.ScalarBaseMult(privateA[:])
				if err != nil {
					t.Errorf("concurrent scalar multiplication: %v", err)
					return
				}
				if x.Cmp(expectedX) != 0 || y.Cmp(expectedY) != 0 {
					t.Error("concurrent scalar multiplication changed the public key")
					return
				}

				secret, err := c.KEK2012256(privateA[:], peerX, peerY, big.NewInt(1))
				if err != nil {
					t.Errorf("concurrent VKO: %v", err)
					return
				}
				if !bytes.Equal(secret, expectedSecret) {
					t.Error("concurrent VKO changed the shared secret")
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
}
