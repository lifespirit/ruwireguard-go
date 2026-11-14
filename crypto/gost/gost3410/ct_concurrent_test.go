// SPDX-License-Identifier: GPL-3.0-or-later
package gost3410

import (
	"fmt"
	"math/big"
	"sync"
	"testing"
)

// All workers share one immutable Curve and its cached Montgomery context.
// The expected points are public and generated once from the variable-time
// reference, outside the concurrent part of the test.
func TestConcurrentCT256ScalarMult(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()
	const n = 12
	keys := make([][]byte, n)
	expectedX := make([]*big.Int, n)
	expectedY := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		k := big.NewInt(int64(i + 1))
		keys[i] = k.FillBytes(make([]byte, 32))
		var err error
		expectedX[i], expectedY[i], err = c.Exp(k, c.X, c.Y)
		if err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errors := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			x, y, err := c.ScalarBaseMult(keys[i])
			if err != nil {
				errors <- err
			} else if x.Cmp(expectedX[i]) != 0 || y.Cmp(expectedY[i]) != 0 {
				errors <- fmt.Errorf("worker %d: fixed-limb point mismatch", i)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
