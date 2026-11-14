// SPDX-License-Identifier: GPL-3.0-or-later
package gost3410

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012256"
)

// Verify the fixed-limb secret path byte-for-byte against the legacy math/big
// reference. The reference is used ONLY for tests, not for VPN private keys.
func TestCT256ScalarAndVKOReferenceParity(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()
	kMax := new(big.Int).Sub(c.Q, big.NewInt(1)).FillBytes(make([]byte, 32))
	keys := [][]byte{
		big.NewInt(1).FillBytes(make([]byte, 32)),
		big.NewInt(2).FillBytes(make([]byte, 32)),
		big.NewInt(3).FillBytes(make([]byte, 32)),
		kMax,
	}
	for i := 0; i < 4; i++ {
		k, err := GenerateScalar(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	for i, key := range keys {
		k := new(big.Int).SetBytes(key)
		gotX, gotY, err := c.ScalarBaseMult(key)
		if err != nil {
			t.Fatalf("scalar %d: %v", i, err)
		}
		wantX, wantY, err := c.Exp(k, c.X, c.Y)
		if err != nil {
			t.Fatal(err)
		}
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatalf("scalar %d: constant-time base multiplication differs from reference", i)
		}
		// Non-base public point (k*G) with distinct secret multiplier.
		other := keys[(i+1)%len(keys)]
		secret, err := c.KEK2012256(other, gotX, gotY, big.NewInt(1))
		if err != nil {
			t.Fatal(err)
		}
		pubX, pubY, err := c.Exp(new(big.Int).SetBytes(other), gotX, gotY)
		if err != nil {
			t.Fatal(err)
		}
		pubX, pubY, err = c.Exp(c.Co, pubX, pubY)
		if err != nil {
			t.Fatal(err)
		}
		raw := (&PublicKey{c, pubX, pubY}).Raw()
		h := gost34112012256.New()
		h.Write(raw)
		want := h.Sum(nil)
		if !bytes.Equal(secret, want) {
			t.Fatalf("scalar %d: CT VKO differs from legacy reference", i)
		}
	}
}

func TestCT256RejectsInvalidScalar(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()
	for _, n := range []*big.Int{
		big.NewInt(0),
		new(big.Int).Set(c.Q),
		new(big.Int).Add(c.Q, big.NewInt(1)),
	} {
		k := n.FillBytes(make([]byte, 32))
		if c.validScalarFixed256(k) {
			t.Fatalf("accepted invalid scalar %s", n)
		}
		if _, _, err := c.ScalarBaseMult(k); err == nil {
			t.Fatal("accepted invalid scalar through fixed-limb base multiplication")
		}
	}
}
