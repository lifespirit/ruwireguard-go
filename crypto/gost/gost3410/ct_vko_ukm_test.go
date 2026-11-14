// SPDX-License-Identifier: GPL-3.0-or-later
package gost3410

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

// UKM is public. The constant-time path must preserve the original VKO
// semantics for non-default factors as well as the VPN's UKM=1, cofactor=4.
func TestCT256VKOArbitraryPublicUKM(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()
	mySecret, err := GenerateScalar(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerSecret, err := GenerateScalar(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerX, peerY, err := c.ScalarBaseMult(peerSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, factor := range []int64{1, 2, 3, 5, 17, 65537} {
		ukm := big.NewInt(factor)
		got, err := c.KEK(mySecret, peerX, peerY, ukm)
		if err != nil {
			t.Fatal(err)
		}
		x, y, err := c.Exp(new(big.Int).SetBytes(mySecret), peerX, peerY)
		if err != nil {
			t.Fatal(err)
		}
		u := new(big.Int).Mul(ukm, c.Co)
		if u.Cmp(big.NewInt(1)) != 0 {
			x, y, err = c.Exp(u, x, y)
			if err != nil {
				t.Fatal(err)
			}
		}
		expected := (&PublicKey{c, x, y}).Raw()
		if !bytes.Equal(got, expected) {
			t.Fatalf("VKO with public UKM %d differs from legacy reference", factor)
		}
	}
}
