// SPDX-License-Identifier: GPL-3.0-or-later
//
// Public-key subgroup regression tests for TC26 GOST 34.10-2012 256A.
package gost3410

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// These are real points on TC26 256A, not malformed curve points. The
// curve has cofactor 4: accepting either makes VKO vulnerable to small-
// subgroup contributions. The order-4 point was derived by [Q]P from an
// on-curve point with affine x=13.
const (
	order2XHex = "0100fe73f595ff158e974b44d478d9588744fe5c192ac47ea63075dce7a14aaa"
	order4XHex = "7f7f80c60535007538b45a5d95c39353bc5d80d1f36a9dc0ace7c5118c2f5977"
	order4YHex = "7e7e82520f9f015faa1d0f18c14ab9fb35188275da3fd94206b74f34a48e0ecd"
)

func subgroupHexInt(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatal("invalid subgroup test fixture")
	}
	return n
}

func TestTC26SubgroupRejectsLowOrderPoints(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()
	tests := []struct {
		name string
		x, y *big.Int
	}{
		{"order-2", subgroupHexInt(t, order2XHex), big.NewInt(0)},
		{"order-4", subgroupHexInt(t, order4XHex), subgroupHexInt(t, order4YHex)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !c.IsOnCurve(tc.x, tc.y) {
				t.Fatal("test vector does not lie on TC26 256A")
			}
			if c.IsInPrimeOrderSubgroup(tc.x, tc.y) {
				t.Fatal("accepted a low-order point as a prime-order public key")
			}
			if x, y := Unmarshal(c, Marshal(c, tc.x, tc.y)); x != nil || y != nil {
				t.Fatal("uncompressed point parser accepted a low-order point")
			}
			if x, y := UnmarshalCompressed(c, MarshalCompressed(c, tc.x, tc.y)); x != nil || y != nil {
				t.Fatal("compressed point parser accepted a low-order point")
			}
		})
	}
	if x, y := UnmarshalCompressed(c, append([]byte{3}, subgroupHexInt(t, order2XHex).FillBytes(make([]byte, 32))...)); x != nil || y != nil {
		t.Fatal("accepted the noncanonical odd encoding of a zero-Y point")
	}
}

func TestTC26SubgroupAcceptsValidPublicPoints(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()
	for _, n := range []int64{1, 2, 3, 7, 99} {
		x, y, err := c.Exp(big.NewInt(n), c.X, c.Y)
		if err != nil {
			t.Fatal(err)
		}
		if !c.IsInPrimeOrderSubgroup(x, y) {
			t.Fatalf("rejected valid multiple %d of subgroup generator", n)
		}
		if dx, dy := Unmarshal(c, Marshal(c, x, y)); dx == nil || dy == nil || dx.Cmp(x) != 0 || dy.Cmp(y) != 0 {
			t.Fatalf("rejected valid uncompressed point %d", n)
		}
		if dx, dy := UnmarshalCompressed(c, MarshalCompressed(c, x, y)); dx == nil || dy == nil || dx.Cmp(x) != 0 || dy.Cmp(y) != 0 {
			t.Fatalf("rejected valid compressed point %d", n)
		}
	}
}

func TestTC26SubgroupRejectsMalformedCoordinates(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()
	if c.IsInPrimeOrderSubgroup(nil, c.Y) || c.IsInPrimeOrderSubgroup(c.X, nil) {
		t.Fatal("nil point coordinate accepted")
	}
	if c.IsInPrimeOrderSubgroup(c.P, c.Y) || c.IsInPrimeOrderSubgroup(big.NewInt(-1), c.Y) {
		t.Fatal("noncanonical field coordinate accepted")
	}
	invalidCompressed, err := hex.DecodeString("04" + order2XHex)
	if err != nil {
		t.Fatal(err)
	}
	if x, _ := UnmarshalCompressed(c, invalidCompressed); x != nil {
		t.Fatal("invalid compressed prefix accepted")
	}
}
