// SPDX-License-Identifier: GPL-3.0-or-later
package gost3410

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestCTField256MatchesBigInt(t *testing.T) {
	curve := CurveIdtc26gost34102012256paramSetA()
	f := newCTField(curve.P)
	edge := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Sub(curve.P, big.NewInt(1)),
		new(big.Int).Sub(curve.P, big.NewInt(2)),
	}
	for i := 0; i < 24; i++ {
		x, err := rand.Int(rand.Reader, curve.P)
		if err != nil {
			t.Fatal(err)
		}
		edge = append(edge, x)
	}
	for i := range edge {
		a := edge[i]
		b := edge[(i+7)%len(edge)]
		fa, fb := f.toMont(feFromBig(a)), f.toMont(feFromBig(b))
		for _, op := range []struct {
			name string
			got fe
			want *big.Int
		}{
			{"add", f.add(fa, fb), new(big.Int).Mod(new(big.Int).Add(a, b), curve.P)},
			{"sub", f.sub(fa, fb), new(big.Int).Mod(new(big.Int).Sub(a, b), curve.P)},
			{"mul", f.mul(fa, fb), new(big.Int).Mod(new(big.Int).Mul(a, b), curve.P)},
			{"sqr", f.sqr(fa), new(big.Int).Mod(new(big.Int).Mul(a, a), curve.P)},
		} {
			got := bigFromFe(f.fromMont(op.got))
			if got.Cmp(op.want) != 0 {
				t.Fatalf("sample %d %s: got %s want %s", i, op.name, got, op.want)
			}
		}
		if a.Sign() != 0 {
			got := bigFromFe(f.fromMont(f.inv(fa)))
			want := new(big.Int).ModInverse(a, curve.P)
			if got.Cmp(want) != 0 {
				t.Fatalf("sample %d inverse mismatch", i)
			}
		}
	}
}

func TestCT256CompletePointExceptionalCases(t *testing.T) {
	curve := CurveIdtc26gost34102012256paramSetA()
	cc := newCTCurve(curve)
	base := cc.fromAffine(curve.X, curve.Y)
	identity := cc.identity()
	check := func(label string, point ctPoint, x, y *big.Int) {
		t.Helper()
		gotX, gotY := cc.toAffine(point)
		if x == nil || y == nil {
			if gotX != nil || gotY != nil {
				t.Errorf("%s: expected identity", label)
			}
			return
		}
		if gotX == nil || gotY == nil || gotX.Cmp(x) != 0 || gotY.Cmp(y) != 0 {
			t.Errorf("%s: unexpected point", label)
		}
	}
	check("O+P", cc.add(identity, base), curve.X, curve.Y)
	check("P+O", cc.add(base, identity), curve.X, curve.Y)
	check("2P", cc.double(base), func() *big.Int {
		x, _, _ := curve.Exp(big.NewInt(2), curve.X, curve.Y)
		return x
	}(), func() *big.Int {
		_, y, _ := curve.Exp(big.NewInt(2), curve.X, curve.Y)
		return y
	}())
	check("P-P", cc.add(base, cc.fromAffine(curve.X, new(big.Int).Sub(curve.P, curve.Y))), nil, nil)
}

func FuzzCT256ScalarMatchesLegacy(f *testing.F) {
	curve := CurveIdtc26gost34102012256paramSetA()
	for _, n := range []int64{1, 2, 3, 7, 31, 65537} {
		f.Add(big.NewInt(n).FillBytes(make([]byte, 32)))
	}
	f.Add(new(big.Int).Sub(curve.Q, big.NewInt(1)).FillBytes(make([]byte, 32)))
	f.Fuzz(func(t *testing.T, scalar []byte) {
		if len(scalar) != 32 || !curve.validScalarFixed256(scalar) {
			return
		}
		gotX, gotY, err := curve.ScalarBaseMult(scalar)
		if err != nil {
			t.Fatal(err)
		}
		wantX, wantY, err := curve.Exp(new(big.Int).SetBytes(scalar), curve.X, curve.Y)
		if err != nil {
			t.Fatal(err)
		}
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatal("fixed-limb scalar multiplication differs from reference")
		}
	})
}
