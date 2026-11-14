// SPDX-License-Identifier: MIT
//
// Regression tests for canonical GOST private scalar generation.
package gost3410

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"testing"
)

func testScalarBytes(n *big.Int, size int) []byte {
	return n.FillBytes(make([]byte, size))
}

func TestValidScalarRange(t *testing.T) {
	curve := CurveIdtc26gost34102012256paramSetA()
	size := curve.PointSize()
	cases := []struct {
		name  string
		value *big.Int
		valid bool
	}{
		{"zero", big.NewInt(0), false},
		{"one", big.NewInt(1), true},
		{"q-minus-one", new(big.Int).Sub(curve.Q, big.NewInt(1)), true},
		{"q", new(big.Int).Set(curve.Q), false},
		{"q-plus-one", new(big.Int).Add(curve.Q, big.NewInt(1)), false},
		{"max-256", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := testScalarBytes(tc.value, size)
			if got := ValidScalar(curve, raw); got != tc.valid {
				t.Fatalf("ValidScalar(%s) = %t, want %t", tc.name, got, tc.valid)
			}
			if tc.valid {
				if _, err := NewPrivateKey(curve, Reversed(raw)); err != nil {
					t.Fatalf("valid scalar rejected by NewPrivateKey: %v", err)
				}
			} else if _, err := NewPrivateKey(curve, Reversed(raw)); err == nil {
				t.Fatal("NewPrivateKey accepted a noncanonical scalar")
			}
		})
	}
	if ValidScalar(curve, []byte{1}) {
		t.Fatal("short scalar accepted")
	}
	if ValidScalar(nil, make([]byte, size)) {
		t.Fatal("nil curve accepted")
	}
}

func TestGenerateScalarRejectsOutOfRangeCandidates(t *testing.T) {
	curve := CurveIdtc26gost34102012256paramSetA()
	size := curve.PointSize()
	// Each candidate is supplied in GOST little-endian byte order, as
	// GenerateScalar reads from the RNG before reversing for the caller.
	var stream []byte
	for _, candidate := range []*big.Int{
		big.NewInt(0),
		new(big.Int).Set(curve.Q),
		new(big.Int).Add(curve.Q, big.NewInt(1)),
		big.NewInt(7),
	} {
		stream = append(stream, Reversed(testScalarBytes(candidate, size))...)
	}

	key, err := GenerateScalar(curve, bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, testScalarBytes(big.NewInt(7), size)) {
		t.Fatalf("generator did not reject invalid samples: got %x", key)
	}

	if _, err := GenerateScalar(curve, bytes.NewReader(make([]byte, size-1))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short reader: got %v, want ErrUnexpectedEOF", err)
	}
	if _, err := GenerateScalar(curve, bytes.NewReader(make([]byte, 256*size))); err == nil {
		t.Fatal("accepted an RNG producing only zero scalars")
	}
}

func TestGenerateKeyAndGenPrivateKeyUseCanonicalScalars(t *testing.T) {
	curve := CurveIdtc26gost34102012256paramSetA()
	size := curve.PointSize()
	q := Reversed(testScalarBytes(curve.Q, size))
	one := Reversed(testScalarBytes(big.NewInt(1), size))
	rng := bytes.NewReader(append(append([]byte{}, q...), one...))
	key, x, y, err := GenerateKey(curve, rng)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidScalar(curve, key) || x.Cmp(curve.X) != 0 || y.Cmp(curve.Y) != 0 {
		t.Fatal("GenerateKey did not produce the scalar-one public point")
	}
	rng = bytes.NewReader(append(append([]byte{}, q...), one...))
	private, err := GenPrivateKey(curve, rng)
	if err != nil {
		t.Fatal(err)
	}
	if private.Key.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("GenPrivateKey returned scalar %v instead of one", private.Key)
	}
}
