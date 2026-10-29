// SPDX-License-Identifier: GPL-3.0-or-later
package mgm

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"
)

// Reference uses the original independent math/big algorithm. Production
// code intentionally has no big.Int or data-dependent iteration count.
func referenceMulGF128(xRaw, yRaw []byte) []byte {
	x := new(big.Int).SetBytes(xRaw)
	y := new(big.Int).SetBytes(yRaw)
	z := new(big.Int)
	poly := big.NewInt(0x87)
	for y.Sign() != 0 {
		if y.Bit(0) == 1 {
			z.Xor(z, x)
		}
		top := x.Bit(127)
		if top == 1 {
			x.SetBit(x, 127, 0)
		}
		x.Lsh(x, 1)
		if top == 1 {
			x.Xor(x, poly)
		}
		y.Rsh(y, 1)
	}
	return z.FillBytes(make([]byte, 16))
}

func TestGF128FixedIterationMatchesBigInt(t *testing.T) {
	var mgm MGM
	edge := [][]byte{
		make([]byte, 16),
		bytes.Repeat([]byte{0xff}, 16),
		append(make([]byte, 15), 1),
		append([]byte{0x80}, make([]byte, 15)...),
	}
	for i, x := range edge {
		for j, y := range edge {
			got := mgm.mul(x, y)
			want := referenceMulGF128(x, y)
			if !bytes.Equal(got, want) {
				t.Fatalf("edge input %d/%d: got %x, want %x", i, j, got, want)
			}
		}
	}

	random := rand.New(rand.NewSource(2026))
	for i := 0; i < 2000; i++ {
		var x, y [16]byte
		if _, err := random.Read(x[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := random.Read(y[:]); err != nil {
			t.Fatal(err)
		}
		xOriginal, yOriginal := x, y
		got := mgm.mul(x[:], y[:])
		want := referenceMulGF128(x[:], y[:])
		if !bytes.Equal(got, want) {
			t.Fatalf("trial %d: got %x, want %x; x=%x, y=%x", i, got, want, x, y)
		}
		if x != xOriginal || y != yOriginal {
			t.Fatal("GF multiplication modified an input operand")
		}
	}
}
