// SPDX-License-Identifier: GPL-3.0-or-later
//
// Benchmark the VKO operation used by the Ru-WireGuard handshake.
// This is a microbenchmark, not a constant-time security evaluation.
package gost3410

import (
	"math/big"
	"testing"
)

func BenchmarkTC26VKO2012_256(b *testing.B) {
	curve := CurveIdtc26gost34102012256paramSetA()
	scalar := big.NewInt(7).FillBytes(make([]byte, curve.PointSize()))
	x, y, err := curve.Exp(big.NewInt(23), curve.X, curve.Y)
	if err != nil {
		b.Fatal(err)
	}
	ukm := big.NewInt(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := curve.KEK2012256(scalar, x, y, ukm); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTC26CompressedPublicKeyValidation(b *testing.B) {
	curve := CurveIdtc26gost34102012256paramSetA()
	encoded := MarshalCompressed(curve, curve.X, curve.Y)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x, y := UnmarshalCompressed(curve, encoded)
		if x == nil || y == nil {
			b.Fatal("valid public key rejected")
		}
	}
}
