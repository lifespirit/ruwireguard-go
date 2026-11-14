/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package gost3410

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

// ValidScalar reports whether key is a canonical, big-endian private scalar
// in the interval [1, curve.Q). No reduction modulo Q is performed.
func ValidScalar(curve *Curve, key []byte) bool {
	if curve == nil || curve.Q == nil || len(key) != curve.PointSize() {
		return false
	}
	k := new(big.Int).SetBytes(key)
	return k.Sign() > 0 && k.Cmp(curve.Q) < 0
}

// GenerateScalar draws a uniformly distributed scalar in [1, Q) via rejection
// sampling. The bytes are big-endian for internal scalar multiplication.
// An explicit bound keeps broken deterministic readers from looping forever.
func GenerateScalar(curve *Curve, rng io.Reader) ([]byte, error) {
	if curve == nil || curve.Q == nil || curve.Q.Sign() <= 0 {
		return nil, errors.New("gost3410: invalid curve order")
	}
	if rng == nil {
		rng = rand.Reader
	}
	raw := make([]byte, curve.PointSize())
	key := make([]byte, curve.PointSize())
	for attempt := 0; attempt < 256; attempt++ {
		if _, err := io.ReadFull(rng, raw); err != nil {
			return nil, err
		}
		for i := range key {
			key[i] = raw[len(raw)-i-1]
		}
		if ValidScalar(curve, key) {
			return key, nil
		}
	}
	return nil, errors.New("gost3410: unable to generate a valid private scalar")
}

func GenerateKey(curve *Curve, rng io.Reader) (key []byte, x, y *big.Int, err error) {
	key, err = GenerateScalar(curve, rng)
	if err != nil {
		return nil, nil, nil, err
	}
	x, y, err = curve.Exp(new(big.Int).SetBytes(key), curve.X, curve.Y)
	return
}

func Reverse(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

func Marshal(curve *Curve, x, y *big.Int) []byte {
	byteLen := curve.PointSize()

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	x.FillBytes(ret[1 : 1+byteLen])
	y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}

func MarshalCompressed(curve *Curve, x, y *big.Int) []byte {
	byteLen := curve.PointSize()
	compressed := make([]byte, 1+byteLen)
	compressed[0] = byte(y.Bit(0)) | 2
	x.FillBytes(compressed[1:])
	return compressed
}

func Unmarshal(curve *Curve, data []byte) (x, y *big.Int) {
	byteLen := curve.PointSize()
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	if data[0] != 4 { // uncompressed form
		return nil, nil
	}
	p := curve.P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil
	}
	if !curve.IsInPrimeOrderSubgroup(x, y) {
		return nil, nil
	}
	return
}

func UnmarshalCompressed(curve *Curve, data []byte) (x, y *big.Int) {
	byteLen := curve.PointSize()
	if len(data) != 1+byteLen {
		return nil, nil
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil
	}
	p := curve.P
	x = new(big.Int).SetBytes(data[1:])
	if x.Cmp(p) >= 0 {
		return nil, nil
	}
	// y² = x³ + ax + b
	y = polynomial(curve, x)
	y = y.ModSqrt(y, p)
	if y == nil {
		return nil, nil
	}
	if byte(y.Bit(0)) != data[0]&1 {
		y.Neg(y).Mod(y, p)
	}
	// Reject the odd encoding of y=0; it has no odd square root.
	if byte(y.Bit(0)) != data[0]&1 {
		return nil, nil
	}
	if !curve.IsInPrimeOrderSubgroup(x, y) {
		return nil, nil
	}
	return
}
