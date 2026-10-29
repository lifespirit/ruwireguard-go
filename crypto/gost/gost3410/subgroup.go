// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2026 Contributors.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package gost3410

import "math/big"

// subgroupJacobianPoint uses Z=0 for the point at infinity. This is separate
// from Curve.Exp, whose affine arithmetic cannot represent infinity.
// All operations here are on PUBLIC key material and the public curve order.
type subgroupJacobianPoint struct {
	x, y, z *big.Int
}

func subgroupInfinity() subgroupJacobianPoint {
	return subgroupJacobianPoint{new(big.Int), big.NewInt(1), new(big.Int)}
}

func subgroupMul(a, b, p *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(a, b), p)
}

func subgroupAdd(a, b, p *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(a, b), p)
}

func subgroupSub(a, b, p *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Sub(a, b), p)
}

// subgroupDouble doubles a Jacobian point on y^2 = x^3 + ax + b.
// In particular, doubling a point with y=0 returns infinity.
func (c *Curve) subgroupDouble(s subgroupJacobianPoint) subgroupJacobianPoint {
	if s.z.Sign() == 0 || s.y.Sign() == 0 {
		return subgroupInfinity()
	}
	p := c.P
	yy := subgroupMul(s.y, s.y, p)
	zz := subgroupMul(s.z, s.z, p)
	m := subgroupAdd(
		subgroupMul(big.NewInt(3), subgroupMul(s.x, s.x, p), p),
		subgroupMul(c.A, subgroupMul(zz, zz, p), p),
		p,
	)
	fourXYY := subgroupMul(big.NewInt(4), subgroupMul(s.x, yy, p), p)
	x := subgroupSub(subgroupMul(m, m, p), subgroupMul(big.NewInt(2), fourXYY, p), p)
	y := subgroupSub(
		subgroupMul(m, subgroupSub(fourXYY, x, p), p),
		subgroupMul(big.NewInt(8), subgroupMul(yy, yy, p), p),
		p,
	)
	z := subgroupMul(big.NewInt(2), subgroupMul(s.y, s.z, p), p)
	return subgroupJacobianPoint{x, y, z}
}

// subgroupAddAffine adds an affine PUBLIC point to a Jacobian accumulator.
// Equal and opposite points are handled explicitly so no modular inverse
// of zero is ever attempted.
func (c *Curve) subgroupAddAffine(s subgroupJacobianPoint, x, y *big.Int) subgroupJacobianPoint {
	if s.z.Sign() == 0 {
		return subgroupJacobianPoint{new(big.Int).Set(x), new(big.Int).Set(y), big.NewInt(1)}
	}
	p := c.P
	zz := subgroupMul(s.z, s.z, p)
	u := subgroupMul(x, zz, p)
	v := subgroupMul(y, subgroupMul(zz, s.z, p), p)
	h := subgroupSub(u, s.x, p)
	r := subgroupSub(v, s.y, p)
	if h.Sign() == 0 {
		if r.Sign() == 0 {
			return c.subgroupDouble(s)
		}
		return subgroupInfinity()
	}
	hh := subgroupMul(h, h, p)
	hhh := subgroupMul(h, hh, p)
	t := subgroupMul(s.x, hh, p)
	newX := subgroupSub(
		subgroupSub(subgroupMul(r, r, p), hhh, p),
		subgroupAdd(t, t, p),
		p,
	)
	newY := subgroupSub(
		subgroupMul(r, subgroupSub(t, newX, p), p),
		subgroupMul(s.y, hhh, p),
		p,
	)
	newZ := subgroupMul(s.z, h, p)
	return subgroupJacobianPoint{newX, newY, newZ}
}

// IsInPrimeOrderSubgroup checks a public point against the curve's prime-order
// subgroup: 0 <= x,y < P, y^2 = x^3 + ax + b, and [Q]P = infinity.
// It does NOT multiply any private scalar. In particular, it rejects the
// order-2 and order-4 points on the TC26 256A curve (cofactor 4).
func (c *Curve) IsInPrimeOrderSubgroup(x, y *big.Int) bool {
	if c == nil || c.P == nil || c.Q == nil || c.A == nil ||
		x == nil || y == nil || c.P.Sign() <= 0 || c.Q.Sign() <= 0 ||
		x.Sign() < 0 || y.Sign() < 0 || x.Cmp(c.P) >= 0 || y.Cmp(c.P) >= 0 ||
		!c.IsOnCurve(x, y) {
		return false
	}
	acc := subgroupInfinity()
	for i := c.Q.BitLen() - 1; i >= 0; i-- {
		acc = c.subgroupDouble(acc)
		if c.Q.Bit(i) == 1 {
			acc = c.subgroupAddAffine(acc, x, y)
		}
	}
	return acc.z.Sign() == 0
}
