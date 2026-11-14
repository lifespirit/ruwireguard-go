// SPDX-License-Identifier: BSD-2-Clause
// Adapted from github.com/bigbes/gostcrypto (2026), BSD-2-Clause.
// Fixed-limb Montgomery arithmetic and complete RCB formulas.
// See CT_THIRD_PARTY_LICENSE.txt for copyright/attribution.
// EXPERIMENTAL: not independently audited in Ru-WireGuard-Go.
// ctpoint.go — EXPERIMENT. Constant-time projective point arithmetic using the
// Renes–Costello–Batina (2016) complete short-Weierstrass formulas
// (add-2015-rcb / dbl-2015-rcb, general a, b3 = 3·b). "Complete" means add and
// double have NO secret-dependent special-case branches for the identity or
// equal points, so they are safe inside a constant-time scalar multiply.
//
// A ctPoint is projective (X:Y:Z) with all coordinates in the Montgomery
// domain. The identity (point at infinity) is (0:1:0).

package gost3410

import (
	"encoding/binary"
	"math/big"
)

// ctCurve bundles the field with the curve constants a and b3 (Montgomery).
type ctCurve struct {
	f         *ctField
	a         fe  // Weierstrass a, Montgomery domain.
	b3        fe  // 3·b, Montgomery domain.
	orderBits int // bit length of the group order Q (fixed ladder iteration count).
}

// ctPoint is a projective point (X:Y:Z), Montgomery-domain coordinates.
type ctPoint struct {
	x, y, z fe
}

// newCTCurve derives the constant-time context for a 256-bit curve c.
func newCTCurve(c *Curve) *ctCurve {
	f := newCTField(c.P)

	aRed := new(big.Int).Mod(c.A, c.P)
	// b3 = 3·b, a precomputed constant of the complete addition formula.
	three := big.NewInt(3) //nolint:mnd // formula coefficient 3 (b3 = 3·b).
	b3big := new(big.Int).Mod(new(big.Int).Mul(c.B, three), c.P)

	return &ctCurve{
		f:         f,
		a:         f.toMont(feFromBig(aRed)),
		b3:        f.toMont(feFromBig(b3big)),
		orderBits: c.Q.BitLen(),
	}
}

// identity returns the projective point at infinity (0:1:0).
func (cc *ctCurve) identity() ctPoint {
	return ctPoint{x: fe{}, y: cc.f.one, z: fe{}}
}

// fromAffine maps an affine Point (or the affine identity (nil,nil)) to a
// projective Montgomery ctPoint. Setup/boundary helper — not constant-time in
// the infinity branch, which is fine: whether the *base point* is the identity
// is not secret.
func (cc *ctCurve) fromAffine(xCoord, yCoord *big.Int) ctPoint {
	if xCoord == nil || yCoord == nil {
		return cc.identity()
	}

	f := cc.f
	x := f.toMont(feFromBig(new(big.Int).Mod(xCoord, bigFromFe(f.p))))
	y := f.toMont(feFromBig(new(big.Int).Mod(yCoord, bigFromFe(f.p))))

	return ctPoint{x: x, y: y, z: f.one}
}

// toAffine maps a projective ctPoint back to an affine Point, returning the
// affine identity (nil,nil) when Z == 0. Uses a field inversion (Z^{-1}).
func (cc *ctCurve) toAffine(p ctPoint) (*big.Int, *big.Int) {
	f := cc.f

	if feEqual(p.z, fe{}) {
		return nil, nil // identity.
	}

	zinv := f.inv(p.z)
	x := f.fromMont(f.mul(p.x, zinv))
	y := f.fromMont(f.mul(p.y, zinv))

	return bigFromFe(x), bigFromFe(y)
}

// toRaw serialises the shared affine point without converting SECRET
// coordinates to math/big. GoGOST PublicKey.Raw() is little-endian X || Y.
func (cc *ctCurve) toRaw(p ctPoint) ([64]byte, bool) {
	var raw [64]byte
	if feEqual(p.z, fe{}) {
		return raw, false
	}
	f := cc.f
	zinv := f.inv(p.z)
	x := f.fromMont(f.mul(p.x, zinv))
	y := f.fromMont(f.mul(p.y, zinv))
	for i := 0; i < ctLimbs; i++ {
		binary.LittleEndian.PutUint64(raw[i*8:(i+1)*8], x[i])
		binary.LittleEndian.PutUint64(raw[32+i*8:32+(i+1)*8], y[i])
	}
	return raw, true
}

// add returns P + Q via the complete addition formula (add-2015-rcb).
func (cc *ctCurve) add(p, q ctPoint) ctPoint {
	f, a, b3 := cc.f, cc.a, cc.b3
	x1, y1, z1 := p.x, p.y, p.z
	x2, y2, z2 := q.x, q.y, q.z

	t0 := f.mul(x1, x2)
	t1 := f.mul(y1, y2)
	t2 := f.mul(z1, z2)
	t3 := f.add(x1, y1)
	t4 := f.add(x2, y2)

	t3 = f.mul(t3, t4)
	t4 = f.add(t0, t1)
	t3 = f.sub(t3, t4)
	t4 = f.add(x1, z1)

	t5 := f.add(x2, z2)

	t4 = f.mul(t4, t5)
	t5 = f.add(t0, t2)
	t4 = f.sub(t4, t5)
	t5 = f.add(y1, z1)

	x3 := f.add(y2, z2)

	t5 = f.mul(t5, x3)
	x3 = f.add(t1, t2)
	t5 = f.sub(t5, x3)

	z3 := f.mul(a, t4)

	x3 = f.mul(b3, t2)
	z3 = f.add(x3, z3)
	x3 = f.sub(t1, z3)
	z3 = f.add(t1, z3)

	y3 := f.mul(x3, z3)

	t1 = f.add(t0, t0)
	t1 = f.add(t1, t0)
	t2 = f.mul(a, t2)
	t4 = f.mul(b3, t4)
	t1 = f.add(t1, t2)
	t2 = f.sub(t0, t2)
	t2 = f.mul(a, t2)
	t4 = f.add(t4, t2)
	t0 = f.mul(t1, t4)
	y3 = f.add(y3, t0)
	t0 = f.mul(t5, t4)
	x3 = f.mul(t3, x3)
	x3 = f.sub(x3, t0)
	t0 = f.mul(t3, t1)
	z3 = f.mul(t5, z3)
	z3 = f.add(z3, t0)

	return ctPoint{x: x3, y: y3, z: z3}
}

// double returns 2·P via the complete doubling formula (dbl-2015-rcb).
func (cc *ctCurve) double(p ctPoint) ctPoint {
	f, a, b3 := cc.f, cc.a, cc.b3
	x1, y1, z1 := p.x, p.y, p.z

	t0 := f.sqr(x1)
	t1 := f.sqr(y1)
	t2 := f.sqr(z1)
	t3 := f.mul(x1, y1)

	t3 = f.add(t3, t3)

	z3 := f.mul(x1, z1)

	z3 = f.add(z3, z3)

	x3 := f.mul(a, z3)
	y3 := f.mul(b3, t2)

	y3 = f.add(x3, y3)
	x3 = f.sub(t1, y3)
	y3 = f.add(t1, y3)
	y3 = f.mul(x3, y3)
	x3 = f.mul(t3, x3)
	z3 = f.mul(b3, z3)
	t2 = f.mul(a, t2)
	t3 = f.sub(t0, t2)
	t3 = f.mul(a, t3)
	t3 = f.add(t3, z3)
	z3 = f.add(t0, t0)
	t0 = f.add(z3, t0)
	t0 = f.add(t0, t2)
	t0 = f.mul(t0, t3)
	y3 = f.add(y3, t0)
	t2 = f.mul(y1, z1)
	t2 = f.add(t2, t2)
	t0 = f.mul(t2, t3)
	x3 = f.sub(x3, t0)
	z3 = f.mul(t2, t1)
	z3 = f.add(z3, z3)
	z3 = f.add(z3, z3)

	return ctPoint{x: x3, y: y3, z: z3}
}

// cswap conditionally swaps p and q when bit == 1, branch-free.
func (cc *ctCurve) cswap(bit uint64, p, q *ctPoint) {
	mask := ctMask(bit)
	for i := 0; i < ctLimbs; i++ {
		dx := mask & (p.x[i] ^ q.x[i])

		p.x[i] ^= dx
		q.x[i] ^= dx

		dy := mask & (p.y[i] ^ q.y[i])

		p.y[i] ^= dy
		q.y[i] ^= dy

		dz := mask & (p.z[i] ^ q.z[i])

		p.z[i] ^= dz
		q.z[i] ^= dz
	}
}
