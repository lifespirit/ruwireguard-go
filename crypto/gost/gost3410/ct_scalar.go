// SPDX-License-Identifier: BSD-2-Clause
// Adapted from github.com/bigbes/gostcrypto (2026), BSD-2-Clause.
// Fixed-limb Montgomery arithmetic and complete RCB formulas.
// See CT_THIRD_PARTY_LICENSE.txt for copyright/attribution.
// EXPERIMENTAL: not independently audited in Ru-WireGuard-Go.
package gost3410

import (
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
)

func ctMask(selector uint64) uint64 { return uint64(0) - (selector & 1) }

func ctEq(a, b uint64) uint64 {
	d := a ^ b
	return ((d | (0 - d)) >> 63) - 1
}

// Contexts contain only PUBLIC curve constants. The legacy Curve.Exp copies
// its Curve for scratch space, so do not put a sync.Once inside Curve itself.
var ctContexts sync.Map

func context256(c *Curve) *ctCurve {
	if v, ok := ctContexts.Load(c); ok {
		return v.(*ctCurve)
	}
	created := newCTCurve(c)
	v, _ := ctContexts.LoadOrStore(c, created)
	return v.(*ctCurve)
}

// validScalarFixed256 compares a fixed 32-byte big-endian secret against the
// public subgroup order. It never passes the scalar through math/big.
func (c *Curve) validScalarFixed256(k []byte) bool {
	if c == nil || c.Q == nil || len(k) != 32 || c.Q.BitLen() > 256 {
		return false
	}
	var order [32]byte
	c.Q.FillBytes(order[:])
	var less, greater uint64
	var nonzero byte
	for i := 0; i < 32; i++ {
		a, b := uint64(k[i]), uint64(order[i])
		unset := 1 ^ (less | greater)
		less |= unset & ((a - b) >> 63)
		greater |= unset & ((b - a) >> 63)
		nonzero |= k[i]
	}
	return nonzero != 0 && less == 1
}

// multiplyFixed256Projective carries private scalar operations entirely in
// fixed-size limbs and returns only projective coordinates (not math/big).
func (c *Curve) multiplyFixed256Projective(k []byte, x, y *big.Int, factor *big.Int) (*ctCurve, ctPoint, error) {
	if c == nil || c.P == nil || c.Q == nil || c.P.BitLen() > 256 || !c.validScalarFixed256(k) {
		return nil, ctPoint{}, errors.New("gost3410: invalid 256-bit private scalar")
	}
	if x == nil || y == nil {
		return nil, ctPoint{}, errors.New("gost3410: missing point")
	}
	cc := context256(c)
	p := cc.scalarMultLimbs(scalarBytesToLimbs(k), cc.fromAffine(x, y))
	if factor != nil && factor.Cmp(bigInt1) != 0 {
		// factor is PUBLIC (UKM * cofactor). Reducing it through big.Int does
		// not reveal private scalar bits or private point coordinates.
		reduced := new(big.Int).Mod(new(big.Int).Set(factor), c.Q)
		if reduced.Sign() == 0 {
			return nil, ctPoint{}, errors.New("gost3410: UKM factor maps point to infinity")
		}
		var fixed [32]byte
		reduced.FillBytes(fixed[:])
		p = cc.scalarMultLimbs(scalarBytesToLimbs(fixed[:]), p)
	}
	return cc, p, nil
}

// scalarMultFixed256 returns a PUBLIC point for identity/public-key creation.
// It is not used for serialising shared VKO secrets.
func (c *Curve) scalarMultFixed256(k []byte, x, y *big.Int, factor *big.Int) (*big.Int, *big.Int, error) {
	cc, point, err := c.multiplyFixed256Projective(k, x, y, factor)
	if err != nil {
		return nil, nil, err
	}
	xOut, yOut := cc.toAffine(point)
	if xOut == nil || yOut == nil {
		return nil, nil, errors.New("gost3410: scalar multiplication yielded infinity")
	}
	return xOut, yOut, nil
}

// scalarMultFixed256Raw returns fixed-width LE X || Y directly, without the
// variable-width big.Int.Bytes/FillBytes operations on secret-derived coords.
func (c *Curve) scalarMultFixed256Raw(k []byte, x, y *big.Int, factor *big.Int) ([]byte, error) {
	cc, point, err := c.multiplyFixed256Projective(k, x, y, factor)
	if err != nil {
		return nil, err
	}
	raw, ok := cc.toRaw(point)
	if !ok {
		return nil, errors.New("gost3410: scalar multiplication yielded infinity")
	}
	return raw[:], nil
}

func scalarBytesToLimbs(b []byte) fe {
	var out fe
	for i := 0; i < ctLimbs; i++ {
		out[i] = binary.BigEndian.Uint64(b[(ctLimbs-1-i)*8:])
	}

	return out
}

// ctWindow is the fixed-window width for scalarMult. 4 divides 64, so a window
// digit never straddles a limb boundary.
const ctWindow = 4

// scalarMult returns k·P. k must be in [0, 2^256). It uses a constant-time
// fixed-window method (window ctWindow): a precomputed table 0·P…15·P, selected
// per window with a branch-free table scan, then folded in with w doublings per
// window. This does ~orderBits doublings + ~orderBits/w additions, versus the
// Montgomery ladder's add-and-double on every bit (scalarMultLadder).
// scalarMultLimbs is the core fixed-window multiply over a pre-decoded scalar.
// It touches no big.Int, so with a constant-time decode (scalarBytesToLimbs) the
// whole secret path is branch-free.
func (cc *ctCurve) scalarMultLimbs(kl fe, p ctPoint) ctPoint {
	// Precompute tbl[i] = i·P (projective). tbl[0] is the identity.
	var tbl [1 << ctWindow]ctPoint

	tbl[0] = cc.identity()
	tbl[1] = p

	for i := 2; i < len(tbl); i++ {
		tbl[i] = cc.add(tbl[i-1], p)
	}

	nWin := (cc.orderBits + ctWindow - 1) / ctWindow

	result := cc.identity()

	for wi := nWin - 1; wi >= 0; wi-- {
		// Shift the accumulator left by one window. On the first (top) window
		// result is the identity, so this is a harmless, branch-free no-op.
		for j := 0; j < ctWindow; j++ {
			result = cc.double(result)
		}

		pos := uint(wi * ctWindow)
		digit := (kl[pos>>6] >> (pos & limbBitsMinus1)) & ((1 << ctWindow) - 1)

		result = cc.add(result, cc.selectWindow(&tbl, digit))
	}

	return result
}

// selectWindow returns tbl[digit] in constant time by scanning every entry and
// arithmetic-masking the match — the memory-access pattern is independent of the
// secret digit.
func (cc *ctCurve) selectWindow(tbl *[1 << ctWindow]ctPoint, digit uint64) ctPoint {
	var r ctPoint

	for j := range tbl {
		mask := ctEq(uint64(j), digit)

		r.x = cmov(mask, tbl[j].x, r.x)
		r.y = cmov(mask, tbl[j].y, r.y)
		r.z = cmov(mask, tbl[j].z, r.z)
	}

	return r
}

