// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2020 Sergey Matveev <stargrave@stargrave.org>
// Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
// Copyright (C) 2026 Contributors.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.

package mgm

import "encoding/binary"

// mul computes multiplication in GF(2^128) using the MGM reduction
// polynomial x^128 + x^7 + x^2 + x + 1. Operands are big-endian.
//
// Unlike the old math/big implementation this loop always executes
// 128 iterations. Neither branch counts nor iteration counts depend on
// operand bits. This is NOT a claim that the entire Kuznyechik-MGM
// implementation is constant-time: the block cipher requires a separate
// side-channel assessment.
func (mgm *MGM) mul(xBuf, yBuf []byte) []byte {
	xHi := binary.BigEndian.Uint64(xBuf[:8])
	xLo := binary.BigEndian.Uint64(xBuf[8:16])
	yHi := binary.BigEndian.Uint64(yBuf[:8])
	yLo := binary.BigEndian.Uint64(yBuf[8:16])

	var zHi, zLo uint64
	for i := 0; i < 128; i++ {
		// z ^= x iff the low bit of y is 1, without secret branches.
		mask := uint64(0) - (yLo & 1)
		zHi ^= xHi & mask
		zLo ^= xLo & mask

		// x <- x * t mod (t^128 + t^7 + t^2 + t + 1).
		carry := xHi >> 63
		xHi = (xHi << 1) | (xLo >> 63)
		xLo = (xLo << 1) ^ (uint64(0x87) & (uint64(0) - carry))

		// Shift y towards its least significant bit.
		yLo = (yLo >> 1) | (yHi << 63)
		yHi >>= 1
	}

	var out [16]byte
	binary.BigEndian.PutUint64(out[:8], zHi)
	binary.BigEndian.PutUint64(out[8:], zLo)
	return out[:]
}
