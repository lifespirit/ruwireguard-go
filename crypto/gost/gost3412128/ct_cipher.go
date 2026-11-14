// SPDX-License-Identifier: BSD-2-Clause
// Adapted from github.com/bigbes/gostcrypto/kuznyechik/ctkuznyechik.go.
// The original BSD-2-Clause notice is in the neighboring ECC license file,
// crypto/gost/gost3410/CT_THIRD_PARTY_LICENSE.txt.
// Experimental, unaudited constant-address Kuznyechik data path.
package gost3412128

import "encoding/binary"

// The S-box is scanned in PUBLIC order. Every byte of the 128-bit block is
// matched simultaneously using two 64-bit lanes, avoiding any secret-indexed
// memory accesses. The final L and inverse-L transforms use fixed-bit columns.
type ctColumn struct {
	hi, lo uint64
}

var (
	ctForwardColumns [BlockSize][8]ctColumn
	ctInverseColumns [BlockSize][8]ctColumn
)

func init() {
	// Inputs to the reference L functions are public basis bits only.
	for pos := 0; pos < BlockSize; pos++ {
		for bit := 0; bit < 8; bit++ {
			var forward [BlockSize]byte
			forward[pos] = 1 << uint(bit)
			l(&forward, 16)
			ctForwardColumns[pos][bit] = ctColumn{
				binary.BigEndian.Uint64(forward[:8]),
				binary.BigEndian.Uint64(forward[8:]),
			}
			var inverse [BlockSize]byte
			inverse[pos] = 1 << uint(bit)
			lInv(&inverse)
			ctInverseColumns[pos][bit] = ctColumn{
				binary.BigEndian.Uint64(inverse[:8]),
				binary.BigEndian.Uint64(inverse[8:]),
			}
		}
	}
}

const (
	swarBroadcastOne uint64 = 0x0101010101010101
	swarLowSeven     uint64 = 0x7f7f7f7f7f7f7f7f
	swarHighBit      uint64 = 0x8080808080808080
)

// ctSbox uses a borrow-safe SWAR zero comparison to produce a per-byte mask.
// The loop indexes the table by a PUBLIC loop counter only.
func ctSbox(hi, lo uint64, table *[256]byte) (uint64, uint64) {
	var outHi, outLo uint64
	for i := 0; i < 256; i++ {
		broadcastIndex := swarBroadcastOne * uint64(i)
		broadcastValue := swarBroadcastOne * uint64(table[i])

		dh := hi ^ broadcastIndex
		mh := ^(((dh & swarLowSeven) + swarLowSeven) | dh) & swarHighBit
		mh >>= 7
		mh |= mh << 1
		mh |= mh << 2
		mh |= mh << 4
		outHi |= broadcastValue & mh

		dl := lo ^ broadcastIndex
		ml := ^(((dl & swarLowSeven) + swarLowSeven) | dl) & swarHighBit
		ml >>= 7
		ml |= ml << 1
		ml |= ml << 2
		ml |= ml << 4
		outLo |= broadcastValue & ml
	}
	return outHi, outLo
}

func ctSelectLinear(hi, lo uint64, columns *[BlockSize][8]ctColumn) (uint64, uint64) {
	var data [BlockSize]byte
	binary.BigEndian.PutUint64(data[:8], hi)
	binary.BigEndian.PutUint64(data[8:], lo)
	var outHi, outLo uint64
	for pos := 0; pos < BlockSize; pos++ {
		b := data[pos]
		for bit := 0; bit < 8; bit++ {
			// A full-word mask selected by a secret bit, with no branch.
			mask := uint64(0) - (uint64(b>>uint(bit)) & 1)
			outHi ^= columns[pos][bit].hi & mask
			outLo ^= columns[pos][bit].lo & mask
		}
	}
	return outHi, outLo
}

func ctSubstitute(block *[BlockSize]byte, table *[256]byte) {
	hi, lo := ctSbox(
		binary.BigEndian.Uint64(block[:8]),
		binary.BigEndian.Uint64(block[8:]),
		table,
	)
	binary.BigEndian.PutUint64(block[:8], hi)
	binary.BigEndian.PutUint64(block[8:], lo)
}

func ctTransform(block *[BlockSize]byte, columns *[BlockSize][8]ctColumn) {
	hi, lo := ctSelectLinear(
		binary.BigEndian.Uint64(block[:8]),
		binary.BigEndian.Uint64(block[8:]),
		columns,
	)
	binary.BigEndian.PutUint64(block[:8], hi)
	binary.BigEndian.PutUint64(block[8:], lo)
}

func ctSubstituteForward(block *[BlockSize]byte) { ctSubstitute(block, &pi) }
func ctSubstituteInverse(block *[BlockSize]byte) { ctSubstitute(block, &piInv) }
func ctLinearForward(block *[BlockSize]byte) { ctTransform(block, &ctForwardColumns) }
func ctLinearInverse(block *[BlockSize]byte) { ctTransform(block, &ctInverseColumns) }
