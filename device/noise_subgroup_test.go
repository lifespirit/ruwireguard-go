// SPDX-License-Identifier: GPL-3.0-or-later
//
// Regression tests for rejecting on-curve, off-subgroup GOST peer keys.
package device

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func subgroupCompressedKey(t *testing.T, encoded string) NoisePublicKey {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != NoisePublicKeySize {
		t.Fatal("invalid low-order public-key fixture size")
	}
	var key NoisePublicKey
	copy(key[:], raw)
	return key
}

func TestRejectLowOrderGOSTPeersAndHandshakePackets(t *testing.T) {
	const (
		order2 = "020100fe73f595ff158e974b44d478d9588744fe5c192ac47ea63075dce7a14aaa"
		order4 = "037f7f80c60535007538b45a5d95c39353bc5d80d1f36a9dc0ace7c5118c2f5977"
	)

	for _, tc := range []struct{ name, encoded string }{
		{"order-2", order2},
		{"order-4", order4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := subgroupCompressedKey(t, tc.encoded)
			// Verify these fixtures really are on the curve (rather than
			// invalid encodings), independently from the subgroup check.
			x, y := newGOSTPointFromRaw(t, key)
			if !curve.IsOnCurve(x, y) {
				t.Fatal("low-order fixture is not on the curve")
			}
			if curve.IsInPrimeOrderSubgroup(x, y) {
				t.Fatal("low-order test fixture unexpectedly in subgroup")
			}

			var parsed NoisePublicKey
			if err := parsed.FromHex(tc.encoded); err == nil {
				t.Fatal("FromHex accepted low-order public key")
			}

			initiator, responder, _, _, initiation := setupValidationHandshake(t)
			if peer, err := initiator.NewPeer(key); err == nil || peer != nil {
				t.Fatal("NewPeer accepted low-order static key")
			}
			corruptInit := *initiation
			corruptInit.Ephemeral = key
			if peer := responder.ConsumeMessageInitiation(&corruptInit); peer != nil {
				t.Fatal("accepted low-order ephemeral initiation key")
			}
			if secret := initiator.staticIdentity.privateKey.SharedSecret(key); len(secret) != 0 {
				t.Fatal("low-order VKO peer key produced a shared secret")
			}
		})
	}
}

// Decode coordinates for testing without using the public subgroup validator.
// The order-2 point has y=0; the order-4 coordinates are the independently
// generated point for the well-known x coordinate in the test vector.
func newGOSTPointFromRaw(t *testing.T, key NoisePublicKey) (*big.Int, *big.Int) {
	t.Helper()
	x := new(big.Int).SetBytes(key[1:])
	switch key[0] {
	case 2:
		return x, big.NewInt(0)
	case 3:
		y, _ := new(big.Int).SetString("7e7e82520f9f015faa1d0f18c14ab9fb35188275da3fd94206b74f34a48e0ecd", 16)
		return x, y
	default:
		t.Fatal("unexpected test key prefix")
		return nil, nil
	}
}
