// SPDX-License-Identifier: MIT
//
// Tests for imported and directly configured Ru-WireGuard private scalars.
package device

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"
)

func TestGOSTPrivateKeyScalarImport(t *testing.T) {
	bigEndian := func(value *big.Int) []byte {
		return value.FillBytes(make([]byte, NoisePrivateKeySize))
	}
	cases := []struct {
		name  string
		value *big.Int
		valid bool
	}{
		{"zero-reset", big.NewInt(0), true},
		{"one", big.NewInt(1), true},
		{"q-minus-one", new(big.Int).Sub(curve.Q, big.NewInt(1)), true},
		{"q", new(big.Int).Set(curve.Q), false},
		{"q-plus-one", new(big.Int).Add(curve.Q, big.NewInt(1)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := hex.EncodeToString(gost3410.Reversed(bigEndian(tc.value)))
			// Check that failed parsing leaves a previously populated key
			// unchanged, instead of overwriting it with attacker input.
			var sk NoisePrivateKey
			sk[len(sk)-1] = 1
			before := sk
			err := sk.FromMaybeZeroHex(input)
			if (err == nil) != tc.valid {
				t.Fatalf("FromMaybeZeroHex validity: err=%v wantValid=%v", err, tc.valid)
			}
			if !tc.valid {
				if sk != before {
					t.Fatal("failed scalar import overwrote the existing key")
				}
				return
			}
			if !bytes.Equal(sk[:], bigEndian(tc.value)) {
				t.Fatalf("scalar endianness mismatch: got %x", sk)
			}
			if sk.ToHex() != input {
				t.Fatal("GOST key did not roundtrip through external format")
			}
		})
	}
}

func TestRejectOutOfRangePrivateScalarAtDeviceBoundary(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()
	invalidBigEndian := new(big.Int).Set(curve.Q).FillBytes(make([]byte, NoisePrivateKeySize))
	var invalid NoisePrivateKey
	copy(invalid[:], invalidBigEndian)

	if err := dev.SetPrivateKey(invalid); err == nil {
		t.Fatal("SetPrivateKey accepted invalid scalar Q")
	}
	if got := invalid.PublicKey(); got != (NoisePublicKey{}) {
		t.Fatal("invalid private scalar returned a public key")
	}
	if got := invalid.SharedSecret(dev.staticIdentity.publicKey); len(got) != 0 {
		t.Fatal("invalid private scalar produced a VKO shared secret")
	}
}

func TestGOSTGenerationProducesCanonicalScalars(t *testing.T) {
	for i := 0; i < 16; i++ {
		sk, err := newNoisePrivateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !gost3410.ValidScalar(curve, sk[:]) {
			t.Fatalf("generated noncanonical scalar: %x", sk)
		}
		if pk := sk.PublicKey(); pk == (NoisePublicKey{}) {
			t.Fatal("canonical key produced empty public key")
		}
	}
}
