// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Contributors.
// Regression tests for fail-closed Ru-WireGuard GOST key agreement.
package device

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestRejectMalformedGOSTPublicKeys(t *testing.T) {
	device := randDevice(t)
	defer device.Close()

	private, err := newNoisePrivateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := private.PublicKey()

	var decoded NoisePublicKey
	if err := decoded.FromHex(hex.EncodeToString(valid[:])); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if decoded != valid {
		t.Fatal("decoded GOST public key changed")
	}

	var badPrefix = valid
	badPrefix[0] = 4 // ANSI X9.62 uncompressed format is not allowed.
	var outOfRangeX NoisePublicKey
	outOfRangeX[0] = 2
	curve.P.FillBytes(outOfRangeX[1:])

	for name, key := range map[string]NoisePublicKey{
		"zero":           {},
		"bad-prefix":     badPrefix,
		"x-out-of-range": outOfRangeX,
	} {
		t.Run(name, func(t *testing.T) {
			var parsed NoisePublicKey
			if err := parsed.FromHex(hex.EncodeToString(key[:])); err == nil {
				t.Fatal("malformed GOST public key accepted by FromHex")
			}
			if parsed != (NoisePublicKey{}) {
				t.Fatal("invalid key partially installed after failed parse")
			}
			if peer, err := device.NewPeer(key); err == nil || peer != nil {
				t.Fatalf("NewPeer accepted malformed key: peer=%v err=%v", peer, err)
			}
		})
	}

	if err := decoded.FromHex("not hex"); err == nil {
		t.Fatal("invalid hex accepted")
	}
	if err := decoded.FromHex("02"); err == nil {
		t.Fatal("truncated compressed key accepted")
	}
}

func TestZeroGOSTPrivateKeyCannotAgree(t *testing.T) {
	valid, err := newNoisePrivateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var zero NoisePrivateKey
	if secret := zero.SharedSecret(valid.PublicKey()); len(secret) != 0 {
		t.Fatalf("zero private key generated %d-byte shared secret", len(secret))
	}
}

func setupValidationHandshake(t *testing.T) (*Device, *Device, *Peer, *Peer, *MessageInitiation) {
	t.Helper()
	initiator := randDevice(t)
	responder := randDevice(t)
	t.Cleanup(func() {
		initiator.Close()
		responder.Close()
	})

	initiatorPeer, err := initiator.NewPeer(responder.staticIdentity.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	responderPeer, err := responder.NewPeer(initiator.staticIdentity.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := initiator.CreateMessageInitiation(initiatorPeer)
	if err != nil {
		t.Fatal(err)
	}
	return initiator, responder, initiatorPeer, responderPeer, msg
}

func TestRejectMalformedGOSTInitiation(t *testing.T) {
	_, responder, _, responderPeer, msg := setupValidationHandshake(t)

	corrupt := *msg
	corrupt.Ephemeral[0] = 4
	if peer := responder.ConsumeMessageInitiation(&corrupt); peer != nil {
		t.Fatal("accepted initiation with invalid ephemeral key")
	}
	if got := responder.ConsumeMessageInitiation(msg); got != responderPeer {
		t.Fatal("valid initiation rejected after malformed one")
	}
	if peer := responder.ConsumeMessageInitiation(nil); peer != nil {
		t.Fatal("nil initiation accepted")
	}
}

func TestRejectMalformedGOSTResponse(t *testing.T) {
	for name, mutate := range map[string]func(*MessageResponse){
		"invalid-ephemeral": func(msg *MessageResponse) { msg.Ephemeral[0] = 4 },
		"invalid-auth-tag": func(msg *MessageResponse) { msg.Empty[0] ^= 0x80 },
	} {
		t.Run(name, func(t *testing.T) {
			initiator, responder, initiatorPeer, responderPeer, msg := setupValidationHandshake(t)
			if responder.ConsumeMessageInitiation(msg) != responderPeer {
				t.Fatal("valid initiation rejected")
			}
			response, err := responder.CreateMessageResponse(responderPeer)
			if err != nil {
				t.Fatal(err)
			}
			corrupt := *response
			mutate(&corrupt)
			if peer := initiator.ConsumeMessageResponse(&corrupt); peer != nil {
				t.Fatal("accepted malformed response")
			}
			if peer := initiator.ConsumeMessageResponse(response); peer != initiatorPeer {
				t.Fatal("valid response rejected after malformed response")
			}
			if peer := initiator.ConsumeMessageResponse(nil); peer != nil {
				t.Fatal("nil response accepted")
			}
		})
	}
}

func TestCreateGOSTResponseRejectsInvalidVKO(t *testing.T) {
	initiator, responder, initiatorPeer, responderPeer, msg := setupValidationHandshake(t)
	if responder.ConsumeMessageInitiation(msg) != responderPeer {
		t.Fatal("valid initiation rejected")
	}
	handshake := &responderPeer.handshake
	handshake.mutex.Lock()
	validEphemeral := handshake.remoteEphemeral
	handshake.remoteEphemeral = NoisePublicKey{} // Simulate invalid handshake state.
	handshake.mutex.Unlock()

	if response, err := responder.CreateMessageResponse(responderPeer); err == nil || response != nil {
		t.Fatalf("invalid VKO result accepted: response=%v err=%v", response, err)
	}

	handshake.mutex.Lock()
	handshake.remoteEphemeral = validEphemeral
	handshake.mutex.Unlock()
	response, err := responder.CreateMessageResponse(responderPeer)
	if err != nil {
		t.Fatalf("valid handshake could not recover after invalid state: %v", err)
	}
	if peer := initiator.ConsumeMessageResponse(response); peer != initiatorPeer {
		t.Fatal("recovered response failed transcript authentication")
	}
}
