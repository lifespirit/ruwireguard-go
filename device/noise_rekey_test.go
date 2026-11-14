// SPDX-License-Identifier: MIT
//
// GOST handshake lifecycle regression tests. These tests deliberately use
// multiple handshakes with fresh ephemeral keys, without shortening the
// production key-rotation timers.
package device

import (
	"bytes"
	"testing"
)

func TestGOSTSessionRekeyAndKeyRotation(t *testing.T) {
	initiator := randDevice(t)
	responder := randDevice(t)
	defer initiator.Close()
	defer responder.Close()

	initPeer, err := initiator.NewPeer(responder.staticIdentity.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	respPeer, err := responder.NewPeer(initiator.staticIdentity.publicKey)
	if err != nil {
		t.Fatal(err)
	}

	var previousInitiator, previousResponder *Keypair
	var previousCiphertext []byte
	var firstResponse *MessageResponse

	for round := 0; round < 3; round++ {
		init, err := initiator.CreateMessageInitiation(initPeer)
		if err != nil {
			t.Fatalf("round %d: initiation: %v", round, err)
		}
		if peer := responder.ConsumeMessageInitiation(init); peer != respPeer {
			t.Fatalf("round %d: responder rejected initiation", round)
		}
		response, err := responder.CreateMessageResponse(respPeer)
		if err != nil {
			t.Fatalf("round %d: response: %v", round, err)
		}
		if round == 0 {
			firstResponse = response
		}
		if peer := initiator.ConsumeMessageResponse(response); peer != initPeer {
			t.Fatalf("round %d: initiator rejected response", round)
		}
		if err := respPeer.BeginSymmetricSession(); err != nil {
			t.Fatalf("round %d: responder session: %v", round, err)
		}
		if err := initPeer.BeginSymmetricSession(); err != nil {
			t.Fatalf("round %d: initiator session: %v", round, err)
		}

		currentInitiator := initPeer.keypairs.current
		nextResponder := respPeer.keypairs.loadNext()
		if currentInitiator == nil || nextResponder == nil {
			t.Fatalf("round %d: missing newly derived keypair", round)
		}
		if currentInitiator == previousInitiator || nextResponder == previousResponder {
			t.Fatalf("round %d: keypair was not rotated", round)
		}

		var nonce [AEADNonceSize]byte
		plaintext := []byte("GOST session rekey regression")
		ciphertext := currentInitiator.send.Seal(nil, nonce[:], plaintext, nil)
		decrypted, err := nextResponder.receive.Open(nil, nonce[:], ciphertext, nil)
		if err != nil || !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("round %d: new initiator -> responder traffic failed: %v", round, err)
		}
		if round > 0 && bytes.Equal(ciphertext, previousCiphertext) {
			t.Fatalf("round %d: rekey reused the old traffic encryption key", round)
		}
		if round > 0 {
			// A freshly established key must not authenticate traffic
			// encrypted under the previous session's key.
			if _, err := nextResponder.receive.Open(nil, nonce[:], previousCiphertext, nil); err == nil {
				t.Fatalf("round %d: new session accepted previous-session ciphertext", round)
			}
		}
		previousCiphertext = append(previousCiphertext[:0], ciphertext...)

		reverse := nextResponder.send.Seal(nil, nonce[:], plaintext, nil)
		decrypted, err = currentInitiator.receive.Open(nil, nonce[:], reverse, nil)
		if err != nil || !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("round %d: responder -> initiator traffic failed: %v", round, err)
		}

		if !respPeer.ReceivedWithKeypair(nextResponder) {
			t.Fatalf("round %d: responder did not promote the new keypair", round)
		}
		if respPeer.keypairs.current != nextResponder || respPeer.keypairs.loadNext() != nil {
			t.Fatalf("round %d: responder keypair rotation was incomplete", round)
		}

		previousInitiator = currentInitiator
		previousResponder = nextResponder
	}

	if peer := initiator.ConsumeMessageResponse(firstResponse); peer != nil {
		t.Fatal("an old handshake response was accepted after successive rekeys")
	}
}
