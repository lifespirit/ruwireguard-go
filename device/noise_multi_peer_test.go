// SPDX-License-Identifier: MIT
package device

import (
	"fmt"
	"sync"
	"testing"
)

// All initiators target the same responder device. This exercises the shared
// TC26 curve, index table and handshake workers with different peer sessions.
func TestConcurrentIndependentGOSTHandshakes(t *testing.T) {
	const peers = 6
	responder := randDevice(t)
	defer responder.Close()

	type session struct {
		initiator *Device
		initPeer *Peer
		respPeer *Peer
	}
	sessions := make([]session, 0, peers)
	for i := 0; i < peers; i++ {
		initiator := randDevice(t)
		defer initiator.Close()
		remote, err := initiator.NewPeer(responder.staticIdentity.publicKey)
		if err != nil {
			t.Fatal(err)
		}
		local, err := responder.NewPeer(initiator.staticIdentity.publicKey)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session{initiator, remote, local})
	}

	var wg sync.WaitGroup
	errs := make(chan error, peers)
	start := make(chan struct{})
	for i, session := range sessions {
		wg.Add(1)
		go func(i int, s session) {
			defer wg.Done()
			<-start
			initiation, err := s.initiator.CreateMessageInitiation(s.initPeer)
			if err != nil {
				errs <- fmt.Errorf("peer %d initiation: %w", i, err)
				return
			}
			if responder.ConsumeMessageInitiation(initiation) != s.respPeer {
				errs <- fmt.Errorf("peer %d initiation rejected", i)
				return
			}
			response, err := responder.CreateMessageResponse(s.respPeer)
			if err != nil {
				errs <- fmt.Errorf("peer %d response: %w", i, err)
				return
			}
			if s.initiator.ConsumeMessageResponse(response) != s.initPeer {
				errs <- fmt.Errorf("peer %d response rejected", i)
				return
			}
			if err := s.respPeer.BeginSymmetricSession(); err != nil {
				errs <- fmt.Errorf("peer %d responder session: %w", i, err)
				return
			}
			if err := s.initPeer.BeginSymmetricSession(); err != nil {
				errs <- fmt.Errorf("peer %d initiator session: %w", i, err)
				return
			}
			if s.initPeer.keypairs.current == nil || s.respPeer.keypairs.loadNext() == nil {
				errs <- fmt.Errorf("peer %d failed to derive both traffic keys", i)
			}
		}(i, session)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// The PSK is mixed into the response authentication transcript. Two peers
// using different PSKs must not complete the authenticated handshake.
func TestGOSTHandshakeRejectsMismatchedPSK(t *testing.T) {
	initiator, responder, initiatorPeer, responderPeer, msg := setupValidationHandshake(t)
	for i := range responderPeer.handshake.presharedKey {
		responderPeer.handshake.presharedKey[i] = byte(i + 1)
		initiatorPeer.handshake.presharedKey[i] = byte(i + 2)
	}
	if responder.ConsumeMessageInitiation(msg) != responderPeer {
		t.Fatal("valid initiation was rejected")
	}
	reply, err := responder.CreateMessageResponse(responderPeer)
	if err != nil {
		t.Fatal(err)
	}
	if got := initiator.ConsumeMessageResponse(reply); got != nil {
		t.Fatal("response with mismatched PSK authenticated")
	}
}
