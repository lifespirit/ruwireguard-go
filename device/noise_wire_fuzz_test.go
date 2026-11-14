// SPDX-License-Identifier: MIT
package device

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzGOSTInitiationWire runs the authenticated responder handshake parser
// against arbitrary fixed-size network messages. It deliberately uses a fresh
// device per matching packet, preventing fuzz inputs from sharing peer state.
func FuzzGOSTInitiationWire(f *testing.F) {
	var initial MessageInitiation
	initial.Type = MessageInitiationType
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, &initial); err != nil {
		f.Fatal(err)
	}
	f.Add(b.Bytes())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) != MessageInitiationSize {
			return
		}
		var msg MessageInitiation
		if err := binary.Read(bytes.NewReader(wire), binary.LittleEndian, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Type != MessageInitiationType {
			return
		}
		_, responder, _, _, _ := setupValidationHandshake(t)
		responder.ConsumeMessageInitiation(&msg)
	})
}

// FuzzGOSTResponseWire forces the receiver index of a decoded response to
// match a live outstanding handshake, so mutated response fields reach the
// ECDH/authentication path rather than being discarded by index lookup.
func FuzzGOSTResponseWire(f *testing.F) {
	var initial MessageResponse
	initial.Type = MessageResponseType
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, &initial); err != nil {
		f.Fatal(err)
	}
	f.Add(b.Bytes())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) != MessageResponseSize {
			return
		}
		var msg MessageResponse
		if err := binary.Read(bytes.NewReader(wire), binary.LittleEndian, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Type != MessageResponseType {
			return
		}
		initiator, _, initiatorPeer, _, _ := setupValidationHandshake(t)
		msg.Receiver = initiatorPeer.handshake.localIndex
		initiator.ConsumeMessageResponse(&msg)
	})
}
