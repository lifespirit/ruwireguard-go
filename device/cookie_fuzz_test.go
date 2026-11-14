// SPDX-License-Identifier: MIT
package device

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// FuzzGOSTCookieReplyWire exercises decoding and authentication of a
// network-origin cookie reply, including malformed nonce high bits and tags.
func FuzzGOSTCookieReplyWire(f *testing.F) {
	sk, err := newNoisePrivateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	var generator CookieGenerator
	var checker CookieChecker
	generator.Init(sk.PublicKey())
	checker.Init(sk.PublicKey())
	var initiation [MessageInitiationSize]byte
	generator.AddMacs(initiation[:])
	goodReply, err := checker.CreateReply(initiation[:], 7, []byte{127, 0, 0, 1})
	if err != nil {
		f.Fatal(err)
	}
	var buffer bytes.Buffer
	if err = binary.Write(&buffer, binary.LittleEndian, goodReply); err != nil {
		f.Fatal(err)
	}
	if buffer.Len() != MessageCookieReplySize {
		f.Fatalf("unexpected cookie reply size: %d", buffer.Len())
	}
	f.Add(buffer.Bytes())
	f.Add([]byte{})
	bad := *goodReply
	bad.Nonce[0] |= 0x80
	buffer.Reset()
	if err = binary.Write(&buffer, binary.LittleEndian, &bad); err != nil {
		f.Fatal(err)
	}
	f.Add(buffer.Bytes())

	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) != MessageCookieReplySize {
			return // RoutineReceiveIncoming rejects mismatched datagram sizes.
		}
		var msg MessageCookieReply
		if err := binary.Read(bytes.NewReader(packet), binary.LittleEndian, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Type != MessageCookieReplyType {
			return
		}
		generator.ConsumeReply(&msg) // Must never panic for untrusted input.
	})
}
