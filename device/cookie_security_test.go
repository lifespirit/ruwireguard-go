// SPDX-License-Identifier: MIT
package device

import (
	"crypto/rand"
	"testing"
)

// A cookie reply can arrive from the network without a valid authentication
// tag. It must never terminate the VPN process on a malformed nonce.
func TestCookieReplyRejectsMalformedNonceWithoutPanic(t *testing.T) {
	sk, err := newNoisePrivateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey()
	var checker CookieChecker
	var generator CookieGenerator
	checker.Init(pk)
	generator.Init(pk)

	var request [MessageInitiationSize]byte
	generator.AddMacs(request[:])
	reply, err := checker.CreateReply(request[:], 42, []byte{127, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if generator.ConsumeReply(nil) {
		t.Fatal("nil cookie reply accepted")
	}
	badNonce := *reply
	badNonce.Nonce[0] |= 0x80
	if generator.ConsumeReply(&badNonce) {
		t.Fatal("cookie reply with forbidden MGM nonce bit accepted")
	}
	badTag := *reply
	badTag.Cookie[0] ^= 1
	if generator.ConsumeReply(&badTag) {
		t.Fatal("cookie reply with invalid authentication tag accepted")
	}
	if !generator.mac2.cookieSet.IsZero() {
		t.Fatal("rejected cookie reply modified cookie state")
	}
	if !generator.ConsumeReply(reply) {
		t.Fatal("valid cookie reply rejected after malformed replies")
	}
}
