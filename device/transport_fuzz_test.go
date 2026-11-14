// SPDX-License-Identifier: MIT
package device

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3412128"
	"github.com/bi-zone/ruwireguard-go/crypto/mgm"
)

// FuzzGOSTTransportDatagram covers the fixed-size UDP transport header,
// derived packet nonce, 12-byte associated data and MGM authentication.
// It does not replace the end-to-end receiver/replay tests.
func FuzzGOSTTransportDatagram(f *testing.F) {
	var key [AEADSymmetricKeySize]byte
	aead, err := mgm.NewMGM(gost3412128.NewCipher(key[:]))
	if err != nil {
		f.Fatal(err)
	}
	const localIndex uint32 = 7
	const remoteIndex uint32 = 12
	var header [MessageTransportHeaderSize]byte
	binary.LittleEndian.PutUint32(header[0:4], MessageTransportType)
	binary.LittleEndian.PutUint32(header[4:8], localIndex)
	binary.LittleEndian.PutUint64(header[8:16], 5)
	var aad [AdditionalDataSize]byte
	binary.LittleEndian.PutUint32(aad[0:4], MessageTransportType)
	binary.LittleEndian.PutUint32(aad[4:8], remoteIndex)
	binary.LittleEndian.PutUint32(aad[8:12], localIndex)
	var nonce [AEADNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[8:], 5)
	valid := append(header[:], aead.Seal(nil, nonce[:], []byte("IP packet"), aad[:])...)
	f.Add(valid)
	f.Add([]byte{})
	f.Add(header[:])
	bad := append([]byte(nil), valid...)
	bad[len(bad)-1] ^= 1
	f.Add(bad)

	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) < MessageTransportSize || len(packet) > MaxMessageSize {
			return // Drop before handing a packet to the decryption queue.
		}
		if binary.LittleEndian.Uint32(packet[:4]) != MessageTransportType {
			return
		}
		var n [AEADNonceSize]byte
		copy(n[8:], packet[MessageTransportOffsetCounter:MessageTransportOffsetContent])
		var associated [AdditionalDataSize]byte
		binary.LittleEndian.PutUint32(associated[0:4], MessageTransportType)
		binary.LittleEndian.PutUint32(associated[4:8], remoteIndex)
		binary.LittleEndian.PutUint32(associated[8:12], localIndex)
		plaintext, err := aead.Open(nil, n[:], packet[MessageTransportOffsetContent:], associated[:])
		if err != nil {
			if plaintext != nil {
				t.Fatal("transport authentication failure returned plaintext")
			}
			return
		}
		if !bytes.Equal(aead.Seal(nil, n[:], plaintext, associated[:]), packet[MessageTransportOffsetContent:]) {
			t.Fatal("authenticated transport packet did not round-trip")
		}
	})
}
