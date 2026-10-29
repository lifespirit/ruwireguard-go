# Ru-WireGuard-Go modernization roadmap

This fork is a **GOST-only** implementation of Ru-WireGuard. The baseline is
derived from WireGuard-Go v0.0.20201118 and specifies Go 1.15 in `go.mod`.
It must not silently fall back to the standard WireGuard cryptographic suite.

## Required protocol properties

| Function | Protocol algorithm |
| --- | --- |
| Long-term and ephemeral ECDH keys | GOST R 34.10-2012, TC26 256A |
| Key agreement | VKO GOST R 34.10-2012-256 |
| Transcript hash and MAC | Streebog-256; HMAC-Streebog-256 |
| Key derivation | KDF_TREE on HMAC-Streebog-256 |
| Payload and handshake AEAD | Kuznyechik-MGM |

The 33-byte compressed public keys, wire message sizes, labels, nonce layout,
transcript processing and key derivation are part of compatibility. Treat
changes to any of these as protocol changes, not routine refactoring.

## Work plan

### Phase 0: reproducible baseline and crypto concurrency

- [ ] Build and run all unit tests with vendored dependencies on a supported Go toolchain.
- [ ] Run focused regression tests under the Go race detector.
- [ ] Remove data races in concurrent scalar multiplication and VKO (draft PR #1).
- [ ] Inspect Edwards conversion scratch/caches for separate concurrency hazards.

### Phase 1: cryptographic correctness

- [ ] Independent known-answer test vectors for Streebog, HMAC, KDF_TREE, VKO and MGM.
- [ ] Reject invalid private scalars and malformed/off-curve public keys.
- [ ] Verify failure paths for both handshake response directions.
- [ ] Validate MGM nonce uniqueness, tag failure behavior, replay-window and rekey limits.
- [ ] Audit timing side channels in variable-time `math/big` ECC.

### Phase 2: handshake and transport hardening

- [ ] Negative tests for damaged initiation, response, cookie and transport packets.
- [ ] Replay, concurrent initiation, flood limit, roaming and PSK tests.
- [ ] End-to-end two-peer test with full UDP/TUN data transfer.
- [ ] Cross-implementation interoperability only against the same Ru-WireGuard specification.

### Phase 3: modernize userspace networking

- [ ] Inventory changes between the 2020 WireGuard-Go base and maintained upstream.
- [ ] Port network/TUN/UAPI changes incrementally, not by overwriting GOST crypto.
- [ ] Maintain per-change tests and use a protocol-compatibility fixture.
- [ ] Update the Go version, vendored dependencies and automation incrementally.

### Phase 4: operations and performance

- [ ] Linux/Arch packaging, systemd unit and reproducible setup instructions.
- [ ] Ensure users invoke the bundled `wg`, not standard kernel WireGuard tools.
- [ ] Benchmark key agreement, MGM throughput and tunnel performance.
- [ ] Evaluate GOST acceleration independently; do not change crypto wire semantics.

## Security gate

Experimental/unaudited code is not appropriate for protecting production
secrets. Passing unit tests or Go's race detector does not make the protocol
or its cryptographic implementation independently audited or certified.

Reference protocol: https://github.com/bi-zone/ruwireguard-spec
