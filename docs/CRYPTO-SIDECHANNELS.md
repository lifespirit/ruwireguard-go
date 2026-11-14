# Stage 4: experimental GOST timing-side-channel hardening

**Status: experimental, unaudited. Do not infer production-grade constant-time
security from passing unit tests or Linux tunnel checks.**

This repository remains **GOST-only**. The wire protocol, TC26 256A curve,
VKO/UKM+cofactor processing, Streebog hashes and Kuznyechik-MGM ciphertexts do
not change. These changes replace implementation internals, not the protocol.

## 256-bit ECC / VKO (default tunnel key exchange)

Before this change, `Curve.Exp` performed a conditional point addition for
each private scalar bit, and each addition performed variable-time
`math/big.ModInverse`. This leaks key-dependent timing information.

The **256-bit** `Curve.ScalarBaseMult` and `Curve.KEK` paths now use:

- canonical fixed-width 32-byte scalar validation, no `math/big` input parsing;
- four 64-bit Montgomery limbs with fixed-iteration field arithmetic;
- complete Renes–Costello–Batina projective point formulas with no
  secret-dependent identity/equal-point special-case branches;
- fixed-window multiplication with a full table scan, mask-selecting the
  matching digit without secret-indexed memory;
- cofactor-4 processing via two unconditional projective point doublings;
- direct fixed-width little-endian serialization for the **shared secret**
  (X || Y) without converting secret-derived coordinates to `math/big.Int`.

The default 256-bit VPN key exchange uses the fixed-width secret path.
`Curve.Exp` remains a variable-time reference for public-scalar operations and
**non-tunnel legacy callers**, including 512-bit GOST code and signing helpers.
No claim is made that all functions in the `gost3410` package are constant-time.

The 256-bit output-to-public-key path still converts a point to `math/big`:
those coordinates are public by design. The VKO shared-secret path does not.

## Kuznyechik

Previously `gosthopper.NewCipher` used amd64 assembly / fused tables indexed
by secret-dependent state bytes. The cookie cipher also used a key-dependent
S-box lookup. Now both VPN handshake and cookie/payload AEAD paths use the
hardened `crypto/gost/gost3412128.NewCipher` implementation.

That implementation applies:

- 256-element **public-order** S-box scans using SWAR masks for all 16 bytes;
- fixed-public-index, branchless bit-column scans for the L and inverse-L
  transforms;
- the same operations during the **key schedule**, not only data encryption.

The old exported `gosthopper.DoEncrypt`, `DoDecrypt`, and the low-level
legacy GOSTHopper table functions remain for backwards compatibility and
reference parity tests; they are **not** suitable for protecting secret
material against a local timing/cache adversary. Call `NewCipher` instead.

The data-independent implementation may be significantly slower. Measure
before use; no performance target or hardware acceleration is guaranteed.

## Validation

```sh
go test -mod=vendor -count=1 ./...
go test -mod=vendor -race -count=1 -run '^TestCT256ScalarAndVKOReferenceParity$' ./crypto/gost/gost3410
go test -mod=vendor -count=1 -run '^TestCTKuznyechik|^TestHardenedBlockMatchesLegacyKuznyechik$' ./crypto/gost/gost3412128 ./crypto/gosthopper
go test -mod=vendor -run '^$' -bench 'BenchmarkTC26VKO2012_256|BenchmarkKuznyechikCTEncrypt' -benchtime=100ms ./crypto/gost/gost3410 ./crypto/gost/gost3412128
```

Additionally, the project CI tests handshake known-answer vectors, cookie
authentication, MGM, rekey, IPv4/IPv6 and authenticated roaming. The active
long-lived rekey test from PR #10 remains independent of this branch.

## Still outside the security claim

1. No independent cryptographic review, formal proof, `ctgrind` taint
   verification, cross-architecture compiler inspection, or dudect-style
   statistical timing campaign has been completed **for this fork**.
2. `Curve.Exp`, signing, non-256-bit key agreement, and direct legacy
   `gosthopper.DoEncrypt` calls are still variable-time.
3. Streebog/HMAC, MGM orchestration, RNG behavior, parser timing and secret
   lifetimes/zeroization must be separately audited, including data-dependent
   memory accesses outside these new backends.
4. Public-key validation (`UnmarshalCompressed`, subgroup verification)
   still uses `math/big`. Its operand is attacker-controlled **public** input;
   consider denial-of-service limits separately.
5. Experimental fixed-limb code is security-sensitive. Correctness parity and
   unit/race tests are necessary, but not sufficient, to use it for secrets.

## Third-party attribution

Adapted with modifications from
[bigbes/gostcrypto](https://github.com/bigbes/gostcrypto), BSD-2-Clause, June
2026. The imported fixed-limb/complete-point sources and their blob SHAs plus
the full copyright notice are recorded in
`crypto/gost/gost3410/CT_THIRD_PARTY_LICENSE.txt`. The hardened Kuznyechik
SWAR selection / bit-column pattern is adapted from
`kuznyechik/ctkuznyechik.go` (blob `27d6d037a44b40afd98ebb37b25ecc498976ff01`).
These external implementations describe their constant-time properties as
**experimental**, not a certification for this fork.
