# Security and resilience test plan

This repository is an experimental GOST-only userspace VPN. These tests add regression coverage; they do **not** certify resistance to timing attacks or prove production safety.

## Unit tests and concurrency

Use the fork's vendored dependencies:

```sh
go test -mod=vendor -count=1 ./...
go test -mod=vendor -race -count=2 -run '^Test(ConcurrentIndependentGOSTHandshakes|GOSTHandshakeRejectsMismatchedPSK|ConcurrentGOSTInitiationReplay|ConcurrentGOSTResponseReplay)$' ./device
```

The independent-peer test creates six initiators negotiating concurrently with one responder. Replay tests reject concurrent duplicate handshakes. A negative test requires mismatched preshared keys to fail authentication.

## Fuzzing

Each fuzz target runs its seed corpus during ordinary `go test`. To actually mutate inputs, run **one target per command**:

```sh
go test -mod=vendor -run '^$' -fuzz '^FuzzMGMOpen$' -fuzztime=30s -parallel=2 ./crypto/mgm
go test -mod=vendor -run '^$' -fuzz '^FuzzMGMRejectsModifiedTag$' -fuzztime=30s -parallel=2 ./crypto/mgm
go test -mod=vendor -run '^$' -fuzz '^FuzzGOSTCookieReplyWire$' -fuzztime=30s -parallel=2 ./device
go test -mod=vendor -run '^$' -fuzz '^FuzzGOSTInitiationWire$' -fuzztime=30s -parallel=2 ./device
go test -mod=vendor -run '^$' -fuzz '^FuzzGOSTResponseWire$' -fuzztime=30s -parallel=2 ./device
go test -mod=vendor -run '^$' -fuzz '^FuzzGOSTTransportDatagram$' -fuzztime=30s -parallel=2 ./device
```

Fuzz targets cover arbitrary MGM nonces/ciphertexts/AAD, authentication tag tampering, binary decoding and cryptographic acceptance of initiation and response messages, malformed cookie replies and transport header/counter/tag framing. Each input is length-bounded; initiation/response fuzzing uses fresh handshake state for each matching packet.

Any findings saved under `testdata/fuzz/` should be kept as regression inputs and reproduced by a normal unit test. The short CI fuzz run (3 seconds per target) is only a smoke test. Longer runs and coverage-guided campaigns need dedicated hardware and time.

## Real Linux namespace tunnel testing

Requires `root`, `iproute2`, `iputils`, a working `/dev/net/tun`, and the binaries built **from this repository**:

```sh
mkdir -p bin
go build -mod=vendor -o bin/ruwireguard-go .
go build -mod=vendor -o bin/ruwg ./cmd/wgctrl
sudo bash tests/smoke-gost-netns.sh ./bin/ruwireguard-go ./bin/ruwg
```

The test creates two namespaces and a direct veth underlay; it verifies both directions of IPv4/IPv6 over GOST, handshake timestamps, authenticated UDP endpoint roaming and a deliberate underlay link outage followed by **automatic** traffic recovery without restarting the daemons. Both daemons must remain alive.

To run the **real 120-second time-based rekey** (without changing production timeouts):

```sh
sudo RUWG_TEST_REKEY=1 bash tests/smoke-gost-netns.sh ./bin/ruwireguard-go ./bin/ruwg
```

The script generates traffic every five seconds for up to 210 seconds and requires newer authenticated handshake timestamps on **both** peers, followed by IPv4/IPv6 traffic. This tests timed rekey, not merely manual generation of a new keypair. In GitHub Actions, the extended job runs on PRs and is opt-in using `workflow_dispatch` with `long_rekey=true`.

## Remaining gaps

- Fuzzing is not a substitute for full integration coverage of queue scheduling and packet loss under sustained adversarial load.
- Side-channel resistance of `math/big` ECC and Kuznyechik lookup tables remains unverified.
- Multi-day soak tests, sustained throughput, variable MTU, NAT variants, and external cross-implementation interoperability are not established.
- Do not deploy to protect production secrets without an independent audit.
