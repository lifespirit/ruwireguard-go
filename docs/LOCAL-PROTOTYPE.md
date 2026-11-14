# Local Linux Ru-WireGuard GOST prototype

**Status:** experimental userspace test build. Not independently security-audited;
do not use for sensitive or production traffic. This branch contains the stacked
changes from PRs #1, #3, #4 and #5, and is **not** compatible with stock WireGuard.

## One-machine end-to-end test (Arch Linux)

Requirements: Linux, root access to network namespaces/TUN, Go, `iproute2`,
`iputils`, and a `tun` device. **No real network connectivity is required**
after cloning the repository.

```bash
sudo pacman -S --needed go git iproute2 iputils
sudo modprobe tun
git clone https://github.com/lifespirit/ruwireguard-go.git
cd ruwireguard-go
git switch feat/linux-gost-netns-prototype
mkdir -p bin
go build -mod=vendor -o bin/ruwireguard-go .
go build -mod=vendor -o bin/ruwg ./cmd/wgctrl
sudo bash tests/smoke-gost-netns.sh ./bin/ruwireguard-go ./bin/ruwg
```

The smoke test automatically creates **two isolated network namespaces**, two
directly-connected veth underlay endpoints, and two userspace TUN interfaces.
It uses the bundled `ruwg genkey`, `pubkey`, `genpsk`, and `setconf`
commands, then requires successful:
- IPv4 ping in both directions over the encrypted tunnel;
- IPv6 ping in both directions over the encrypted tunnel;
- authenticated handshake timestamps on both peers.

The script cleans up its namespaces, processes, temporary private keys and
UAPI sockets on success or error. If a test fails, daemon logs are printed
before cleanup.

**Important:** do not install or invoke a system `wg` tool in place of
`bin/ruwg`. The bundled tool understands compressed 33-byte GOST public
keys and the Ru-WireGuard control protocol. The Linux `wireguard` kernel
module is not wire-compatible with this build.

For an interactive inspection, run `LOG_LEVEL=debug sudo -E bash
tests/smoke-gost-netns.sh ...` to print daemon logs on failure. Prefer
the regular smoke command first.

## Interoperability and limitations

- The handshake negotiates GOST R 34.10-2012/VKO, Streebog and KDF_TREE;
  tunnel packets are authenticated and encrypted with Kuznyechik-MGM.
- The GOST curve implementation relies on `math/big` and is not constant-time.
- Passing tests does **not** prove resistance to side-channel attacks or
  constitute independent security review/certification.
- This smoke test confirms same-build two-peer interoperability; it does not
  establish compatibility with other implementations, large MTUs, roaming,
  rekey at scale, or performance targets.

## Manual diagnostics

```bash
go test -mod=vendor -count=1 ./...
go test -mod=vendor -race -run '^TestConcurrentExpAndVKO$' ./crypto/gost/gost3410
```

## Rekey, roaming and performance verification

The `test/gost-rekey-roaming-benchmarks` branch extends the two-node
smoke test with **authenticated roaming**: the initiator moves to a new
underlay source IP and UDP port; the responder is intentionally NOT
reconfigured and must automatically learn the new authenticated endpoint.
The script checks IPv4 and IPv6 traffic after the move, then cleans up.

The rekey test performs **three successive GOST handshakes** and verifies
new symmetric keys and rejection of old-session ciphertext. The test
exercises the key rotation *mechanism*, not the production 120-second
automatic rekey timer.

```bash
go test -mod=vendor -count=1 -run '^TestGOSTSessionRekeyAndKeyRotation$' ./device
go test -mod=vendor -race -count=1 -run '^TestGOSTSessionRekeyAndKeyRotation$' ./device

# Run benchmarks on your machine, not just the hosted CI CPU.
go test -mod=vendor -run '^$' -bench '^BenchmarkTC26' \
    -benchmem -benchtime=2s ./crypto/gost/gost3410
go test -mod=vendor -run '^$' -bench '^BenchmarkRuWireGuardKuznyechikMGM' \
    -benchmem -benchtime=2s ./crypto/mgm
```

Benchmarks report operation latency and allocations (`ns/op`, `B/op`,
`allocs/op`). MGM reports effective payload throughput (`MB/s`).
They are not direct VPN throughput estimates; TUN, UDP, routing,
scheduling and IP packet overhead are excluded. Do not interpret
benchmark samples as evidence of constant-time cryptography.

The periodic production rekey deadline and long-duration NAT
convergence require separate soak tests. No production timer is
shortened or made configurable merely to make CI quicker.
