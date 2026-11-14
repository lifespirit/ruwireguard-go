# RuWireGuard-Go
This is a reference implementation of the [Ru-WireGuard](https://github.com/bi-zone/ruwireguard-spec/blob/main/ruwireguard-draft.md) protocol in Go.
 
Ru-WireGuard-Go is a WireGuard-Go [fork](https://github.com/WireGuard/wireguard-go/releases/tag/v0.0.20201118).

It has the same semantics as the original WireGuard protocol but employs the cryptographic algorithms defined
 by the Russian national standards (GOST).
 
## Warnings
- Maturity: The code is experimental. You must not use this in production
- Audit: The code is not audited
- Stability: Breaking changes are expected
- Performance: elliptic curve and MGM implementations are extremely slow
 
## Goals
At the present time, the main goal of the project is to provide an implementation of the core protocol with GOST primitives. 
Formal verification, high-performance and stable cross-platform usage are out of the scope.

## Dependencies
RuWireGuard-Go relies on the following packages:
 - [GoGOST](https://www.git.cypherpunks.ru/?p=gogost.git)
 - [GOSThopper](https://dxdt.ru/golang/gosthopper/dxdt.ru/gosthopper/gosthopper.go)

## Linux local prototype

A **two-endpoint encrypted VPN** can now be tested on one Linux host with no external server. This tests the GOST handshake and IPv4/IPv6 payload transmission in two isolated network namespaces. See [the Arch Linux quickstart and smoke-test instructions](docs/LOCAL-PROTOTYPE.md).

```bash
mkdir -p bin
go build -mod=vendor -o bin/ruwireguard-go .
go build -mod=vendor -o bin/ruwg ./cmd/wgctrl
sudo bash tests/smoke-gost-netns.sh ./bin/ruwireguard-go ./bin/ruwg
```

The bundled `bin/ruwg` must be used, **not** a stock WireGuard `wg` binary, and the stock Linux kernel WireGuard module cannot run this GOST protocol.

## Quickstart

### Build

```
make
```

### Test

```
make gotest
```

### Protocol Benchmark

```
make tests
```

## Contributing

Ru-WireGuard-Go welcomes contributions.

---

## Usage

Unlike the stock Linux kernel WireGuard implementation, Ru-WireGuard requires this fork's userspace TUN daemon. With the binaries built by `make`, start it as follows:

```
$ sudo ./wireguard-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ sudo ./wireguard-go -f wg0
```

When an interface is running, use the **bundled** `./wg` to configure its GOST peer keys. Use `ip(8)` for interface addresses and routes; standard `wg` and `wg-quick` installations are not a substitute.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

Use this fork's userspace Linux TUN implementation. Standard Linux WireGuard kernel support is not compatible with the Ru-WireGuard GOST handshake or 33-byte public keys. See [local prototype documentation](docs/LOCAL-PROTOTYPE.md).

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

This runs on Windows, but you should instead use it from the more [fully featured Windows app](https://git.zx2c4.com/wireguard-windows/about/), which uses this as a module.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## License

    Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
    Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
