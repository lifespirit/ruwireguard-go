#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Ru-WireGuard GOST Linux smoke test. Requires root, iproute2, ping, TUN.
# Runs two isolated endpoints in their own network namespaces.
set -Eeuo pipefail

if (( EUID != 0 )); then
    echo "Run as root: sudo $0 <path-to-daemon> <path-to-wg>" >&2
    exit 2
fi
if (( $# != 2 )); then
    echo "Usage: sudo $0 <path-to-ruwireguard-go> <path-to-bundled-wg>" >&2
    exit 2
fi
for dep in ip ping timeout awk mktemp; do
    command -v "$dep" >/dev/null || { echo "Missing dependency: $dep" >&2; exit 2; }
done
if [[ ! -c /dev/net/tun ]]; then
    echo "Missing /dev/net/tun (load the tun module)" >&2
    exit 2
fi
DAEMON="$(realpath "$1")"
WG="$(realpath "$2")"
[[ -x "$DAEMON" && -x "$WG" ]] || { echo "Build both Ru-WireGuard binaries first" >&2; exit 2; }

# Keep all names unique even if parallel CI jobs are on the same machine.
NS_A="ruwg-a-$$"
NS_B="ruwg-b-$$"
IF_A="rwa$$"
IF_B="rwb$$"
VETH_A="rva$$"
VETH_B="rvb$$"
WORK="$(mktemp -d)"
chmod 700 "$WORK"
PID_A=""
PID_B=""
export GOMAXPROCS="${GOMAXPROCS:-2}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

cleanup() {
    local status="$1"
    trap - EXIT
    if (( status != 0 )); then
        echo "Smoke test FAILED (status $status), daemon logs:" >&2
        for f in "$WORK"/{a,b}.log; do
            if [[ -f "$f" ]]; then
                echo "----- $f -----" >&2
                tail -n 100 "$f" >&2 || :
            fi
        done
        ip netns exec "$NS_A" "$WG" show "$IF_A" >&2 || :
        ip netns exec "$NS_B" "$WG" show "$IF_B" >&2 || :
    fi
    [[ -z "$PID_A" ]] || { kill "$PID_A" 2>/dev/null || :; wait "$PID_A" 2>/dev/null || :; }
    [[ -z "$PID_B" ]] || { kill "$PID_B" 2>/dev/null || :; wait "$PID_B" 2>/dev/null || :; }
    ip netns del "$NS_A" 2>/dev/null || :
    ip netns del "$NS_B" 2>/dev/null || :
    rm -f "/var/run/wireguard/$IF_A.sock" "/var/run/wireguard/$IF_B.sock"
    rm -rf "$WORK"
    exit "$status"
}
trap 'cleanup $?' EXIT

echo "[1/6] Create isolated network namespaces and veth underlay"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"
ip -n "$NS_A" link set lo up
ip -n "$NS_B" link set lo up
ip -n "$NS_A" addr add 172.30.233.1/30 dev "$VETH_A"
ip -n "$NS_B" addr add 172.30.233.2/30 dev "$VETH_B"
ip -n "$NS_A" link set "$VETH_A" up
ip -n "$NS_B" link set "$VETH_B" up
ip netns exec "$NS_A" ping -n -c 1 -W 2 172.30.233.2 >/dev/null

echo "[2/6] Create ephemeral GOST keys using bundled wg"
umask 077
KEY_A="$("$WG" genkey)"
KEY_B="$("$WG" genkey)"
PUB_A="$(printf '%s\n' "$KEY_A" | "$WG" pubkey)"
PUB_B="$(printf '%s\n' "$KEY_B" | "$WG" pubkey)"
PSK="$("$WG" genpsk)"
[[ -n "$KEY_A" && -n "$KEY_B" && -n "$PUB_A" && -n "$PUB_B" && -n "$PSK" ]]

cat >"$WORK/a.conf" <<EOF
[Interface]
PrivateKey = $KEY_A
ListenPort = 51871

[Peer]
PublicKey = $PUB_B
PresharedKey = $PSK
Endpoint = 172.30.233.2:51872
AllowedIPs = 10.77.255.2/32, fd77:77::2/128
PersistentKeepalive = 1
EOF
cat >"$WORK/b.conf" <<EOF
[Interface]
PrivateKey = $KEY_B
ListenPort = 51872

[Peer]
PublicKey = $PUB_A
PresharedKey = $PSK
Endpoint = 172.30.233.1:51871
AllowedIPs = 10.77.255.1/32, fd77:77::1/128
PersistentKeepalive = 1
EOF

echo "[3/6] Start userspace GOST tunnel endpoints"
ip netns exec "$NS_A" "$DAEMON" --foreground "$IF_A" >"$WORK/a.log" 2>&1 &
PID_A=$!
ip netns exec "$NS_B" "$DAEMON" --foreground "$IF_B" >"$WORK/b.log" 2>&1 &
PID_B=$!
for attempt in {1..60}; do
    if ip -n "$NS_A" link show dev "$IF_A" >/dev/null 2>&1 &&
       ip -n "$NS_B" link show dev "$IF_B" >/dev/null 2>&1 &&
       [[ -S "/var/run/wireguard/$IF_A.sock" ]] &&
       [[ -S "/var/run/wireguard/$IF_B.sock" ]]; then
        break
    fi
    kill -0 "$PID_A" 2>/dev/null || { echo "First GOST daemon exited" >&2; exit 1; }
    kill -0 "$PID_B" 2>/dev/null || { echo "Second GOST daemon exited" >&2; exit 1; }
    sleep 0.2
done
ip -n "$NS_A" link show dev "$IF_A" >/dev/null
ip -n "$NS_B" link show dev "$IF_B" >/dev/null

ip netns exec "$NS_A" "$WG" setconf "$IF_A" "$WORK/a.conf"
ip netns exec "$NS_B" "$WG" setconf "$IF_B" "$WORK/b.conf"
ip -n "$NS_A" addr add 10.77.255.1/30 dev "$IF_A"
ip -n "$NS_B" addr add 10.77.255.2/30 dev "$IF_B"
ip -n "$NS_A" addr add fd77:77::1/64 dev "$IF_A"
ip -n "$NS_B" addr add fd77:77::2/64 dev "$IF_B"
ip -n "$NS_A" link set dev "$IF_A" mtu 1280 up
ip -n "$NS_B" link set dev "$IF_B" mtu 1280 up

echo "[4/6] Check GOST encrypted payload delivery in both directions"
success=0
for attempt in {1..12}; do
    if ip netns exec "$NS_A" timeout 8 ping -n -c 1 -W 3 -I "$IF_A" 10.77.255.2 >/dev/null 2>&1; then
        success=1
        break
    fi
    sleep 1
done
(( success == 1 )) || { echo "IPv4 initiation through GOST failed" >&2; exit 1; }
ip netns exec "$NS_A" timeout 20 ping -n -c 2 -W 5 -I "$IF_A" 10.77.255.2
ip netns exec "$NS_B" timeout 20 ping -n -c 2 -W 5 -I "$IF_B" 10.77.255.1
ip netns exec "$NS_A" timeout 20 ping -n -6 -c 2 -W 5 -I "$IF_A" fd77:77::2
ip netns exec "$NS_B" timeout 20 ping -n -6 -c 2 -W 5 -I "$IF_B" fd77:77::1

echo "[5/6] Require an authenticated nonzero handshake timestamp on both peers"
ip netns exec "$NS_A" "$WG" show "$IF_A" latest-handshakes |
    awk 'NF >= 2 && $2 + 0 > 0 {ok=1} END {exit !ok}'
ip netns exec "$NS_B" "$WG" show "$IF_B" latest-handshakes |
    awk 'NF >= 2 && $2 + 0 > 0 {ok=1} END {exit !ok}'
echo "[6/6] Verify authenticated roaming after UDP source address/port change"
# B is not told about the new A endpoint. A's next authenticated packet
# must teach B the new 172.30.233.9:51873 endpoint automatically.
ip -n "$NS_A" addr add 172.30.233.9/32 dev "$VETH_A"
ip -n "$NS_A" route replace 172.30.233.2/32 dev "$VETH_A" src 172.30.233.9
ip -n "$NS_B" route replace 172.30.233.9/32 dev "$VETH_B"
ip netns exec "$NS_A" "$WG" set "$IF_A" listen-port 51873

expected_endpoint="172.30.233.9:51873"
found_endpoint=""
for attempt in {1..12}; do
    # The send may first trigger a handshake or a keepalive, depending
    # on the current session state.
    ip netns exec "$NS_A" timeout 8 ping -n -c 1 -W 3 -I "$IF_A" 10.77.255.2 >/dev/null 2>&1 || :
    found_endpoint="$(ip netns exec "$NS_B" "$WG" show "$IF_B" endpoints | awk 'NF >= 2 {print $2; exit}')"
    if [[ "$found_endpoint" == "$expected_endpoint" ]]; then
        break
    fi
    sleep 0.5
done
if [[ "$found_endpoint" != "$expected_endpoint" ]]; then
    echo "Roaming failed: B still reports ${found_endpoint:-<none>} instead of $expected_endpoint" >&2
    exit 1
fi
# Check data from both sides after the endpoint moved, including IPv6.
ip netns exec "$NS_B" timeout 20 ping -n -c 2 -W 5 -I "$IF_B" 10.77.255.1
ip netns exec "$NS_A" timeout 20 ping -n -6 -c 2 -W 5 -I "$IF_A" fd77:77::2

ip netns exec "$NS_A" "$WG" show "$IF_A"
ip netns exec "$NS_B" "$WG" show "$IF_B"
echo "PASS: GOST IPv4/IPv6 tunnel and authenticated UDP endpoint roaming"
