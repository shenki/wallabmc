#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Tenstorrent USA, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Check TLS pre-shared key (PSK) support on a live device with
# openssl s_client.
#
# PSK is a build option (CONFIG_APP_HTTPS_PSK, default n), so say which
# kind of build is on the device:
#
#   --no-psk  (default) PSK handshakes must be refused, and offering a
#             PSK must not stop the certificate handshake working.
#   --psk     PSK handshakes must work over TLS 1.2 and TLS 1.3, a wrong
#             key must be refused, and certificate handshakes must still
#             work over both versions.
#
# The key and identity default to the placeholder in src/config.c and
# src/http.c. Override them with the PSK (hex) and PSK_ID environment
# variables.
#
# Usage: test-tls-psk.sh [--psk|--no-psk] [IP]
#   IP     Target device address (default: 192.168.1.110)

set -u

PSK="${PSK:-0102030405060708}"
PSK_ID="${PSK_ID:-WallaBMC}"
WRONG_PSK=ffffffffffffffff

usage() {
	cat <<'EOF'
Usage: test-tls-psk.sh [--psk|--no-psk] [IP]
  --no-psk  Device was built without CONFIG_APP_HTTPS_PSK (default)
  --psk     Device was built with CONFIG_APP_HTTPS_PSK=y
  IP        Target device address (default: 192.168.1.110)
EOF
}

expect_psk=0
IP=""
for arg in "$@"; do
	case "$arg" in
	--psk) expect_psk=1 ;;
	--no-psk) expect_psk=0 ;;
	-h|--help) usage; exit 0 ;;
	-*) echo "Unknown option: $arg" >&2; usage >&2; exit 1 ;;
	*) IP="$arg" ;;
	esac
done
IP="${IP:-192.168.1.110}"

if ! command -v openssl >/dev/null 2>&1; then
	echo "openssl not installed" >&2
	exit 1
fi

failed=0

pass() {
	echo "PASS: $*"
}

fail() {
	echo "FAIL: $*" >&2
	failed=$((failed + 1))
}

# Run a handshake. Sets $out to the s_client output and returns its exit
# status, which is zero only when the handshake completed.
handshake() {
	out="$(openssl s_client -connect "$IP:443" "$@" </dev/null 2>&1)"
}

# True when the last handshake was authenticated with a PSK: the server
# sent no certificate.
used_psk() {
	printf '%s\n' "$out" | grep -q '^no peer certificate available'
}

negotiated() {
	printf '%s\n' "$out" | grep -E '^(New|Reused), ' | head -1
}

psk_args=(-psk "$PSK" -psk_identity "$PSK_ID")
wrong_args=(-psk "$WRONG_PSK" -psk_identity "$PSK_ID")

# TLS 1.3 handshakes that offer a PSK send a P-256 key share, which the
# device always accepts. If the device has to ask for another group with
# a HelloRetryRequest and picks a SHA-384 ciphersuite, openssl gives up
# with "bad psk" instead of carrying on without the PSK, which would
# look like a device failure.
tls13_psk=(-tls1_3 -groups P-256)

echo ">>> certificate handshakes"
for ver in tls1_2 tls1_3; do
	if handshake "-$ver" && ! used_psk; then
		pass "$ver with certificate: $(negotiated)"
	else
		fail "$ver with certificate"
	fi
done

if [ "$expect_psk" = 1 ]; then
	echo ">>> PSK handshakes (expecting PSK support)"

	if handshake -tls1_2 -cipher PSK-AES128-GCM-SHA256 "${psk_args[@]}" && used_psk; then
		pass "tls1_2 with PSK: $(negotiated)"
	else
		fail "tls1_2 with PSK"
	fi

	if handshake "${tls13_psk[@]}" "${psk_args[@]}" && used_psk; then
		pass "tls1_3 with PSK: $(negotiated)"
	else
		fail "tls1_3 with PSK (handshake failed or fell back to the certificate)"
	fi

	if handshake -tls1_2 -cipher PSK-AES128-GCM-SHA256 "${wrong_args[@]}"; then
		fail "tls1_2 accepted a wrong PSK"
	else
		pass "tls1_2 refuses a wrong PSK"
	fi

	# In TLS 1.3 the client also offers a certificate handshake, so a
	# wrong key must not end in a PSK-authenticated session.
	if handshake "${tls13_psk[@]}" "${wrong_args[@]}" && used_psk; then
		fail "tls1_3 accepted a wrong PSK"
	else
		pass "tls1_3 refuses a wrong PSK"
	fi
else
	echo ">>> PSK handshakes (expecting no PSK support)"

	if handshake -tls1_2 -cipher PSK-AES128-GCM-SHA256 "${psk_args[@]}"; then
		fail "tls1_2 PSK handshake succeeded"
	else
		pass "tls1_2 PSK handshake refused"
	fi

	if handshake "${tls13_psk[@]}" "${psk_args[@]}" && ! used_psk; then
		pass "tls1_3 ignores the offered PSK and uses the certificate"
	else
		fail "tls1_3 with a PSK offered"
	fi
fi

echo
if [ "$failed" -ne 0 ]; then
	echo "$failed test(s) failed" >&2
	exit 1
fi
echo "All TLS PSK tests passed"
