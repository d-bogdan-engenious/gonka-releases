#!/usr/bin/env bash
# QA overlay (qa/v6-coverage): dev scenarios D05 / D06 / 1.1 on the production
# proxy-router image — does :9443 negotiate HTTP/2 over TLS via ALPN (NGINX_MODE=https),
# fall back correctly for an http/1.1-only client, and serve cleartext h2c when
# NGINX_MODE=http? Needs docker + openssl + curl on the host. No catalog is required:
# the entrypoint only starts the reconciler when VERSIOND_ROUTING_CATALOG_URL is set,
# and the rpc_h2 backends are `init-addr none`, so the listener comes up regardless.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)            # repo root (docker build context)
tag=qa-proxy-router-tls:$$
ctr=qa-pr-tls-$$
tmp=$(mktemp -d)
pub=19443
cleanup() { docker rm -f "$ctr" "$ctr-h2c" >/dev/null 2>&1 || true; docker image rm "$tag" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT

echo "tls-alpn: build proxy-router image from $root"
docker build -q -t "$tag" -f "$root/proxy-router/Dockerfile" "$root" >/dev/null

echo "tls-alpn: self-signed cert (CN=proxy-router.test)"
mkdir -p "$tmp/ssl"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=proxy-router.test" \
  -keyout "$tmp/ssl/private.key" -out "$tmp/ssl/cert.pem" >/dev/null 2>&1
chmod 644 "$tmp/ssl/cert.pem" "$tmp/ssl/private.key"

common_env=(-e 'VERSIOND_VERSIONS=v4 v5' -e 'VERSIOND_NON_HA_VERSIONS=' \
  -e VERSIOND_ROUTER_POOL_HOST=versiond-router-fleet \
  -e PROXY_ROUTER_VERSION_CAPACITY=1 -e PROXY_ROUTER_ACTIVATION_MIN_READY=2)

wait_port() { # host port secs
  for _ in $(seq "$3"); do (exec 3<>"/dev/tcp/$1/$2") >/dev/null 2>&1 && return 0; sleep 1; done; return 1
}

verdict() { printf '| %-34s | %-6s | %s |\n' "$1" "$2" "$3"; }
echo
echo "| check | result | detail |"
echo "|---|---|---|"
fail=0

# --- D05: NGINX_MODE=https → bind :9443 ssl crt … alpn h2 -------------------------------
docker run -d --name "$ctr" -p "127.0.0.1:$pub:9443" "${common_env[@]}" \
  -e NGINX_MODE=https -v "$tmp/ssl:/etc/haproxy/ssl:ro" "$tag" >/dev/null
if ! wait_port 127.0.0.1 "$pub" 60; then
  verdict "D05 listener :9443 (https mode)" FAIL "port never opened; entrypoint log follows"; docker logs "$ctr" 2>&1 | tail -20; exit 1
fi
rendered=$(docker exec "$ctr" sh -c 'grep -E "^ *bind :9443" /usr/local/etc/haproxy/haproxy.cfg /etc/haproxy/*.cfg 2>/dev/null | head -1' || true)
verdict "rendered bind (https)" INFO "${rendered:-not found}"

neg=$(echo | openssl s_client -alpn h2 -connect "127.0.0.1:$pub" -servername proxy-router.test 2>/dev/null | grep -E "^ALPN protocol:|^No ALPN" || true)
if echo "$neg" | grep -q "ALPN protocol: h2"; then verdict "D05 ALPN negotiates h2" PASS "$neg"; else verdict "D05 ALPN negotiates h2" FAIL "${neg:-no ALPN line}"; fail=1; fi

h1=$(echo | openssl s_client -alpn http/1.1 -connect "127.0.0.1:$pub" -servername proxy-router.test 2>/dev/null | grep -E "^ALPN protocol:|^No ALPN" || true)
verdict "client offers http/1.1 only" INFO "${h1:-no ALPN line (handshake may still complete without ALPN)}"
if echo "$h1" | grep -q "ALPN protocol: h2"; then verdict "no h2 forced on http/1.1 client" FAIL "$h1"; fail=1; else verdict "no h2 forced on http/1.1 client" PASS "h2 not negotiated"; fi

noalpn=$(echo | openssl s_client -connect "127.0.0.1:$pub" -servername proxy-router.test 2>/dev/null | grep -E "^ALPN protocol:|^No ALPN|Protocol  *:" | head -2 | tr '\n' ' ' || true)
verdict "client without ALPN (TLS handshake)" INFO "${noalpn:-n/a}"

code=$(curl -sk --http2 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 "https://127.0.0.1:$pub/healthz" || true)
verdict "curl --http2 over TLS /healthz" INFO "status/version: ${code:-no response} (any HTTP answer over h2 = TLS path works; 503 expected with no backends)"
docker rm -f "$ctr" >/dev/null 2>&1 || true

# --- D06: NGINX_MODE=http → bind :9443 proto h2 (cleartext h2c) ---------------------------
docker run -d --name "$ctr-h2c" -p "127.0.0.1:$pub:9443" "${common_env[@]}" -e NGINX_MODE=http "$tag" >/dev/null
if ! wait_port 127.0.0.1 "$pub" 60; then verdict "D06 listener :9443 (http mode)" FAIL "port never opened"; docker logs "$ctr-h2c" 2>&1 | tail -20; exit 1; fi
rendered2=$(docker exec "$ctr-h2c" sh -c 'grep -E "^ *bind :9443" /usr/local/etc/haproxy/haproxy.cfg /etc/haproxy/*.cfg 2>/dev/null | head -1' || true)
verdict "rendered bind (http)" INFO "${rendered2:-not found}"
h2c=$(curl -s --http2-prior-knowledge -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 "http://127.0.0.1:$pub/healthz" || true)
if echo "$h2c" | grep -qE ' 2$'; then verdict "D06 h2c prior-knowledge answers" PASS "$h2c"; else verdict "D06 h2c prior-knowledge answers" FAIL "${h2c:-no response}"; fail=1; fi
tlsfail=$(echo | openssl s_client -alpn h2 -connect "127.0.0.1:$pub" 2>&1 | grep -ciE "wrong version number|unknown protocol|packet length too long" || true)
if [ "${tlsfail:-0}" -gt 0 ]; then verdict "D06 TLS refused on cleartext bind" PASS "openssl: not TLS"; else verdict "D06 TLS refused on cleartext bind" INFO "openssl did not report a TLS-mismatch error"; fi

echo
[ "$fail" -eq 0 ] && echo "tls-alpn: ok" || { echo "tls-alpn: FAIL" >&2; exit 1; }
