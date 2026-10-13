#!/usr/bin/env bash
# QA overlay (qa/v6-coverage): dev scenarios D05 / D06 / 1.1 on the production
# proxy-router image — does :9443 negotiate HTTP/2 over TLS via ALPN (NGINX_MODE=https),
# fall back correctly for an http/1.1-only client, and serve cleartext h2c when
# NGINX_MODE=http? Needs docker + openssl + curl on the host. No catalog is required:
# the entrypoint only starts the reconciler when VERSIOND_ROUTING_CATALOG_URL is set,
# and the rpc_h2 backends are `init-addr none`, so the listener comes up regardless.
#
# v2: the container runs on a user-defined docker network (so the embedded DNS at
# 127.0.0.11 that haproxy.cfg's `resolvers docker` names actually exists), readiness
# is "haproxy process alive AND the listener answers", not "docker-proxy accepted a
# TCP connect" (run 38450013346 passed wait_port while nothing was behind it), and
# every FAIL dumps the container log so the verdict is auditable.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)            # repo root (docker build context)
tag=qa-proxy-router-tls:$$
ctr=qa-pr-tls-$$
net=qa-pr-tls-net-$$
tmp=$(mktemp -d)
pub=19443
keep=${QA_TLS_KEEP:-}
cleanup() {
  if [ -z "$keep" ]; then
    docker rm -f "$ctr" "$ctr-h2c" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
    docker image rm "$tag" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

echo "tls-alpn: build proxy-router image from $root"
docker build -q -t "$tag" -f "$root/proxy-router/Dockerfile" "$root" >/dev/null
docker network create "$net" >/dev/null

echo "tls-alpn: self-signed cert (CN=proxy-router.test)"
mkdir -p "$tmp/ssl"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=proxy-router.test" \
  -keyout "$tmp/ssl/private.key" -out "$tmp/ssl/cert.pem" >/dev/null 2>&1
chmod 644 "$tmp/ssl/cert.pem" "$tmp/ssl/private.key"

common_env=(-e 'VERSIOND_VERSIONS=v4 v5' -e 'VERSIOND_NON_HA_VERSIONS=' \
  -e VERSIOND_ROUTER_POOL_HOST=versiond-router-fleet \
  -e PROXY_ROUTER_VERSION_CAPACITY=1 -e PROXY_ROUTER_ACTIVATION_MIN_READY=2)

verdict() { printf '| %-34s | %-6s | %s |\n' "$1" "$2" "$3"; }
dump() { echo "--- docker logs $1 (tail 30) ---"; docker logs "$1" 2>&1 | tail -30; echo "--- docker inspect state ---"; docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' "$1" 2>&1 || true; }

# wait_ready <ctr> <probe-fn>: haproxy must be alive in the container and the probe
# must succeed; up to 60 s. Prints the elapsed seconds on success.
wait_ready() {
  local c=$1 probe=$2 i
  for i in $(seq 60); do
    if ! docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true; then
      echo "container $c not running after ${i}s"; return 1
    fi
    if docker exec "$c" sh -c 'pgrep -x haproxy >/dev/null' 2>/dev/null && "$probe" >/dev/null 2>&1; then
      echo "$i"; return 0
    fi
    sleep 1
  done
  echo "timeout 60s (haproxy alive: $(docker exec "$c" sh -c 'pgrep -x haproxy >/dev/null && echo yes || echo no' 2>/dev/null))"; return 1
}
tls_probe() { echo | timeout 5 openssl s_client -connect "127.0.0.1:$pub" -servername proxy-router.test 2>/dev/null | grep -qE "^(Protocol|New, |---)"; }
h2c_probe() { curl -s --http2-prior-knowledge -o /dev/null --max-time 5 "http://127.0.0.1:$pub/healthz"; }

echo
echo "| check | result | detail |"
echo "|---|---|---|"
fail=0

# --- D05: NGINX_MODE=https → bind :9443 ssl crt … alpn h2 -------------------------------
docker run -d --name "$ctr" --network "$net" -p "127.0.0.1:$pub:9443" "${common_env[@]}" \
  -e NGINX_MODE=https -v "$tmp/ssl:/etc/haproxy/ssl:ro" "$tag" >/dev/null
if r=$(wait_ready "$ctr" tls_probe); then
  verdict "D05 listener :9443 (https) ready" PASS "haproxy alive + TLS handshake after ${r}s"
else
  verdict "D05 listener :9443 (https) ready" FAIL "$r"; fail=1; dump "$ctr"
fi
rendered=$(docker exec "$ctr" sh -c 'grep -E "^ *bind :9443" /usr/local/etc/haproxy/haproxy.cfg /etc/haproxy/*.cfg 2>/dev/null | head -1' || true)
verdict "rendered bind (https)" INFO "${rendered:-not found}"
pem=$(docker exec "$ctr" sh -c 'ls -l /var/lib/gonka-router/rpc-h2.pem 2>&1; grep -c "PRIVATE KEY" /var/lib/gonka-router/rpc-h2.pem 2>/dev/null' | tr '\n' ' ' || true)
verdict "rpc-h2.pem written (cert+key)" INFO "${pem:-n/a}"

neg=$(echo | timeout 8 openssl s_client -alpn h2 -connect "127.0.0.1:$pub" -servername proxy-router.test 2>/dev/null | grep -E "^ALPN protocol:|^No ALPN" || true)
if echo "$neg" | grep -q "ALPN protocol: h2"; then verdict "D05 ALPN negotiates h2" PASS "$neg"; else verdict "D05 ALPN negotiates h2" FAIL "${neg:-no ALPN line}"; fail=1; dump "$ctr"; fi

h1=$(echo | timeout 8 openssl s_client -alpn http/1.1 -connect "127.0.0.1:$pub" -servername proxy-router.test 2>/dev/null | grep -E "^ALPN protocol:|^No ALPN" || true)
verdict "client offers http/1.1 only" INFO "${h1:-no ALPN line (handshake may still complete without ALPN)}"
if echo "$h1" | grep -q "ALPN protocol: h2"; then verdict "no h2 forced on http/1.1 client" FAIL "$h1"; fail=1; else verdict "no h2 forced on http/1.1 client" PASS "h2 not negotiated"; fi

noalpn=$(echo | timeout 8 openssl s_client -connect "127.0.0.1:$pub" -servername proxy-router.test 2>/dev/null | grep -E "^ALPN protocol:|^No ALPN|Protocol  *:" | head -2 | tr '\n' ' ' || true)
verdict "client without ALPN (TLS handshake)" INFO "${noalpn:-n/a}"

code=$(curl -sk --http2 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 "https://127.0.0.1:$pub/healthz" || true)
if echo "$code" | grep -qE '^[1-5][0-9][0-9] 2$'; then verdict "curl --http2 over TLS answers (h2)" PASS "$code (503 expected: no backends)"; else verdict "curl --http2 over TLS answers (h2)" FAIL "${code:-no response}"; fail=1; fi

codeh1=$(curl -sk --http1.1 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 "https://127.0.0.1:$pub/healthz" || true)
verdict "curl --http1.1 over TLS (1.1 client)" INFO "${codeh1:-no response} (listener is alpn h2 only; 1.1 answer or reset both acceptable, recorded)"
[ -z "$keep" ] && docker rm -f "$ctr" >/dev/null 2>&1 || true

# --- D06: NGINX_MODE=http → bind :9443 proto h2 (cleartext h2c) ---------------------------
docker run -d --name "$ctr-h2c" --network "$net" -p "127.0.0.1:$pub:9443" "${common_env[@]}" -e NGINX_MODE=http "$tag" >/dev/null
if r=$(wait_ready "$ctr-h2c" h2c_probe); then
  verdict "D06 listener :9443 (http) ready" PASS "haproxy alive + h2c answer after ${r}s"
else
  verdict "D06 listener :9443 (http) ready" FAIL "$r"; fail=1; dump "$ctr-h2c"
fi
rendered2=$(docker exec "$ctr-h2c" sh -c 'grep -E "^ *bind :9443" /usr/local/etc/haproxy/haproxy.cfg /etc/haproxy/*.cfg 2>/dev/null | head -1' || true)
verdict "rendered bind (http)" INFO "${rendered2:-not found}"
h2c=$(curl -s --http2-prior-knowledge -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 "http://127.0.0.1:$pub/healthz" || true)
if echo "$h2c" | grep -qE ' 2$'; then verdict "D06 h2c prior-knowledge answers" PASS "$h2c"; else verdict "D06 h2c prior-knowledge answers" FAIL "${h2c:-no response}"; fail=1; dump "$ctr-h2c"; fi
h11=$(curl -s --http1.1 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 "http://127.0.0.1:$pub/healthz" || true)
verdict "D06 HTTP/1.1 on the h2c bind" INFO "${h11:-no response} (proto h2 bind: 1.1 is expected to fail/000)"
tlsfail=$(echo | timeout 8 openssl s_client -alpn h2 -connect "127.0.0.1:$pub" 2>&1 | grep -ciE "wrong version number|unknown protocol|packet length too long" || true)
if [ "${tlsfail:-0}" -gt 0 ]; then verdict "D06 TLS refused on cleartext bind" PASS "openssl: not TLS"; else verdict "D06 TLS refused on cleartext bind" INFO "openssl did not report a TLS-mismatch error"; fi

echo
[ "$fail" -eq 0 ] && echo "tls-alpn: ok" || { echo "tls-alpn: FAIL" >&2; exit 1; }
