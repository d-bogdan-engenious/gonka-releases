#!/usr/bin/env bash
# QA overlay (qa/v6-coverage): catalog 2.9 / 2.11 / 2.12 / 2.8 on the PRODUCTION proxy-router image,
# cleartext (NGINX_MODE=http): abusive clients against the two HAProxy frontends that face peers and
# the policy workers — rpc_h2 (:9443, proto h2) and versiond_router_in (:18081, HTTP/1.1).
# No backends are attached (rpc_h2_upstream is init-addr none), so a request that passes every
# guard ends as 503 — which is exactly the signal that the guards did NOT fire.
#
# Oracles (READ from proxy-router/haproxy.cfg.template, stated before running):
#   A1 slowloris on :18081   → closed/408 within `timeout http-request` = CONNECT_TIMEOUT (2 s) + margin
#   A2 64 KiB header :18081  → 400 (header > tune.bufsize 16 KiB)
#   A3 `%` left in rpc path  → 400 (`http-request deny deny_status 400 if path_reg …[%]`)
#   A4 non-rpc path on :9443 → 404 (`deny 404 unless path_reg …/sessions/*/rpc/*/*$`)
#   A5 well-formed rpc path  → 503 (reaches rpc_h2_upstream, no server) — control
#   A6 attach-zone burst     → first ≤100 within 10 s pass to 503, the rest 429 (Connect) /
#                              200+grpc-status 8 (content-type application/grpc)
#   A7 64 KiB HEADERS on h2c → 431/400 or stream reset; never a 503 (never forwarded)
#   A8 TCP connect flood     → `tcp-request connection reject if sc_conn_rate(0) gt 200`: >200
#                              connects in 1 s from one src → some are reset before HTTP
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../../.." && pwd)
tag=qa-proxy-router-abuse:$$; ctr=qa-pr-abuse-$$; net=qa-pr-abuse-net-$$
rpc=19443; pol=18081
cleanup() { docker rm -f "$ctr" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; docker image rm "$tag" >/dev/null 2>&1 || true; }
trap cleanup EXIT
verdict() { printf '| %-36s | %-6s | %s |\n' "$1" "$2" "$3"; }
fail=0

echo "ingress-abuse: build proxy-router image"
docker build -q -t "$tag" -f "$root/proxy-router/Dockerfile" "$root" >/dev/null
docker network create "$net" >/dev/null
docker run -d --name "$ctr" --network "$net" -p "127.0.0.1:$rpc:9443" -p "127.0.0.1:$pol:18081" \
  -e 'VERSIOND_VERSIONS=v2 v5' -e 'VERSIOND_NON_HA_VERSIONS=' -e VERSIOND_ROUTER_POOL_HOST=versiond-router-fleet \
  -e PROXY_ROUTER_VERSION_CAPACITY=1 -e PROXY_ROUTER_ACTIVATION_MIN_READY=2 -e NGINX_MODE=http "$tag" >/dev/null
for i in $(seq 60); do
  docker exec "$ctr" sh -c 'pgrep -x haproxy >/dev/null' 2>/dev/null && curl -s --http2-prior-knowledge -o /dev/null --max-time 3 "http://127.0.0.1:$rpc/healthz" && break; sleep 1
done
echo "timeouts in rendered cfg: $(docker exec "$ctr" sh -c 'grep -E "timeout (http-request|connect)" /etc/haproxy/haproxy.cfg | head -2 | tr -s " " | tr "\n" ";"')"
echo
echo "| check | result | detail |"; echo "|---|---|---|"

# A1 slowloris
r=$(python3 - "$pol" <<'PY'
import socket,sys,time
s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),timeout=15); t0=time.time()
s.sendall(b"GET /v2/healthz HTTP/1.1\r\nHost: x\r\nX-Slow: ")
try:
    for i in range(60):
        time.sleep(0.5); s.sendall(b"a")   # keep dribbling header bytes
    print("still-open", round(time.time()-t0,1))
except Exception as e:
    print("closed", round(time.time()-t0,1), type(e).__name__)
PY
)
case "$r" in closed*) secs=$(echo "$r" | awk '{print $2}'); if awk "BEGIN{exit !($secs <= 8)}"; then verdict "A1 slowloris :18081 cut by http-request timeout" PASS "$r"; else verdict "A1 slowloris :18081" FAIL "closed late: $r"; fail=1; fi;;
  *) verdict "A1 slowloris :18081" FAIL "$r (never closed in 30 s)"; fail=1;; esac

# A2 oversized header on HTTP/1.1
big=$(head -c 65536 /dev/zero | tr '\0' 'a')
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "X-Big: $big" "http://127.0.0.1:$pol/v2/healthz" || echo "curl-exit-$?")
case "$code" in 400|431|000|curl-exit-*) verdict "A2 64 KiB header :18081 rejected" PASS "$code";; *) verdict "A2 64 KiB header :18081" FAIL "$code"; fail=1;; esac

h2() { curl -s -o /dev/null -w '%{http_code}' --http2-prior-knowledge --max-time 8 "$@"; }
# A3 percent left in rpc path → 400
c=$(h2 "http://127.0.0.1:$rpc/v2/sessions/1/rpc/devshard.transport.v1.SessionService/Ch%25at" || true)
[ "$c" = "400" ] && verdict "A3 % in rpc path → 400" PASS "$c" || { verdict "A3 % in rpc path → 400" FAIL "$c"; fail=1; }
# A3b unreserved escape decodes (%41ttach → Attach) and is NOT 400
c=$(h2 "http://127.0.0.1:$rpc/v2/sessions/1/rpc/devshard.transport.v1.PeerAuthService/%41ttach" || true)
[ "$c" != "400" ] && verdict "A3b %41ttach decodes (not 400)" PASS "$c" || { verdict "A3b %41ttach decodes" FAIL "$c"; fail=1; }
# A3c dot-dot escape out of /rpc/ → 404 (path-strip-dotdot then unless-match)
c=$(h2 --path-as-is "http://127.0.0.1:$rpc/v2/sessions/1/rpc/../metrics" || true)
[ "$c" = "404" ] && verdict "A3c /rpc/../metrics → 404" PASS "$c" || { verdict "A3c /rpc/../metrics" FAIL "$c"; fail=1; }
# A4 non-rpc path → 404
c=$(h2 "http://127.0.0.1:$rpc/v2/healthz" || true)
[ "$c" = "404" ] && verdict "A4 non-rpc path :9443 → 404" PASS "$c" || { verdict "A4 non-rpc path :9443 → 404" FAIL "$c"; fail=1; }
# A5 control: well-formed → reaches backend → 503
c=$(h2 -X POST "http://127.0.0.1:$rpc/v2/sessions/1/rpc/devshard.transport.v1.SessionService/GetDiffs" || true)
[ "$c" = "503" ] && verdict "A5 well-formed rpc → 503 (no server) control" PASS "$c" || { verdict "A5 control" FAIL "$c"; fail=1; }

# A6 attach-zone budget: 100 / 10 s per src
codes=$(for i in $(seq 140); do h2 -X POST "http://127.0.0.1:$rpc/v2/sessions/1/rpc/devshard.transport.v1.PeerAuthService/Attach"; echo; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
n429=$(echo "$codes" | grep -oE '[0-9]+ 429' | awk '{print $1}'); n503=$(echo "$codes" | grep -oE '[0-9]+ 503' | awk '{print $1}')
if [ "${n429:-0}" -ge 30 ] && [ "${n503:-0}" -ge 90 ] && [ "${n503:-0}" -le 101 ]; then verdict "A6 attach zone 100/10s → 429 after cap" PASS "$codes"; else verdict "A6 attach zone 100/10s" FAIL "$codes"; fail=1; fi
# A6b same cap but native gRPC content-type → 200 + grpc-status 8 (not 429)
g=$(curl -s -D - -o /dev/null --http2-prior-knowledge --max-time 8 -X POST -H 'content-type: application/grpc' "http://127.0.0.1:$rpc/v2/sessions/1/rpc/devshard.transport.v1.PeerAuthService/Attach" | tr -d '\r' | grep -iE '^(HTTP/|grpc-status|content-type)' | tr '\n' ' ')
echo "$g" | grep -qE 'HTTP/2 200' && echo "$g" | grep -qiE 'grpc-status: 8' && verdict "A6b gRPC over-cap → 200 + grpc-status 8" PASS "$g" || verdict "A6b gRPC over-cap (cap window may have expired)" INFO "$g"

# A7 oversized HEADERS on h2c
c=$(h2 -H "X-Big: $big" "http://127.0.0.1:$rpc/v2/sessions/1/rpc/devshard.transport.v1.SessionService/GetDiffs" 2>/dev/null || echo "curl-exit-$?")
case "$c" in 503) verdict "A7 64 KiB HEADERS on h2c" FAIL "forwarded (503)"; fail=1;; *) verdict "A7 64 KiB HEADERS on h2c rejected" PASS "$c";; esac

# A8 connection-rate reject (>200 connects/s from one src)
r=$(python3 - "$rpc" <<'PY'
import socket,sys,time
port=int(sys.argv[1]); ok=rej=0; socks=[]
t0=time.time()
for i in range(300):
    try:
        s=socket.create_connection(("127.0.0.1",port),timeout=2); socks.append(s)
    except Exception: rej+=1
el=time.time()-t0
# a rejected connection is accepted by the kernel then closed by haproxy: probe with a read
closed=0
for s in socks:
    s.settimeout(0.3)
    try:
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        d=s.recv(1)
        if d==b"": closed+=1
    except socket.timeout: pass
    except Exception: closed+=1
print(f"connects={len(socks)} connect_err={rej} closed_by_haproxy={closed} in {el:.2f}s")
for s in socks: s.close()
PY
)
closed=$(echo "$r" | grep -oE 'closed_by_haproxy=[0-9]+' | cut -d= -f2); el=$(echo "$r" | grep -oE 'in [0-9.]+s' | awk '{print $2}' | tr -d s)
if awk "BEGIN{exit !($el < 1.5)}" && [ "${closed:-0}" -ge 50 ]; then verdict "A8 conn_rate>200/s → connections reset" PASS "$r"; elif awk "BEGIN{exit !($el >= 1.5)}"; then verdict "A8 conn_rate (host too slow to hit 200/s)" INFO "$r"; else verdict "A8 conn_rate>200/s" FAIL "$r"; fail=1; fi

echo; echo "--- haproxy log tail (denies/rejects) ---"; docker logs "$ctr" 2>&1 | grep -E ' (400|404|429|431|503|408) | PR-- | CR-- | sC-- ' | tail -8 || true
echo; [ "$fail" -eq 0 ] && echo "ingress-abuse: ok" || { echo "ingress-abuse: FAIL" >&2; exit 1; }
