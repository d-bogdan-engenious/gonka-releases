SHELL := /bin/bash

# ---- QA overlay (qa/v6-coverage): Phase 0.5 load modes / Phase 1 fault×load driver ----
# Parameters via LOAD_* env (see citest/load_fault_test.go). Writes results-load/<ts>/.
.PHONY: citest-load
citest-load: citest-images ## QA: load + fault driver (LOAD_RPS, LOAD_FAULT, LOAD_TARGET, LOAD_RPS_SWEEP…).
	$(MAKE) build-devshardd
	$(CITEST_RPC_RUN) -run '^TestLoadFault$$' -count=1 -v -timeout 180m

# QA: single-test confirm target for the P0 failure (repeat-to-confirm rule).
.PHONY: citest-ha-catchup
citest-ha-catchup: citest-images ## QA: only TestHAStaleStandbyCatchupIdempotent.
	$(MAKE) build-devshardd
	$(CITEST_RPC_RUN) -run '^TestHAStaleStandbyCatchupIdempotent$$' -count=1 -v -timeout 30m

# QA: proxy-router integration test on a FULL checkout (turns #13 maxconn / #14 X-Real-IP into RUN).
.PHONY: citest-proxy-routing
citest-proxy-routing: ## QA: proxy-router/test-routing.sh + route-status_test.sh (needs docker, openssl, flock).
	$(MAKE) -C ../../proxy-router test-route-status
	cd ../../proxy-router && ./test-routing.sh

# QA: D05/D06/1.1 — ALPN h2 over TLS vs cleartext h2c on the production proxy-router :9443 listener.
.PHONY: citest-tls-alpn
citest-tls-alpn: ## QA: proxy-router :9443 TLS+ALPN h2 (NGINX_MODE=https) and h2c (NGINX_MODE=http) probe.
	bash $(CURDIR)/scripts/qa-tls-alpn.sh

# QA: Phase B — full unit/integration `go test` of the devshard module with docker present
# (testcontainers Postgres suites), plus a coverprofile for the Phase A5 diff-line coverage.
# Writes citest/results-load/unit/{unit.log,cover.out,cover-func.txt}.
.PHONY: citest-unit
citest-unit: ## QA: go test ./... (devshard module) + coverprofile; needs docker for the PG suites.
	mkdir -p $(CURDIR)/citest/results-load/unit
	cd ../.. && (go test ./... -count=1 -timeout 60m -coverprofile=$(CURDIR)/citest/results-load/unit/cover.out -covermode=atomic 2>&1 | tee $(CURDIR)/citest/results-load/unit/unit.log; exit $${PIPESTATUS[0]}) ; rc=$$?; \
	  go tool cover -func=$(CURDIR)/citest/results-load/unit/cover.out > $(CURDIR)/citest/results-load/unit/cover-func.txt 2>/dev/null || true; \
	  echo "citest-unit: ok=$$(grep -c '^ok' $(CURDIR)/citest/results-load/unit/unit.log) FAIL=$$(grep -c '^FAIL' $(CURDIR)/citest/results-load/unit/unit.log) rc=$$rc"; exit $$rc

# QA: Phase B for the other Go modules touched by the PR (proxy-router has shell tests only).
.PHONY: citest-unit-dapi
citest-unit-dapi: ## QA: go test of decentralized-api devshard-related packages.
	mkdir -p $(CURDIR)/citest/results-load/unit-dapi
	cd ../../decentralized-api && go test ./... -count=1 -timeout 40m 2>&1 | tee $(CURDIR)/citest/results-load/unit-dapi/unit.log; exit $${PIPESTATUS[0]}
