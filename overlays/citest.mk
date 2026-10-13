
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
