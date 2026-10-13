
# ---- QA overlay (qa/v6-coverage): Phase 0.5 load modes / Phase 1 fault×load driver ----
# Parameters via LOAD_* env (see citest/load_fault_test.go). Writes results-load/<ts>/.
.PHONY: citest-load
citest-load: citest-images ## QA: load + fault driver (LOAD_RPS, LOAD_FAULT, LOAD_TARGET, LOAD_RPS_SWEEP…).
	$(MAKE) build-devshardd
	TESTENV_CITEST=1 go test -tags=testenvci ./citest/ -run '^TestLoadFault$$' -count=1 -v -timeout 180m
