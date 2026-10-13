//go:build testenvci

package citest

// Phase 0.5 / Phase 1 load + fault driver (QA overlay, branch qa/v6-coverage).
//
// Drives a fixed-rps (or stepped, for the knee) chat load at the gateway over the
// real testenv stack, optionally injects one fault on one host mid-run, and writes
// per-request + per-host evidence so every verdict carries its load mode:
//
//	LOAD_RPS            requests per second (default 16 = L1 nominal)
//	LOAD_DURATION_S     total run seconds (default 300)
//	LOAD_PAUSE_AT_S     fault start offset (default 91 = colleague's 1:31)
//	LOAD_PAUSE_LEN_S    fault length (default 60)
//	LOAD_FAULT          none | pause | stop | netdown | drop9443 | reject9443
//	LOAD_ASYM_FROM      with drop9443/reject9443: only block traffic FROM this service to the
//	                    target's :9443 (asymmetric partition); empty = block all inbound :9443
//	LOAD_PPROF          1 → capture cpu(15s)/mutex/block/goroutine pprof from each sampled host
//	                    at the end of every load step (knee) and right after fault revert
//	                    pause=docker pause≈SIGSTOP · stop=stop+start≈kill+restart ·
//	                    netdown=docker network disconnect/connect (full L3 partition of the
//	                    target, IP preserved on reconnect). :9443-only DROP/REJECT and the
//	                    asymmetric partition need NET_ADMIN+iptables in the versiond image —
//	                    not available in the generated compose (see results/19-repro.md).
//	LOAD_TARGET         service name | primary | survivor  (sticky primary/survivor of the warm escrow)
//	LOAD_SHAPE          short | long | stream
//	LOAD_RPS_SWEEP      e.g. "1,4,8,16,32,64" → knee sweep (no fault), LOAD_STEP_S per step (default 60)
//	LOAD_SAMPLE_HOSTS   comma list of services to sample (default versiond-0,versiond-1)
//	LOAD_OUT_DIR        artifact dir (default results-load/<ts>)
//	LOAD_NAME           free-text label stored in summary
//
// Artifacts: requests.jsonl, samples.jsonl (per-host RSS/threads/goroutines every 10s),
// summary.json, summary.md. The product invariants (503 rate, orphaned, time-to-
// recovery) are REPORTED, not asserted: the test fails only if the stack cannot boot.
// Keep the failure, keep the data.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"common/chain"
	"devshard/testenv/citest/harness"
	"devshard/testenv/config"
	inferencetypes "github.com/productscience/inference/x/inference/types"

	"github.com/stretchr/testify/require"
)

type loadReq struct {
	Seq       int     `json:"seq"`
	TStartMs  int64   `json:"t_start_ms"`
	LatencyMs int64   `json:"latency_ms"`
	Status    string  `json:"status"` // ok | 503 | 429 | 502 | err
	Err       string  `json:"err,omitempty"`
	Shape     string  `json:"shape"`
	RPS       float64 `json:"rps"`
}

type hostSample struct {
	TMs        int64  `json:"t_ms"`
	Service    string `json:"service"`
	RSSKb      int64  `json:"rss_kb"`
	Threads    int64  `json:"threads"`
	Goroutines int64  `json:"goroutines"` // -1 = unavailable
	Raw        string `json:"raw,omitempty"`
}

type bucket struct {
	TS  int64   `json:"t_s"`
	N   int     `json:"n"`
	Err float64 `json:"err_rate"`
}

var statusRe = regexp.MustCompile(`\b(4\d\d|5\d\d)\b`)

func envOrDef(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	if n, err := strconv.Atoi(envOrDef(k, "")); err == nil {
		return n
	}
	return d
}

func classify(err error) (string, string) {
	if err == nil {
		return "ok", ""
	}
	if harness.GatewayCapacityGone(err) {
		// Budget exhaustion ("no escrow can fund this request … insufficient escrow balance")
		// is the gateway refusing for lack of escrow funds, not a capacity/transport fault.
		// Wave 1 (runs 38450196300…38450281671) was 98 % this status from t≈20 s because the
		// seed escrow is 1_000_000 and a 16-token chat reserves ≈10.8 k; keep it apart from
		// real 503s so the knee and the fault window are never masked by the test budget.
		if strings.Contains(err.Error(), "insufficient escrow balance") {
			return "503-budget", err.Error()
		}
		return "503", err.Error()
	}
	if m := statusRe.FindString(err.Error()); m != "" {
		return m, err.Error()
	}
	return "err", err.Error()
}

func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[int(float64(len(sorted)-1)*p)]
}

func shellOut(name string, args ...string) (string, error) {
	b, err := exec.Command(name, args...).CombinedOutput()
	return string(b), err
}

func gitSHA() string {
	out, err := shellOut("git", "rev-parse", "--short", "HEAD")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(out)
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func modeLabel(rps int, sweep, fault string) string {
	if sweep != "" {
		return "L2-knee[" + sweep + "]"
	}
	m := "L1"
	switch {
	case rps <= 1:
		m = "L0-smoke"
	case rps >= 32:
		m = "L4+"
	}
	if fault != "none" {
		m += "+fault"
	}
	return m
}

// adminGET fetches an admin-gated gateway JSON endpoint into dest.
func adminGET(client *http.Client, url, key string, dest any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Admin-Api-Key", key)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	return json.Unmarshal(b, dest)
}

// orphanedCount counts gateway inference records not in a terminal state
// (RUN evidence for "orphaned"); field names are read defensively.
func orphanedCount(client *http.Client, gatewayURL, key string) (int, int, error) {
	var raw any
	if err := adminGET(client, gatewayURL+"/v1/debug/inferences", key, &raw); err != nil {
		return -1, -1, err
	}
	var recs []map[string]any
	switch v := raw.(type) {
	case []any:
		for _, r := range v {
			if m, ok := r.(map[string]any); ok {
				recs = append(recs, m)
			}
		}
	case map[string]any:
		for _, k := range []string{"inferences", "live", "items", "records"} {
			if arr, ok := v[k].([]any); ok {
				for _, r := range arr {
					if m, ok := r.(map[string]any); ok {
						recs = append(recs, m)
					}
				}
			}
		}
	}
	terminal := map[string]bool{"sealed": true, "finished": true, "settled": true, "finish_published": true, "done": true, "refused": true, "failed": true}
	orph := 0
	for _, m := range recs {
		st := ""
		for _, k := range []string{"status", "state", "stage", "terminal"} {
			if s, ok := m[k].(string); ok && s != "" {
				st = strings.ToLower(s)
				break
			}
		}
		if !terminal[st] {
			orph++
		}
	}
	return orph, len(recs), nil
}

func sampleHost(stack *harness.Stack, svc string, t0 time.Time) hostSample {
	s := hostSample{TMs: time.Since(t0).Milliseconds(), Service: svc, Goroutines: -1}
	out, err := stack.ComposeExecOutputTimeout(8*time.Second, svc, "sh", "-c",
		"grep -E 'VmRSS|Threads' /proc/1/status; for p in 5000 5001 5002; do wget -qO- http://127.0.0.1:$p/debug/pprof/goroutine?debug=1 2>/dev/null | head -1 && break; done; true")
	if err != nil {
		s.Raw = "exec-err: " + err.Error()
		return s
	}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		switch {
		case strings.HasPrefix(ln, "VmRSS") && len(f) >= 2:
			s.RSSKb, _ = strconv.ParseInt(f[1], 10, 64)
		case strings.HasPrefix(ln, "Threads") && len(f) >= 2:
			s.Threads, _ = strconv.ParseInt(f[1], 10, 64)
		case strings.HasPrefix(ln, "goroutine profile: total"):
			if n, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(ln, "goroutine profile: total")), 10, 64); err == nil {
				s.Goroutines = n
			}
		}
	}
	return s
}

// payloadFetchErrCount counts peer-RPC payload-fetch failures in the stack's versiond logs (host-side, best-effort).
func payloadFetchErrCount(projectHint string) string {
	names, err := shellOut("docker", "ps", "-a", "--format", "{{.Names}}")
	if err != nil {
		return "n/a"
	}
	cnt := 0
	for _, n := range strings.Fields(names) {
		if strings.Contains(n, "versiond-") && strings.Contains(n, projectHint) {
			if lg, err := shellOut("docker", "logs", n); err == nil {
				cnt += strings.Count(lg, "payload_fetch_err") + strings.Count(lg, "peer rpc session not ready")
			}
		}
	}
	return strconv.Itoa(cnt)
}

func TestLoadFault(t *testing.T) {
	harness.SkipUnlessEnv(t, "TESTENV_CITEST")
	harness.RequireDocker(t)

	rps := envInt("LOAD_RPS", 16)
	durationS := envInt("LOAD_DURATION_S", 300)
	pauseAtS := envInt("LOAD_PAUSE_AT_S", 91)
	pauseLenS := envInt("LOAD_PAUSE_LEN_S", 60)
	fault := envOrDef("LOAD_FAULT", "none")
	target := envOrDef("LOAD_TARGET", "primary")
	shape := envOrDef("LOAD_SHAPE", "short")
	sweep := envOrDef("LOAD_RPS_SWEEP", "")
	stepS := envInt("LOAD_STEP_S", 60)
	name := envOrDef("LOAD_NAME", "")
	outDir := envOrDef("LOAD_OUT_DIR", filepath.Join("results-load", time.Now().UTC().Format("20060102T150405Z")))
	require.NoError(t, os.MkdirAll(outDir, 0o755))

	// Boot like harness.BootStack but with a seed escrow sized for the run: LOAD_ESCROW
	// (default 1e11 ≈ 9 M short chats) so the budget is never the limiter under load.
	escrowAmt := uint64(envInt("LOAD_ESCROW", 0))
	if escrowAmt == 0 {
		escrowAmt = 100_000_000_000
	}
	// Topology: LOAD_HOSTS=2 → the HA pair (fault on the pair's sticky primary = 5.2/5.3 failover);
	// LOAD_HOSTS=4 → HA pair + two solo participants, 3 escrow slots — the colleague's #19 /
	// dev `loadtest` catch-up.yaml topology, where LOAD_TARGET=versiond-2 pauses a SOLO slot.
	nHosts := envInt("LOAD_HOSTS", 2)
	nSlots := envInt("LOAD_SLOTS", 0)
	if nSlots == 0 {
		nSlots = nHosts
		if nHosts == 4 {
			nSlots = 3
		}
	}
	stack := harness.NewStack(t, "citest-load-*")
	harness.RequireLinuxDevshardd(t, stack.TestenvDir)
	harness.WriteMultiConfig(t, stack.WorkDir, harness.MultiConfigOpts{Hosts: nHosts, EscrowSlots: nSlots, EscrowAmount: escrowAmt,
		MLNodes: envInt("LOAD_ML_NODES", 1), RefusalTimeout: int64(envInt("LOAD_REFUSAL_TIMEOUT_S", 0)), ExecutionTimeout: int64(envInt("LOAD_EXEC_TIMEOUT_S", 0))})
	// Control profile: LOAD_ML_TTFT / LOAD_ML_TOKEN_INTERVAL give the mock ML a realistic
	// serving latency (dev loadtest "realistic" profile = 250ms / 20ms) instead of zero-latency,
	// so the knee is measured with and without the GPU-shaped floor. Written as explicit
	// mock_openai.nodes (config.MockOpenAINodeCfg) into the generated config before gencompose.
	if ttft, ti := os.Getenv("LOAD_ML_TTFT"), os.Getenv("LOAD_ML_TOKEN_INTERVAL"); ttft != "" || ti != "" {
		p := filepath.Join(stack.WorkDir, "config.yaml")
		raw, rerr := os.ReadFile(p)
		require.NoError(t, rerr)
		var nodes strings.Builder
		nodes.WriteString("  nodes:\n")
		for i := 0; i < envInt("LOAD_ML_NODES", 1); i++ {
			nodes.WriteString(fmt.Sprintf("    - name: mock-openai-%d\n", i))
			if ttft != "" {
				nodes.WriteString(fmt.Sprintf("      ttft: %s\n", ttft))
			}
			if ti != "" {
				nodes.WriteString(fmt.Sprintf("      token_interval: %s\n", ti))
			}
		}
		patched := strings.Replace(string(raw), "mock_openai:\n", "mock_openai:\n"+nodes.String(), 1)
		require.NotEqual(t, string(raw), patched, "mock_openai block not found in generated config")
		require.NoError(t, os.WriteFile(p, []byte(patched), 0o644))
		t.Logf("mock ML control profile: ttft=%q token_interval=%q nodes=%d", ttft, ti, envInt("LOAD_ML_NODES", 1))
	}
	stack.RunGencompose(t)
	cfg := stack.LoadConfig(t)
	require.Len(t, cfg.Hosts, nHosts, "load stack host count")
	stack.Up(t)
	eps := stack.Endpoints(t, cfg)
	client := harness.HTTPClient()
	chatClient := harness.GatewayChatClient()
	adminKey := harness.TestenvAdminAPIKey
	t.Cleanup(func() {
		if t.Failed() {
			harness.DumpComposeLogs(t, stack, "devshardctl", "versiond-0", "versiond-1", "versiond-router")
		}
	})
	harness.WaitStackHealthy(t, stack, eps)
	harness.WaitGatewayChatReady(t, chatClient, eps.GatewayHTTP, 3*time.Minute, stack)
	version := cfg.Versiond.VersionName
	harness.WaitGETOK(t, client, eps.RouterHTTP+"/"+version+"/healthz", 5*time.Minute, "devshardd health via router", stack)
	model := config.PrimaryModelID(cfg)

	// Warm one escrow; resolve sticky primary / survivor host ids for LOAD_TARGET.
	harness.PostGatewayChatCompletion(t, chatClient, eps.GatewayHTTP, adminKey, harness.ChatCompletionRequest{
		Model: model, Messages: []harness.ChatMessage{{Role: "user", Content: "load warm"}}, MaxTokens: 8,
	})
	snap := harness.GetGatewaySessionSnapshot(t, client, eps.GatewayHTTP, adminKey)
	require.NotEmpty(t, snap.EscrowID)
	ledgerStart := harness.GetGatewayLedgerSnapshot(t, client, eps.GatewayHTTP, adminKey)
	t.Logf("ledger at start: balance=%d latest_nonce=%d (seed escrow amount %d)", ledgerStart.Balance, ledgerStart.LatestNonce, escrowAmt)
	_, upA, _, upB := harness.FindDistinctStickySessions(t, client, eps.RouterHTTP, version)
	primaryUp := harness.RequireResponseHeader(t, client, harness.RouterSessionURL(eps.RouterHTTP, version, snap.EscrowID, "/mempool"), harness.StickyUpstreamHeader)
	primaryHost := harness.HostIDForUpstream(cfg, primaryUp)
	survivorHost := harness.HostIDForUpstream(cfg, harness.OtherStickyUpstream(primaryUp, upA, upB))
	switch target {
	case "primary":
		target = primaryHost
	case "survivor":
		target = survivorHost
	}
	hosts := strings.Split(envOrDef("LOAD_SAMPLE_HOSTS", "versiond-0,versiond-1"), ",")

	prompt := "load short"
	if shape == "long" {
		prompt = strings.Repeat("The quick brown fox jumps over the lazy dog. ", 400) // ~18 KB
	}
	mkReq := func(i int) harness.ChatCompletionRequest {
		return harness.ChatCompletionRequest{
			Model: model, Messages: []harness.ChatMessage{{Role: "user", Content: fmt.Sprintf("%s #%d", prompt, i)}}, MaxTokens: 16,
		}
	}

	reqFile, err := os.Create(filepath.Join(outDir, "requests.jsonl"))
	require.NoError(t, err)
	defer reqFile.Close()
	sampFile, err := os.Create(filepath.Join(outDir, "samples.jsonl"))
	require.NoError(t, err)
	defer sampFile.Close()

	var (
		mu      sync.Mutex
		results []loadReq
		wg      sync.WaitGroup
	)
	t0 := time.Now()
	record := func(r loadReq) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, r)
		b, _ := json.Marshal(r)
		_, _ = reqFile.Write(append(b, '\n'))
	}
	fire := func(seq int, curRPS float64) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := time.Now()
			var e error
			if shape == "stream" {
				_, e = harness.TryPostGatewayChatCompletionStreamTimed(chatClient, eps.GatewayHTTP, adminKey, mkReq(seq))
			} else {
				_, e = harness.TryPostGatewayChatCompletion(chatClient, eps.GatewayHTTP, adminKey, mkReq(seq))
			}
			status, es := classify(e)
			record(loadReq{Seq: seq, TStartMs: st.Sub(t0).Milliseconds(), LatencyMs: time.Since(st).Milliseconds(), Status: status, Err: es, Shape: shape, RPS: curRPS})
		}()
	}

	// per-host sampler (RSS / threads / goroutines every 10s)
	stopSample := make(chan struct{})
	go func() {
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stopSample:
				return
			case <-tk.C:
				for _, h := range hosts {
					s := sampleHost(stack, strings.TrimSpace(h), t0)
					b, _ := json.Marshal(s)
					mu.Lock()
					_, _ = sampFile.Write(append(b, '\n'))
					mu.Unlock()
				}
			}
		}
	}()

	var runSteps [][2]int // {rps, seconds}
	if sweep != "" {
		for _, p := range strings.Split(sweep, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 {
				runSteps = append(runSteps, [2]int{n, stepS})
			}
		}
	} else {
		runSteps = append(runSteps, [2]int{rps, durationS})
	}
	harness.Step(t, "load start: steps=%v shape=%s fault=%s target=%s pauseAt=%ds len=%ds out=%s",
		runSteps, shape, fault, target, pauseAtS, pauseLenS, outDir)

	faultAt, faultOff := -1*time.Second, -1*time.Second
	applied, reverted := false, false
	netdownIP := ""
	seq := 0
	for _, step := range runSteps {
		curRPS, secs := step[0], step[1]
		tick := time.NewTicker(time.Second / time.Duration(curRPS))
		stepEnd := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(stepEnd) {
			<-tick.C
			el := time.Since(t0)
			if fault != "none" && sweep == "" {
				if !applied && el >= time.Duration(pauseAtS)*time.Second {
					faultAt = el
					harness.Step(t, "FAULT %s on %s at +%ds", fault, target, int(el.Seconds()))
					switch fault {
					case "pause":
						stack.PauseService(t, target)
					case "stop":
						stack.StopService(t, target)
					case "netdown":
						netdownIP = netdownApply(t, target)
					case "drop9443", "reject9443":
						iptables9443(t, target, fault, os.Getenv("LOAD_ASYM_FROM"), true)
					}
					applied = true
				}
				if applied && !reverted && el >= time.Duration(pauseAtS+pauseLenS)*time.Second {
					faultOff = el
					harness.Step(t, "REVERT %s on %s at +%ds", fault, target, int(el.Seconds()))
					switch fault {
					case "pause":
						stack.UnpauseService(t, target)
					case "stop":
						stack.StartService(t, target)
					case "netdown":
						netdownRevert(t, target, netdownIP)
					case "drop9443", "reject9443":
						iptables9443(t, target, fault, os.Getenv("LOAD_ASYM_FROM"), false)
					}
					reverted = true
					if os.Getenv("LOAD_PPROF") == "1" {
						capturePprof(t, stack, hosts, outDir, "after-revert")
					}
				}
			}
			seq++
			fire(seq, float64(curRPS))
		}
		tick.Stop()
		if os.Getenv("LOAD_PPROF") == "1" {
			capturePprof(t, stack, hosts, outDir, fmt.Sprintf("step-%drps", curRPS))
		}
	}
	wg.Wait()
	const drain = 60 * time.Second
	harness.Step(t, "load done, draining %s", drain)
	time.Sleep(drain)
	close(stopSample)

	// ---- analysis ----
	mu.Lock()
	rs := append([]loadReq(nil), results...)
	mu.Unlock()
	sort.Slice(rs, func(i, j int) bool { return rs[i].TStartMs < rs[j].TStartMs })
	byStatus := map[string]int{}
	var lat []int64
	for _, r := range rs {
		byStatus[r.Status]++
		if r.Status == "ok" {
			lat = append(lat, r.LatencyMs)
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	errRate := func(from, to int64) (float64, int) {
		n, bad := 0, 0
		for _, r := range rs {
			if r.TStartMs >= from && r.TStartMs < to {
				n++
				if r.Status != "ok" {
					bad++
				}
			}
		}
		if n == 0 {
			return 0, 0
		}
		return float64(bad) / float64(n), n
	}
	endMs := time.Since(t0).Milliseconds()
	var buckets []bucket
	for b := int64(0); b < endMs; b += 10000 {
		e, n := errRate(b, b+10000)
		buckets = append(buckets, bucket{TS: b / 1000, N: n, Err: e})
	}
	ttr := "n/a"
	if reverted {
		ttr = "none"
		for b := faultOff.Milliseconds(); b+30000 <= endMs; b += 10000 {
			if e, n := errRate(b, b+30000); n > 0 && e < 0.05 {
				ttr = fmt.Sprintf("%ds", (b-faultOff.Milliseconds())/1000)
				break
			}
		}
	}
	orph, recs, oerr := orphanedCount(client, eps.GatewayHTTP, adminKey)
	pfe := payloadFetchErrCount("citest-load")
	escFound, escSettled, escErr := escrowFate(t, eps, snap.EscrowID)
	metrics := scrapeMetrics(t, client, stack, eps, hosts)
	ledgerEnd := harness.GetGatewayLedgerSnapshot(t, client, eps.GatewayHTTP, adminKey)
	var costPerOK uint64
	if byStatus["ok"] > 0 && ledgerStart.Balance > ledgerEnd.Balance {
		costPerOK = (ledgerStart.Balance - ledgerEnd.Balance) / uint64(byStatus["ok"])
	}

	summary := map[string]any{
		"escrow_amount": escrowAmt, "ledger_start": ledgerStart, "ledger_end": ledgerEnd, "cost_per_ok": costPerOK,
		"name": name, "mode": modeLabel(rps, sweep, fault), "rps": rps, "sweep": sweep, "shape": shape,
		"fault": fault, "target": target, "pause_at_s": pauseAtS, "pause_len_s": pauseLenS,
		"fault_at_s": int(faultAt.Seconds()), "fault_off_s": int(faultOff.Seconds()),
		"total": len(rs), "by_status": byStatus,
		"p50_ms": percentile(lat, 0.50), "p95_ms": percentile(lat, 0.95), "p99_ms": percentile(lat, 0.99),
		"orphaned": orph, "gateway_records": recs, "orphan_query_err": fmt.Sprint(oerr),
		"time_to_recovery": ttr, "payload_fetch_err": pfe, "buckets_10s": buckets,
		"escrow": snap.EscrowID, "escrow_found": escFound, "escrow_settled": escSettled, "escrow_query_err": escErr,
		"metrics": metrics,
		"primary": primaryHost, "survivor": survivorHost, "sha": gitSHA(),
	}
	sb, _ := json.MarshalIndent(summary, "", " ")
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "summary.json"), sb, 0o644))
	md := fmt.Sprintf("| %s | %s | %s/%s | %d | ok=%d 503=%d 503-budget=%d 429=%d 502=%d err=%d | p50=%dms p95=%dms p99=%dms | orphaned=%d/%d | ttr=%s | pfe=%s | balance %d→%d cost/ok≈%d |\n",
		name, modeLabel(rps, sweep, fault), fault, target, len(rs), byStatus["ok"], byStatus["503"], byStatus["503-budget"], byStatus["429"], byStatus["502"], byStatus["err"],
		percentile(lat, 0.5), percentile(lat, 0.95), percentile(lat, 0.99), orph, recs, ttr, pfe, ledgerStart.Balance, ledgerEnd.Balance, costPerOK)
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "summary.md"), []byte(md), 0o644))
	t.Logf("LOAD-SUMMARY %s", md)
	t.Logf("LOAD-BUCKETS %s", mustJSON(buckets))
}

// netdownContainer resolves the compose container for a service of this test's stack.
func netdownContainer(t *testing.T, service string) (ctr, network string) {
	t.Helper()
	out, err := shellOut("docker", "ps", "--format", "{{.Names}}")
	require.NoError(t, err)
	for _, n := range strings.Fields(out) {
		if strings.HasPrefix(n, "citest-load-") && strings.HasSuffix(n, "-"+service+"-1") {
			project := strings.TrimSuffix(n, "-"+service+"-1")
			return n, project + "_testenv"
		}
	}
	t.Fatalf("netdown: container for service %q not found", service)
	return "", ""
}

// netdownApply partitions the target at L3 (docker network disconnect) and
// returns its static IP so revert can restore the same address (otherwise the
// run would also be scenario 1.9 "peer IP changed").
func netdownApply(t *testing.T, service string) string {
	t.Helper()
	ctr, net := netdownContainer(t, service)
	ip, err := shellOut("docker", "inspect", "-f", `{{(index .NetworkSettings.Networks "`+net+`").IPAddress}}`, ctr)
	require.NoError(t, err)
	ip = strings.TrimSpace(ip)
	out, err := shellOut("docker", "network", "disconnect", net, ctr)
	require.NoError(t, err, out)
	t.Logf("netdown: disconnected %s from %s (ip %s)", ctr, net, ip)
	return ip
}

func netdownRevert(t *testing.T, service, ip string) {
	t.Helper()
	ctr, net := netdownContainer(t, service)
	args := []string{"network", "connect"}
	if ip != "" {
		args = append(args, "--ip", ip)
	}
	args = append(args, net, ctr)
	out, err := shellOut("docker", args...)
	require.NoError(t, err, out)
	t.Logf("netdown: reconnected %s to %s (ip %s)", ctr, net, ip)
}

// iptables9443 blocks (apply=true) or unblocks the target's :9443 using a
// privileged sidecar that shares the target's network namespace — no image
// or compose change needed. mode drop9443 → -j DROP, reject9443 → -j REJECT.
// asymFrom != "" restricts to packets from that service's IP (B→A closed,
// A→B open = the asymmetric partition).
func iptables9443(t *testing.T, target, mode, asymFrom string, apply bool) {
	t.Helper()
	ctr, net := netdownContainer(t, target)
	act := "DROP"
	if mode == "reject9443" {
		act = "REJECT"
	}
	src := ""
	if asymFrom != "" {
		fromCtr, _ := netdownContainer(t, asymFrom)
		ip, err := shellOut("docker", "inspect", "-f", `{{(index .NetworkSettings.Networks "`+net+`").IPAddress}}`, fromCtr)
		require.NoError(t, err)
		src = " -s " + strings.TrimSpace(ip)
	}
	op := "-A"
	if !apply {
		op = "-D"
	}
	rule := fmt.Sprintf("iptables %s INPUT -p tcp --dport 9443%s -j %s", op, src, act)
	out, err := shellOut("docker", "run", "--rm", "--net=container:"+ctr, "--cap-add", "NET_ADMIN", "alpine:3.19",
		"sh", "-c", "apk add --no-cache iptables >/dev/null 2>&1; "+rule+" && iptables -S INPUT")
	require.NoError(t, err, out)
	t.Logf("iptables9443 apply=%v on %s: %s\n%s", apply, ctr, rule, out)
}

// capturePprof pulls cpu/mutex/block/goroutine profiles from the child
// devshardd (versiond BasePort 5000) of each sampled host into outDir.
func capturePprof(t *testing.T, stack *harness.Stack, hosts []string, outDir, tag string) {
	t.Helper()
	profiles := map[string]string{
		"cpu":       "profile?seconds=15",
		"mutex":     "mutex",
		"block":     "block",
		"goroutine": "goroutine?debug=1",
	}
	ports := envOrDef("LOAD_PPROF_PORTS", "5000 5001 5002 6060 8080")
	// fetch: wget or curl, whichever the image has; `|| true` keeps the loop going per port.
	fetch := func(q string) string {
		return "for p in " + ports + "; do u=\"http://127.0.0.1:$p/debug/pprof/" + q + "\"; " +
			"if command -v wget >/dev/null; then o=$(wget -qO- \"$u\" 2>/dev/null); else o=$(curl -sf --max-time 30 \"$u\" 2>/dev/null); fi; " +
			"[ -n \"$o\" ] && { printf '%s' \"$o\" | base64 | tr -d '\\n'; exit 0; }; done; exit 1"
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if !pprofDiagDone[h] {
			pprofDiagDone[h] = true
			diag, _ := stack.ComposeExecOutputTimeout(20*time.Second, h, "sh", "-c",
				"echo tools: $(command -v wget) $(command -v curl); echo listeners:; (netstat -tln 2>/dev/null || ss -tln 2>/dev/null || cat /proc/net/tcp) | head -20; for p in "+ports+"; do printf '%s: ' $p; (wget -qO- http://127.0.0.1:$p/debug/pprof/ 2>/dev/null || curl -s --max-time 3 http://127.0.0.1:$p/debug/pprof/ 2>/dev/null) | head -c 80; echo; done")
			t.Logf("pprof diag %s: %s", h, strings.TrimSpace(diag))
		}
		for name, q := range profiles {
			out, err := stack.ComposeExecOutputTimeout(60*time.Second, h, "sh", "-c", fetch(q))
			if err != nil || strings.TrimSpace(out) == "" {
				t.Logf("pprof %s/%s %s: unavailable (%v)", h, name, tag, err)
				continue
			}
			raw, derr := decodeB64(strings.TrimSpace(out))
			if derr != nil {
				t.Logf("pprof %s/%s %s: decode: %v", h, name, tag, derr)
				continue
			}
			ext := ".pb.gz"
			if name == "goroutine" {
				ext = ".txt"
			}
			fn := filepath.Join(outDir, fmt.Sprintf("pprof-%s-%s-%s%s", h, name, tag, ext))
			if werr := os.WriteFile(fn, raw, 0o644); werr == nil {
				t.Logf("pprof saved %s (%d bytes)", fn, len(raw))
			}
		}
	}
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

var pprofDiagDone = map[string]bool{}

// escrowFate queries the mock chain for the warm escrow's on-chain state (Phase 1b in testenv).
// The mock store models only {not-found, unsettled, settled} — no refund/expiry — so the
// "refunded on timeout" branch can only be answered on a real chain. Non-fatal.
func escrowFate(t *testing.T, eps harness.Endpoints, escrowID string) (found, settled bool, errStr string) {
	t.Helper()
	id, err := strconv.ParseUint(escrowID, 10, 64)
	if err != nil {
		return false, false, "parse: " + err.Error()
	}
	conn := harness.DialMockChainGRPC(t, eps)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, qerr := chain.NewFromConn(conn).InferenceQueryClient().DevshardEscrow(ctx, &inferencetypes.QueryGetDevshardEscrowRequest{Id: id})
	if qerr != nil {
		return false, false, qerr.Error()
	}
	return resp.GetFound(), resp.GetEscrow().GetSettled(), ""
}

// scrapeMetrics collects the X1 observability counters (orphan / timeout / fetch) from the
// gateway and from each versiond child at run end. RUN evidence for "is #19 visible?".
func scrapeMetrics(t *testing.T, client *http.Client, stack *harness.Stack, eps harness.Endpoints, hosts []string) map[string]string {
	t.Helper()
	want := []string{"devshard_receipt_orphan_total", "devshard_validation_orphan_total", "devshard_inference_timeouts_total",
		"devshard_gateway_timeout_actions_total", "devshard_payload_fetch_ttfb_seconds_count", "devshard_payload_fetch_ttfb_seconds_sum"}
	out := map[string]string{}
	pick := func(src, body string) {
		for _, ln := range strings.Split(body, "\n") {
			if strings.HasPrefix(ln, "#") {
				continue
			}
			for _, w := range want {
				if strings.HasPrefix(ln, w) {
					out[src+":"+ln[:strings.IndexAny(ln+" ", " ")]] = strings.TrimSpace(ln[strings.LastIndex(ln, " ")+1:])
				}
			}
		}
	}
	if resp, err := client.Get(eps.GatewayHTTP + "/metrics"); err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		pick("gateway", string(b))
	} else {
		out["gateway:err"] = err.Error()
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		body, err := stack.ComposeExecOutputTimeout(15*time.Second, h, "sh", "-c",
			"for p in 5000 5001 5002; do wget -qO- http://127.0.0.1:$p/metrics 2>/dev/null && break; done")
		if err != nil {
			out[h+":err"] = err.Error()
			continue
		}
		pick(h, body)
	}
	return out
}
