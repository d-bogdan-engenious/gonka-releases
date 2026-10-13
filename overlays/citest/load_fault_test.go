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
//	LOAD_FAULT          none | pause | stop   (pause=docker pause≈SIGSTOP, stop=stop+start≈kill+restart)
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

	"devshard/testenv/citest/harness"
	"devshard/testenv/config"

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
		"grep -E 'VmRSS|Threads' /proc/1/status; (wget -qO- http://127.0.0.1:8080/debug/pprof/goroutine?debug=1 2>/dev/null | head -1) || true")
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

	stack, cfg, eps := harness.BootStack(t, "citest-load-*")
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
					}
					reverted = true
				}
			}
			seq++
			fire(seq, float64(curRPS))
		}
		tick.Stop()
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

	summary := map[string]any{
		"name": name, "mode": modeLabel(rps, sweep, fault), "rps": rps, "sweep": sweep, "shape": shape,
		"fault": fault, "target": target, "pause_at_s": pauseAtS, "pause_len_s": pauseLenS,
		"fault_at_s": int(faultAt.Seconds()), "fault_off_s": int(faultOff.Seconds()),
		"total": len(rs), "by_status": byStatus,
		"p50_ms": percentile(lat, 0.50), "p95_ms": percentile(lat, 0.95), "p99_ms": percentile(lat, 0.99),
		"orphaned": orph, "gateway_records": recs, "orphan_query_err": fmt.Sprint(oerr),
		"time_to_recovery": ttr, "payload_fetch_err": pfe, "buckets_10s": buckets,
		"escrow": snap.EscrowID, "primary": primaryHost, "survivor": survivorHost, "sha": gitSHA(),
	}
	sb, _ := json.MarshalIndent(summary, "", " ")
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "summary.json"), sb, 0o644))
	md := fmt.Sprintf("| %s | %s | %s/%s | %d | ok=%d 503=%d 429=%d 502=%d err=%d | p50=%dms p95=%dms p99=%dms | orphaned=%d/%d | ttr=%s | pfe=%s |\n",
		name, modeLabel(rps, sweep, fault), fault, target, len(rs), byStatus["ok"], byStatus["503"], byStatus["429"], byStatus["502"], byStatus["err"],
		percentile(lat, 0.5), percentile(lat, 0.95), percentile(lat, 0.99), orph, recs, ttr, pfe)
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "summary.md"), []byte(md), 0o644))
	t.Logf("LOAD-SUMMARY %s", md)
	t.Logf("LOAD-BUCKETS %s", mustJSON(buckets))
}
