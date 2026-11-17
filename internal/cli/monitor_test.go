/*
monitor_test.go

Tests for `angela monitor` with a fake scan (no network)

Tests:
  TestMonitorAlertsOnlyOnce        - baseline, then a new CVE alerts once
  TestMonitorVersionBumpResolves   - bumping the pinned version resolves alerts
  TestMonitorScanErrorKeepsState   - a failed scan never touches the state
  TestMonitorRestartNoRepeat       - a new session over the same state is quiet
  TestMonitorRunOnce               - --once runs one round; a failure exits 1
  TestMonitorRunStopsOnCancel      - Ctrl+C ends the loop and saves the state
  TestMonitorJSONLines             - --json prints one valid JSON per round
  TestMonitorLogFile               - the log gets one line per alert
  TestIsPinned                     - only == / === specs count as pinned
  TestDefaultStatePath             - one stable state file per dependency file
  TestShortDuration                - 1h instead of 1h0m0s
  TestExpandHome                   - ~/ in flag values points at the home dir
  TestMonitorCmdMinInterval        - intervals under 1m are rejected
  TestMonitorCmdOnceEndToEnd       - real command twice, then a version bump
*/

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/angela/internal/monitor"
	"github.com/CarterPerez-dev/angela/pkg/types"
)

var (
	vulnA = types.Vulnerability{
		ID: "GHSA-aaaa", Severity: "HIGH", Summary: "old bug",
		Aliases: []string{"CVE-2021-0001"},
	}
	vulnB = types.Vulnerability{
		ID: "GHSA-bbbb", Severity: "CRITICAL", Summary: "fresh advisory",
	}
)

func snapOf(
	version string,
	vulns ...types.Vulnerability,
) monitor.Snapshot {
	s := monitor.Snapshot{
		File:      "/abs/req.txt",
		ScannedAt: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC),
		Versions:  map[string]string{"django": version},
		Vulns:     map[string][]types.Vulnerability{},
	}
	if len(vulns) > 0 {
		s.Vulns["django"] = vulns
	}
	return s
}

// scripted returns a scan function that plays back results in order
type scripted struct {
	steps []func() (monitor.Snapshot, error)
	calls int
}

func (s *scripted) scan(context.Context) (monitor.Snapshot, error) {
	step := s.steps[s.calls]
	s.calls++
	return step()
}

func ok(snap monitor.Snapshot) func() (monitor.Snapshot, error) {
	return func() (monitor.Snapshot, error) { return snap, nil }
}

func fail(msg string) func() (monitor.Snapshot, error) {
	return func() (monitor.Snapshot, error) {
		return monitor.Snapshot{}, errors.New(msg)
	}
}

type testLoop struct {
	*monitorLoop
	out, log *bytes.Buffer
	script   *scripted
}

func newTestLoop(
	t *testing.T,
	statePath string,
	steps ...func() (monitor.Snapshot, error),
) *testLoop {
	t.Helper()
	state, err := monitor.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	tl := &testLoop{
		out:    &bytes.Buffer{},
		log:    &bytes.Buffer{},
		script: &scripted{steps: steps},
	}
	tl.monitorLoop = &monitorLoop{
		scan:      tl.script.scan,
		state:     state,
		statePath: statePath,
		file:      "req.txt",
		out:       tl.out,
		log:       tl.log,
	}
	return tl
}

// step runs one round and returns what it printed
func (tl *testLoop) step(t *testing.T) string {
	t.Helper()
	tl.out.Reset()
	scanErr, err := tl.round(context.Background())
	if err != nil || scanErr != nil {
		t.Fatalf("round failed: %v %v", scanErr, err)
	}
	return tl.out.String()
}

func statePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state.json")
}

func TestMonitorAlertsOnlyOnce(t *testing.T) {
	fixedNow(t)
	tl := newTestLoop(t, statePath(t),
		ok(snapOf("3.2.0", vulnA)),
		ok(snapOf("3.2.0", vulnA)),
		ok(snapOf("3.2.0", vulnA, vulnB)),
		ok(snapOf("3.2.0", vulnA, vulnB)),
	)

	if out := tl.step(t); !strings.Contains(out, "baseline: 1 known") ||
		strings.Contains(out, "NEW") {
		t.Errorf("round 1 should be a quiet baseline:\n%s", out)
	}
	if out := tl.step(t); !strings.Contains(out, "no changes") {
		t.Errorf("round 2 should report no changes:\n%s", out)
	}
	out := tl.step(t)
	if strings.Count(out, "NEW") != 1 || !strings.Contains(out, "GHSA-bbbb") {
		t.Errorf("round 3 should alert GHSA-bbbb once:\n%s", out)
	}
	if strings.Contains(out, "GHSA-aaaa") {
		t.Errorf("round 3 repeated an old alert:\n%s", out)
	}
	if out := tl.step(t); strings.Contains(out, "NEW") {
		t.Errorf("round 4 repeated the alert:\n%s", out)
	}
}

func TestMonitorVersionBumpResolves(t *testing.T) {
	fixedNow(t)
	tl := newTestLoop(t, statePath(t),
		ok(snapOf("3.2.0", vulnA)),
		ok(snapOf("4.2.16")),
	)

	tl.step(t)
	out := tl.step(t)
	if !strings.Contains(out, "RESOLVED") ||
		!strings.Contains(out, "django 3.2.0  GHSA-aaaa") {
		t.Errorf("bump should resolve GHSA-aaaa:\n%s", out)
	}
	if strings.Contains(out, "NEW") {
		t.Errorf("bump to a clean version raised an alert:\n%s", out)
	}
}

func TestMonitorScanErrorKeepsState(t *testing.T) {
	fixedNow(t)
	path := statePath(t)
	tl := newTestLoop(t, path,
		ok(snapOf("3.2.0", vulnA)),
		fail("osv.dev unreachable"),
		ok(snapOf("3.2.0", vulnA)),
	)

	tl.step(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	tl.out.Reset()
	scanErr, err := tl.round(context.Background())
	if err != nil || scanErr == nil {
		t.Fatalf("scanErr=%v err=%v", scanErr, err)
	}
	if !strings.Contains(tl.out.String(), "scan failed, state kept") {
		t.Errorf("failure not reported:\n%s", tl.out.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a failed scan changed the state file")
	}

	if out := tl.step(t); strings.Contains(out, "RESOLVED") ||
		strings.Contains(out, "NEW") {
		t.Errorf("round after the failure should be quiet:\n%s", out)
	}
}

func TestMonitorRestartNoRepeat(t *testing.T) {
	fixedNow(t)
	path := statePath(t)

	first := newTestLoop(t, path, ok(snapOf("3.2.0", vulnA, vulnB)))
	first.step(t)

	second := newTestLoop(t, path, ok(snapOf("3.2.0", vulnA, vulnB)))
	out := second.step(t)
	if strings.Contains(out, "NEW") || strings.Contains(out, "baseline") {
		t.Errorf("restart repeated alerts:\n%s", out)
	}
	if !strings.Contains(out, "no changes since the saved state") {
		t.Errorf("unexpected restart output:\n%s", out)
	}
}

func TestMonitorRunOnce(t *testing.T) {
	fixedNow(t)
	tl := newTestLoop(t, statePath(t), ok(snapOf("3.2.0", vulnA)))
	if err := tl.run(context.Background(), time.Hour, true); err != nil {
		t.Fatal(err)
	}
	if tl.script.calls != 1 {
		t.Errorf("--once ran %d rounds", tl.script.calls)
	}

	bad := newTestLoop(t, statePath(t), fail("down"))
	err := bad.run(context.Background(), time.Hour, true)
	if !errors.Is(err, errAlreadyReported) {
		t.Errorf("failed --once should exit 1, got %v", err)
	}
}

func TestMonitorRunStopsOnCancel(t *testing.T) {
	fixedNow(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	path := statePath(t)
	tl := newTestLoop(t, path,
		ok(snapOf("3.2.0", vulnA)),
		func() (monitor.Snapshot, error) {
			cancel() // Ctrl+C arrives in the middle of round 2
			return monitor.Snapshot{}, context.Canceled
		},
	)

	if err := tl.run(ctx, time.Millisecond, false); err != nil {
		t.Fatal(err)
	}
	out := tl.out.String()
	if !strings.Contains(out, "state saved to "+path) {
		t.Errorf("missing save message:\n%s", out)
	}
	if strings.Contains(out, "scan failed") {
		t.Errorf("Ctrl+C was reported as a scan failure:\n%s", out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("state not saved: %v", err)
	}
}

func TestMonitorJSONLines(t *testing.T) {
	fixedNow(t)
	tl := newTestLoop(t, statePath(t),
		ok(snapOf("3.2.0", vulnA)),
		ok(snapOf("3.2.0", vulnA, vulnB)),
		fail("osv down"),
	)
	tl.json = true

	var rounds []monitorRound
	for range 3 {
		_, _ = tl.round(context.Background()) //nolint:errcheck
	}
	for _, line := range strings.Split(strings.TrimSpace(tl.out.String()), "\n") {
		var r monitorRound
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("not JSON: %q (%v)", line, err)
		}
		rounds = append(rounds, r)
	}

	if len(rounds) != 3 {
		t.Fatalf("got %d JSON lines, want 3", len(rounds))
	}
	if !rounds[0].Baseline || len(rounds[0].New) != 1 {
		t.Errorf("round 1 = %+v", rounds[0])
	}
	if rounds[1].Baseline || len(rounds[1].New) != 1 ||
		rounds[1].New[0].Vulnerability.ID != "GHSA-bbbb" {
		t.Errorf("round 2 = %+v", rounds[1])
	}
	if rounds[2].Error != "osv down" {
		t.Errorf("round 3 = %+v", rounds[2])
	}
	if strings.Contains(tl.out.String(), `"aliases":null`) ||
		strings.Contains(tl.out.String(), `"resolved":null`) {
		t.Errorf("null arrays in JSON:\n%s", tl.out.String())
	}
}

func TestMonitorLogFile(t *testing.T) {
	fixedNow(t)
	tl := newTestLoop(t, statePath(t),
		ok(snapOf("3.2.0", vulnA)),
		ok(snapOf("3.2.0", vulnA)),
		ok(snapOf("3.2.0", vulnA, vulnB)),
		ok(snapOf("4.2.16")),
	)
	for range 4 {
		tl.step(t)
	}

	want := []string{
		"2026-11-19T12:00:00Z BASELINE file=req.txt known=1",
		"2026-11-19T12:00:00Z NEW django 3.2.0 GHSA-bbbb CRITICAL",
		// most severe first: GHSA-bbbb is CRITICAL, GHSA-aaaa is HIGH
		"2026-11-19T12:00:00Z RESOLVED django 3.2.0 GHSA-bbbb",
		"2026-11-19T12:00:00Z RESOLVED django 3.2.0 GHSA-aaaa",
	}
	got := strings.Split(strings.TrimSpace(tl.log.String()), "\n")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("log =\n%s\nwant\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestIsPinned(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"==3.2.0":       true,
		"===3.2.0":      true,
		">=3.2.0":       false,
		"==3.2.*":       false,
		"==3.2.0,<4":    false,
		"~=3.2":         false,
		"":              false,
		">=2.0,==2.1.0": false,
	}
	for spec, want := range cases {
		if got := isPinned(spec); got != want {
			t.Errorf("isPinned(%q) = %v, want %v", spec, got, want)
		}
	}
}

func TestDefaultStatePath(t *testing.T) {
	t.Parallel()

	a := defaultStatePath("/proj/a/requirements.txt")
	b := defaultStatePath("/proj/b/requirements.txt")
	if a != defaultStatePath("/proj/a/requirements.txt") {
		t.Error("state path is not stable")
	}
	if a == b {
		t.Error("two files share one state")
	}
	if filepath.Base(filepath.Dir(a)) != "monitor" ||
		!strings.HasPrefix(filepath.Base(a), "requirements.txt-") ||
		filepath.Ext(a) != ".json" {
		t.Errorf("unexpected path %s", a)
	}
}

func TestShortDuration(t *testing.T) {
	t.Parallel()

	cases := map[time.Duration]string{
		time.Minute:                 "1m",
		time.Hour:                   "1h",
		90 * time.Minute:            "1h30m",
		90 * time.Second:            "1m30s",
		2*time.Hour + 5*time.Second: "2h0m5s",
		45 * time.Second:            "45s",
	}
	for d, want := range cases {
		if got := shortDuration(d); got != want {
			t.Errorf("shortDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestExpandHome(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	if got := expandHome("~/.angela/monitor.log"); got !=
		filepath.Join(home, ".angela", "monitor.log") {
		t.Errorf("expandHome = %q", got)
	}
	if got := expandHome("/abs/x.log"); got != "/abs/x.log" {
		t.Errorf("absolute path changed: %q", got)
	}
	if got := expandHome(""); got != "" {
		t.Errorf("empty path changed: %q", got)
	}
}

func runMonitorCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	orig := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = orig })

	root := newRootCmd()
	root.SetArgs(append([]string{"monitor"}, args...))
	err := root.Execute()
	return buf.String(), err
}

func TestMonitorCmdMinInterval(t *testing.T) {
	file := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(file, []byte("django==3.2.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runMonitorCLI(t, "--file", file, "--interval", "30s")
	if err == nil || !strings.Contains(err.Error(), "at least 1m") {
		t.Errorf("err = %v", err)
	}
}

func TestMonitorCmdOnceEndToEnd(t *testing.T) {
	fixedNow(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "requirements.txt")
	write := func(content string) {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	origScan := scanVulns
	scanVulns = func(
		_ context.Context, deps []types.Dependency,
	) (map[string][]types.Vulnerability, error) {
		for _, d := range deps {
			if d.Name == "django" && d.Spec == "==3.2.0" {
				return map[string][]types.Vulnerability{
					"django": {vulnA},
				}, nil
			}
		}
		return nil, nil
	}
	t.Cleanup(func() { scanVulns = origScan })

	args := []string{
		"--file", file, "--once",
		"--state", filepath.Join(dir, "state.json"),
		"--log", filepath.Join(dir, "monitor.log"),
	}

	write("django==3.2.0\nclick>=8.0\n")
	out, err := runMonitorCLI(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "baseline: 1 known") ||
		!strings.Contains(out, "click>=8.0 is not pinned") {
		t.Errorf("first run:\n%s", out)
	}

	out, err = runMonitorCLI(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "NEW") || !strings.Contains(out, "no changes") {
		t.Errorf("second run repeated alerts:\n%s", out)
	}

	write("django==4.2.16\nclick>=8.0\n")
	out, err = runMonitorCLI(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "RESOLVED") {
		t.Errorf("version bump not resolved:\n%s", out)
	}

	logData, err := os.ReadFile(filepath.Join(dir, "monitor.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "RESOLVED django 3.2.0 GHSA-aaaa") {
		t.Errorf("log:\n%s", logData)
	}
}
