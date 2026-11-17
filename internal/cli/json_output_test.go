/*
json_output_test.go

End-to-end tests of `angela scan --json` with a fake OSV scan (no network)

Tests:
  TestScanJSON         - stdout is only JSON, parsed back into types.Report
  TestScanJSONCompact  - --json-compact prints exactly one line
  TestScanJSONOSVError - an OSV failure lands in "errors", vulnerabilities_scanned
                         is false, vulnerabilities is [], and the run fails
  TestJSONFlagsExclusive - --json and --json-compact together are rejected
  TestArgsWantJSON     - detects --json even when cobra never parsed it
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

	"github.com/CarterPerez-dev/angela/pkg/types"
)

func runCLI(
	t *testing.T,
	fake func(context.Context, []types.Dependency) (map[string][]types.Vulnerability, error),
	args ...string,
) (string, error) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "requirements.txt")
	content := "django==3.2.0\nrequests==2.25.0\nclick>=8.0.0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	origOut, origScan := stdout, scanVulns
	stdout, scanVulns = &buf, fake
	t.Cleanup(func() { stdout, scanVulns = origOut, origScan })

	root := newRootCmd()
	root.SetArgs(append([]string{"scan", "--file", path}, args...))
	err := root.Execute()
	return buf.String(), err
}

func fakeVulns(
	_ context.Context, _ []types.Dependency,
) (map[string][]types.Vulnerability, error) {
	return map[string][]types.Vulnerability{
		"requests": {{ID: "GHSA-r", Severity: "MODERATE"}},
		"django": {
			{ID: "GHSA-d1", Severity: "LOW"},
			{ID: "GHSA-d2", Severity: "CRITICAL", Aliases: []string{"CVE-1"}},
		},
	}, nil
}

func TestScanJSON(t *testing.T) {
	out, err := runCLI(t, fakeVulns, "--json")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(out, "{") {
		t.Fatalf("stdout must start with JSON, got %q", out[:min(40, len(out))])
	}

	var r types.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if r.Command != "scan" || r.Summary.TotalPackages != 3 ||
		r.Summary.TotalVulns != 3 || !r.Summary.VulnsScanned {
		t.Errorf("report header/summary = %+v", r)
	}
	if len(r.Vulnerabilities) != 2 ||
		r.Vulnerabilities[0].Package != "django" ||
		r.Vulnerabilities[0].Version != "3.2.0" {
		t.Fatalf("vulnerabilities = %+v", r.Vulnerabilities)
	}
	if r.Vulnerabilities[0].Vulnerabilities[0].ID != "GHSA-d2" {
		t.Error("CRITICAL should come first")
	}
	if strings.Contains(out, `"aliases": null`) {
		t.Error("aliases must be [] not null")
	}
}

func TestScanJSONCompact(t *testing.T) {
	out, err := runCLI(t, fakeVulns, "--json-compact")
	if err != nil {
		t.Fatal(err)
	}

	if lines := strings.Count(strings.TrimSpace(out), "\n"); lines != 0 {
		t.Errorf("compact output has %d line breaks", lines)
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("invalid JSON: %s", out)
	}
}

func TestScanJSONOSVError(t *testing.T) {
	failing := func(
		_ context.Context, _ []types.Dependency,
	) (map[string][]types.Vulnerability, error) {
		return nil, errors.New("osv unavailable")
	}

	out, err := runCLI(t, failing, "--json")
	if !errors.Is(err, errAlreadyReported) {
		t.Errorf("err = %v, want errAlreadyReported (exit 1)", err)
	}

	var r types.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "osv unavailable") {
		t.Errorf("errors = %v", r.Errors)
	}
	if !strings.Contains(out, `"vulnerabilities": []`) {
		t.Errorf("vulnerabilities must be []: %s", out)
	}
	if r.Summary.VulnsScanned {
		t.Error("vulnerabilities_scanned must be false when OSV failed")
	}
}

func TestJSONFlagsExclusive(t *testing.T) {
	_, err := runCLI(t, fakeVulns, "--json", "--json-compact")
	if err == nil {
		t.Error("expected an error for --json with --json-compact")
	}
}

func TestArgsWantJSON(t *testing.T) {
	t.Parallel()

	if !argsWantJSON([]string{"scan", "--bogus", "--json"}) {
		t.Error("should detect --json")
	}
	if argsWantJSON([]string{"scan", "--file", "x.txt"}) {
		t.Error("no JSON flag given")
	}
}
