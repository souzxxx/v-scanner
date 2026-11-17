/*
json_output_test.go

End-to-end tests of `angela scan --json` with a fake OSV scan (no network)

Tests:
  TestScanJSON         - stdout is only JSON, parsed back into types.Report
  TestScanJSONCompact  - --json-compact prints exactly one line
  TestScanJSONOSVError - an OSV failure lands in "errors", vulnerabilities is []
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
) string {
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
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
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
	out := runCLI(t, fakeVulns, "--json")

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
}

func TestScanJSONCompact(t *testing.T) {
	out := runCLI(t, fakeVulns, "--json-compact")

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

	out := runCLI(t, failing, "--json")

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
}
