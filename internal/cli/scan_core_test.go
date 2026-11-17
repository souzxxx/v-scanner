/*
scan_core_test.go

Tests for the output-free scan pipeline in scan_core.go (no network)

Tests:
  TestBuildReportShape        - schema fields, totals, and duration in ms
  TestBuildReportOrdering     - packages A→Z, vulns by severity, input untouched
  TestBuildReportEmptyArrays  - updates and vulnerabilities encode as [] not null
  TestBuildReportErrors       - nil errors skipped, real errors kept
  TestDepVersions             - extracts the queried version per dependency
  TestLoadScanTargetTxt       - parses a requirements file into a target
*/

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/angela/pkg/types"
)

func fixedNow(t *testing.T) time.Time {
	t.Helper()
	ts := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	orig := now
	now = func() time.Time { return ts }
	t.Cleanup(func() { now = orig })
	return ts
}

func sampleResult() types.ScanResult {
	return types.ScanResult{
		Vulnerabilities: map[string][]types.Vulnerability{
			"requests": {
				{ID: "GHSA-low", Severity: "LOW"},
				{ID: "GHSA-crit", Severity: "CRITICAL"},
			},
			"django": {
				{ID: "GHSA-mod", Severity: "MODERATE"},
			},
		},
		TotalPackages: 3,
		TotalVulns:    3,
		VulnsScanned:  true,
		Duration:      1500 * time.Millisecond,
	}
}

func TestBuildReportShape(t *testing.T) {
	ts := fixedNow(t)

	r := buildReport(
		"scan", "req.txt", sampleResult(),
		map[string]string{"django": "3.2.0", "requests": "2.25.0"},
	)

	if r.SchemaVersion != types.ReportSchemaVersion {
		t.Errorf("schema_version = %d", r.SchemaVersion)
	}
	if r.Tool != "angela" || r.Command != "scan" || r.File != "req.txt" {
		t.Errorf("header = %q %q %q", r.Tool, r.Command, r.File)
	}
	if !r.GeneratedAt.Equal(ts) {
		t.Errorf("generated_at = %v, want %v", r.GeneratedAt, ts)
	}
	want := types.Summary{
		TotalPackages:  3,
		TotalVulns:     3,
		VulnsScanned:   true,
		DurationMillis: 1500,
	}
	if r.Summary != want {
		t.Errorf("summary = %+v, want %+v", r.Summary, want)
	}
}

func TestBuildReportOrdering(t *testing.T) {
	fixedNow(t)
	res := sampleResult()

	r := buildReport(
		"scan", "req.txt", res,
		map[string]string{"django": "3.2.0", "requests": "2.25.0"},
	)

	if len(r.Vulnerabilities) != 2 {
		t.Fatalf("got %d packages, want 2", len(r.Vulnerabilities))
	}
	if r.Vulnerabilities[0].Package != "django" ||
		r.Vulnerabilities[1].Package != "requests" {
		t.Errorf("packages not sorted: %+v", r.Vulnerabilities)
	}
	if r.Vulnerabilities[1].Version != "2.25.0" {
		t.Errorf("version = %q", r.Vulnerabilities[1].Version)
	}
	if got := r.Vulnerabilities[1].Vulnerabilities[0].ID; got != "GHSA-crit" {
		t.Errorf("first requests vuln = %q, want GHSA-crit", got)
	}
	if res.Vulnerabilities["requests"][0].ID != "GHSA-low" {
		t.Error("buildReport reordered the caller's slice")
	}
}

func TestBuildReportEmptyArrays(t *testing.T) {
	fixedNow(t)

	r := buildReport("scan", "req.txt", types.ScanResult{}, nil)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)
	for _, want := range []string{
		`"updates":[]`, `"vulnerabilities":[]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if strings.Contains(s, `"errors"`) {
		t.Errorf("errors should be omitted when empty: %s", s)
	}
}

func TestBuildReportErrors(t *testing.T) {
	fixedNow(t)

	r := buildReport(
		"scan", "req.txt", types.ScanResult{}, nil,
		nil, errors.New("osv down"),
	)
	if len(r.Errors) != 1 || r.Errors[0] != "osv down" {
		t.Errorf("errors = %v", r.Errors)
	}
}

func TestDepVersions(t *testing.T) {
	t.Parallel()

	got := depVersions([]types.Dependency{
		{Name: "django", Spec: "==3.2.0"},
		{Name: "flask", Spec: ">=2.0,<3.0"},
		{Name: "numpy", Spec: ""},
	})

	if got["django"] != "3.2.0" || got["flask"] != "2.0" {
		t.Errorf("versions = %v", got)
	}
	if _, ok := got["numpy"]; ok {
		t.Error("unversioned dep should be absent")
	}
}

func TestLoadScanTargetTxt(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "requirements.txt")
	content := "django==3.2.0\nrequests>=2.25.0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	target, err := loadScanTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	if target.File != path || len(target.Deps) != 2 {
		t.Errorf("target = %+v", target)
	}
}
