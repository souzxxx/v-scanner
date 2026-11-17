/*
scan_core.go

Scan pipeline without any terminal output

Separates "fetching and filtering results" from "printing them", so the
pretty terminal output, the --json output, and the monitor all use the
same data. Nothing in this file prints.

Key exports (package-internal):
  loadScanTarget - reads config and parses the dependency file
  collectScan    - queries OSV.dev and applies ignore-vulns and min-severity
  buildReport    - turns a ScanResult into the JSON contract in types.Report

Connects to:
  update.go  - runScan and runUpdate call loadScanTarget and collectScan
  monitor    - the monitor command reuses collectScan on every round
  types.go   - produces types.Report
*/

package cli

import (
	"context"
	"sort"
	"time"

	"github.com/CarterPerez-dev/angela/internal/config"
	"github.com/CarterPerez-dev/angela/internal/pyproject"
	"github.com/CarterPerez-dev/angela/pkg/types"
)

const toolName = "angela"

// now and scanVulns are replaced in tests (deterministic, no network)
var (
	now       = time.Now
	scanVulns = scanForVulns
)

// scanTarget is a parsed dependency file ready to be scanned
type scanTarget struct {
	File string
	Cfg  config.Config
	Deps []types.Dependency
}

// scanOutcome is the filtered result of scanning one target
type scanOutcome struct {
	// Versions maps each package to the version queried on OSV.dev
	Versions map[string]string
	// Vulns already has ignore-vulns and min-severity applied
	Vulns map[string][]types.Vulnerability
	// Err is set when OSV.dev could not be queried; Vulns is then empty
	// and must NOT be read as "no vulnerabilities"
	Err error
}

func loadScanTarget(file string) (scanTarget, error) {
	deps, err := parseDeps(file)
	if err != nil {
		return scanTarget{}, err
	}
	return scanTarget{
		File: file,
		Cfg:  config.Load(file),
		Deps: deps,
	}, nil
}

func collectScan(
	ctx context.Context,
	target scanTarget,
) scanOutcome {
	vulns, err := scanVulns(ctx, target.Deps)
	vulns = filterIgnoredVulns(vulns, target.Cfg.IgnoreVulns)
	vulns = filterVulnsBySeverity(
		vulns, resolveMinSeverity(target.Cfg.MinSeverity),
	)
	return scanOutcome{
		Versions: depVersions(target.Deps),
		Vulns:    vulns,
		Err:      err,
	}
}

func depVersions(deps []types.Dependency) map[string]string {
	versions := make(map[string]string, len(deps))
	for _, d := range deps {
		if v := pyproject.ExtractMinVersion(d.Spec); v != "" {
			versions[d.Name] = v
		}
	}
	return versions
}

func countVulns(vulns map[string][]types.Vulnerability) int {
	total := 0
	for _, vl := range vulns {
		total += len(vl)
	}
	return total
}

// buildReport converts a finished run into the JSON contract.
// Packages are sorted by name and each package's vulnerabilities by
// severity, so the output is stable between runs.
func buildReport(
	command, file string,
	res types.ScanResult,
	versions map[string]string,
	errs ...error,
) types.Report {
	report := types.Report{
		SchemaVersion: types.ReportSchemaVersion,
		Tool:          toolName,
		Command:       command,
		File:          file,
		GeneratedAt:   now().UTC(),
		Updates:       res.Updates,
		Vulnerabilities: make(
			[]types.PackageVulns,
			0,
			len(res.Vulnerabilities),
		),
		Summary: types.Summary{
			TotalPackages:  res.TotalPackages,
			TotalUpdated:   res.TotalUpdated,
			TotalVulns:     res.TotalVulns,
			VulnsScanned:   res.VulnsScanned,
			DurationMillis: res.Duration.Milliseconds(),
		},
	}
	if report.Updates == nil {
		report.Updates = []types.UpdateResult{}
	}

	pkgs := make([]string, 0, len(res.Vulnerabilities))
	for pkg := range res.Vulnerabilities {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)

	for _, pkg := range pkgs {
		vlist := append(
			[]types.Vulnerability(nil), res.Vulnerabilities[pkg]...,
		)
		sortVulnsBySeverity(vlist)
		report.Vulnerabilities = append(
			report.Vulnerabilities,
			types.PackageVulns{
				Package:         pkg,
				Version:         versions[pkg],
				Vulnerabilities: vlist,
			},
		)
	}

	for _, err := range errs {
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
		}
	}
	return report
}
