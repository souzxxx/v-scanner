/*
©AngelaMos | 2026
types.go

Shared domain types used across all packages in angela

Defines the core data structures that flow through the scan pipeline,
from parsed dependency specs through update resolution and into final
scan results. All packages import from here; nothing in this package
imports from internal packages.

Key exports:
  Dependency    - a single parsed dependency with name, spec, extras, markers, and group
  UpdateResult  - outcome of checking one dependency for a newer version
  Vulnerability - a single security advisory with severity, fix version, and link
  ScanResult    - aggregated output of a full scan run
  Report        - machine-readable report printed by --json and reused by the monitor
  PackageVulns  - vulnerabilities of one package inside a Report
  Summary       - totals of a Report

JSON contract (schema_version 1), shared by --json and the monitor:

	{
	  "schema_version": 1,
	  "tool": "angela",
	  "command": "scan",                 // scan | check | update
	  "file": "requirements.txt",
	  "generated_at": "2026-11-19T12:00:00Z",
	  "updates": [ UpdateResult... ],    // always an array, empty for scan
	  "vulnerabilities": [               // always an array, sorted by package
	    {"package": "django", "version": "3.2.0",
	     "vulnerabilities": [ Vulnerability... ]}  // sorted by severity
	  ],
	  "summary": {"total_packages": 8, "total_updated": 0,
	              "total_vulnerabilities": 48,
	              "vulnerabilities_scanned": true, "duration_ms": 3593},
	  "errors": ["..."]                  // omitted when empty
	}
*/

package types

import "time"

// Dependency represents a single parsed dependency from a pyproject.toml file
type Dependency struct {
	Name    string
	Spec    string
	Extras  []string
	Markers string
	Group   string
}

// UpdateResult holds the outcome of checking one dependency for updates
type UpdateResult struct {
	Name    string `json:"name"`
	OldSpec string `json:"old_spec,omitempty"`
	NewSpec string `json:"new_spec,omitempty"`
	OldVer  string `json:"old_version,omitempty"`
	NewVer  string `json:"new_version,omitempty"`
	Change  string `json:"change,omitempty"`
	Skipped bool   `json:"skipped"`
	Reason  string `json:"reason,omitempty"`
}

// Vulnerability represents a single security advisory for a package
type Vulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity string   `json:"severity"`
	FixedIn  string   `json:"fixed_in,omitempty"`
	Link     string   `json:"link,omitempty"`
}

// ScanResult holds the aggregated output of a full dependency scan
type ScanResult struct {
	Updates         []UpdateResult
	Vulnerabilities map[string][]Vulnerability
	TotalPackages   int
	TotalUpdated    int
	TotalVulns      int
	VulnsScanned    bool
	Duration        time.Duration
}

// ReportSchemaVersion is bumped whenever the Report JSON changes in a
// backwards-incompatible way
const ReportSchemaVersion = 1

// Report is the machine-readable result of a scan, check, or update run
type Report struct {
	SchemaVersion   int            `json:"schema_version"`
	Tool            string         `json:"tool"`
	Command         string         `json:"command"`
	File            string         `json:"file"`
	GeneratedAt     time.Time      `json:"generated_at"`
	Updates         []UpdateResult `json:"updates"`
	Vulnerabilities []PackageVulns `json:"vulnerabilities"`
	Summary         Summary        `json:"summary"`
	Errors          []string       `json:"errors,omitempty"`
}

// PackageVulns groups the vulnerabilities found for one package version
type PackageVulns struct {
	Package         string          `json:"package"`
	Version         string          `json:"version"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Summary holds the totals of a Report
type Summary struct {
	TotalPackages  int   `json:"total_packages"`
	TotalUpdated   int   `json:"total_updated"`
	TotalVulns     int   `json:"total_vulnerabilities"`
	VulnsScanned   bool  `json:"vulnerabilities_scanned"`
	DurationMillis int64 `json:"duration_ms"`
}
