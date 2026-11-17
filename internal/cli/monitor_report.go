/*
monitor_report.go

How `angela monitor` shows each round: terminal lines, JSON lines, log

Terminal: NEW alerts in red, RESOLVED in green, a gray "no changes"
line otherwise; the first round is a baseline, not an alert. With
--json every round is one compact JSON object per line, so the output
can be piped into jq or a log collector. The log file gets one line per
alert with a UTC timestamp.

Connects to:
  monitor.go - monitorLoop.round calls report after each scan
  output.go  - severityColorFn, padRight, truncate, preferredID
*/

package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CarterPerez-dev/angela/internal/monitor"
	"github.com/CarterPerez-dev/angela/internal/ui"
	"github.com/CarterPerez-dev/angela/pkg/types"
)

// monitorRound is the JSON line printed for each round with --json
type monitorRound struct {
	SchemaVersion int            `json:"schema_version"`
	Tool          string         `json:"tool"`
	Command       string         `json:"command"`
	File          string         `json:"file"`
	ScannedAt     time.Time      `json:"scanned_at"`
	Baseline      bool           `json:"baseline"`
	New           []monitorAlert `json:"new"`
	Resolved      []monitorAlert `json:"resolved"`
	TotalVulns    int            `json:"total_vulnerabilities"`
	Error         string         `json:"error,omitempty"`
}

type monitorAlert struct {
	Package       string              `json:"package"`
	Version       string              `json:"version"`
	Vulnerability types.Vulnerability `json:"vulnerability"`
}

func toAlerts(fs []monitor.Finding) []monitorAlert {
	out := make([]monitorAlert, 0, len(fs))
	for _, f := range fs {
		v := f.Vuln
		if v.Aliases == nil {
			v.Aliases = []string{}
		}
		out = append(out, monitorAlert{
			Package: f.Package, Version: f.Version, Vulnerability: v,
		})
	}
	return out
}

func (m *monitorLoop) report(snap monitor.Snapshot, d monitor.Diff) {
	m.logDiff(d, countVulns(snap.Vulns))
	if m.json {
		m.emitJSON(snap, d, nil)
		return
	}

	clock := ui.HiBlack(now().Format("15:04"))
	total := countVulns(snap.Vulns)

	if d.Baseline {
		m.printf(
			"  %s %s %s\n",
			clock, ui.HiCyan(ui.Diamond),
			ui.HiCyan(fmt.Sprintf(
				"baseline: %d known %s",
				total, pluralize("vulnerability", total),
			)),
		)
		for _, f := range d.New {
			m.printf("        %s\n", ui.HiBlack(findingText(f)))
		}
		return
	}

	if len(d.New) == 0 && len(d.Resolved) == 0 {
		m.printf(
			"  %s %s\n",
			clock, ui.HiBlack(m.noChangesText(total)),
		)
		return
	}

	for _, f := range d.New {
		sev := severityColorFn(f.Vuln.Severity)
		m.printf(
			"  %s %s %s  %s\n",
			clock, ui.RedBold("● NEW     "),
			sev(padRight(strings.ToUpper(f.Vuln.Severity), 8)),
			ui.Red(findingText(f)),
		)
	}
	for _, f := range d.Resolved {
		m.printf(
			"  %s %s %s  %s\n",
			clock, ui.GreenBold(ui.Check+" RESOLVED"),
			ui.HiBlack(padRight(strings.ToUpper(f.Vuln.Severity), 8)),
			ui.Green(findingText(f)),
		)
	}
}

func (m *monitorLoop) noChangesText(total int) string {
	known := fmt.Sprintf(
		"%d known %s", total, pluralize("vulnerability", total),
	)
	if m.lastOK.IsZero() {
		return "no changes since the saved state (" + known + ")"
	}
	return fmt.Sprintf(
		"no changes since %s (%s)",
		m.lastOK.Local().Format("15:04"), known,
	)
}

// findingText is "django 3.2.0  GHSA-xxxx (CVE-2023-xxxx)  summary"
func findingText(f monitor.Finding) string {
	id := f.Vuln.ID
	if cve := preferredID(f.Vuln); cve != id {
		id += " (" + cve + ")"
	}
	text := fmt.Sprintf("%s %s  %s", f.Package, f.Version, id)
	if f.Vuln.Summary != "" {
		text += "  " + truncate(f.Vuln.Summary, 60)
	}
	return text
}

func (m *monitorLoop) logDiff(d monitor.Diff, total int) {
	if d.Baseline {
		m.logf("BASELINE file=%s known=%d", m.file, total)
		return
	}
	for _, f := range d.New {
		m.logf(
			"NEW %s %s %s %s",
			f.Package,
			f.Version,
			f.Vuln.ID,
			strings.ToUpper(f.Vuln.Severity),
		)
	}
	for _, f := range d.Resolved {
		m.logf("RESOLVED %s %s %s", f.Package, f.Version, f.Vuln.ID)
	}
}

func (m *monitorLoop) emitJSON(
	snap monitor.Snapshot,
	d monitor.Diff,
	scanErr error,
) {
	line := monitorRound{
		SchemaVersion: types.ReportSchemaVersion,
		Tool:          toolName,
		Command:       "monitor",
		File:          m.file,
		ScannedAt:     snap.ScannedAt,
		Baseline:      d.Baseline,
		New:           toAlerts(d.New),
		Resolved:      toAlerts(d.Resolved),
		TotalVulns:    countVulns(snap.Vulns),
	}
	if scanErr != nil {
		line.Error = scanErr.Error()
	}
	data, err := json.Marshal(line)
	if err != nil {
		return
	}
	m.printf("%s\n", data)
}
