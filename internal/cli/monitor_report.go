/*
monitor_report.go

How `angela monitor` shows each round: terminal lines, JSON lines, log

The core diff keys findings by package, version, and advisory, so a
version bump that is still affected by the same advisory comes out as
RESOLVED (old version) plus NEW (new version). viewOf pairs those up and
shows them as one "still affected after the bump" line instead of a
false alert. The state still receives the full diff.

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
	"github.com/CarterPerez-dev/angela/internal/pypi"
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
	StillAffected []monitorAlert `json:"still_affected"`
	TotalVulns    int            `json:"total_vulnerabilities"`
	Error         string         `json:"error,omitempty"`
}

type monitorAlert struct {
	Package       string              `json:"package"`
	Version       string              `json:"version"`
	FromVersion   string              `json:"from_version,omitempty"`
	Vulnerability types.Vulnerability `json:"vulnerability"`
}

// roundView is what one round shows: the core Diff minus the advisories
// that only followed a version bump, which are listed in Still
type roundView struct {
	monitor.Diff
	Still []stillFinding
}

// stillFinding is an advisory that affects both the old and the new
// pinned version of a package
type stillFinding struct {
	monitor.Finding
	FromVersion string
}

func viewOf(d monitor.Diff) roundView {
	key := func(f monitor.Finding) string {
		return pypi.NormalizeName(f.Package) + "#" + f.Vuln.ID
	}
	resolved := make(map[string]int, len(d.Resolved))
	for i, f := range d.Resolved {
		resolved[key(f)] = i
	}

	v := roundView{Diff: monitor.Diff{Baseline: d.Baseline}}
	paired := map[int]bool{}
	for _, f := range d.New {
		if i, ok := resolved[key(f)]; ok && !paired[i] {
			paired[i] = true
			v.Still = append(v.Still, stillFinding{
				Finding: f, FromVersion: d.Resolved[i].Version,
			})
			continue
		}
		v.New = append(v.New, f)
	}
	for i, f := range d.Resolved {
		if !paired[i] {
			v.Resolved = append(v.Resolved, f)
		}
	}
	return v
}

func stillAlerts(fs []stillFinding) []monitorAlert {
	out := make([]monitorAlert, 0, len(fs))
	for _, f := range fs {
		a := toAlerts([]monitor.Finding{f.Finding})[0]
		a.FromVersion = f.FromVersion
		out = append(out, a)
	}
	return out
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

func (m *monitorLoop) report(snap monitor.Snapshot, d roundView) {
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

	if len(d.New) == 0 && len(d.Resolved) == 0 && len(d.Still) == 0 {
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
	m.printStill(clock, d.Still)
}

// printStill prints one line per bumped package instead of one per
// advisory, since none of them is new information
func (m *monitorLoop) printStill(clock string, still []stillFinding) {
	for i := 0; i < len(still); {
		f := still[i]
		j := i
		for j < len(still) && still[j].Package == f.Package &&
			still[j].Version == f.Version &&
			still[j].FromVersion == f.FromVersion {
			j++
		}
		n := j - i
		verb := "apply"
		if n == 1 {
			verb = "applies"
		}
		m.printf(
			"  %s %s %s\n",
			clock, ui.HiYellow("↻ BUMPED  "),
			ui.HiYellow(fmt.Sprintf(
				"%s %s → %s: %d %s still %s (angela scan lists them)",
				f.Package, f.FromVersion, f.Version, n,
				pluralize("advisory", n), verb,
			)),
		)
		i = j
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

func (m *monitorLoop) logDiff(d roundView, total int) {
	if d.Baseline {
		m.logf("BASELINE known=%d", total)
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
	for _, f := range d.Still {
		m.logf(
			"STILL %s %s->%s %s",
			f.Package, f.FromVersion, f.Version, f.Vuln.ID,
		)
	}
}

func (m *monitorLoop) emitJSON(
	snap monitor.Snapshot,
	d roundView,
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
		StillAffected: stillAlerts(d.Still),
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
