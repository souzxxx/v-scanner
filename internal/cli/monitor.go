/*
monitor.go

`angela monitor`: periodic scan of a pinned dependency file (Desafio 7)

With the file unchanged, the risk still changes because OSV.dev keeps
publishing advisories for old versions. The monitor rescans on an
interval and reports only what changed: NEW vulnerabilities and
RESOLVED ones. What was already reported is kept in a state file, so a
restart does not repeat old alerts.

Every round re-reads the file (edits are picked up), scans it with the
same pipeline as `angela scan`, compares it with the saved state,
prints, and only then updates and saves the state. If the scan fails
(OSV.dev down), the state is left untouched; otherwise every known
vulnerability would look "resolved".

Key exports (package-internal):
  newMonitorCmd - the cobra command and its flags
  monitorLoop   - one monitor session; the scan function is injected so
                  tests run without the network

Connects to:
  scan_core.go       - loadScanTarget and collectScan run each round
  internal/monitor   - Snapshot, Compare, State (card AR1)
  json_output.go     - --json flags and the stdout writer
*/

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/CarterPerez-dev/angela/internal/monitor"
	"github.com/CarterPerez-dev/angela/internal/pyproject"
	"github.com/CarterPerez-dev/angela/internal/ui"
	"github.com/CarterPerez-dev/angela/pkg/types"
	"github.com/spf13/cobra"
)

const (
	// minMonitorInterval keeps the monitor from hammering OSV.dev
	minMonitorInterval     = time.Minute
	defaultMonitorInterval = time.Hour
)

type monitorFlags struct {
	file     string
	interval time.Duration
	state    string
	logPath  string
	once     bool
}

// monitorScanFunc runs one scan round; tests replace it with a fake
type monitorScanFunc func(ctx context.Context) (monitor.Snapshot, error)

// monitorLoop is one running monitor session
type monitorLoop struct {
	scan      monitorScanFunc
	state     *monitor.State
	statePath string
	file      string // as the user typed it, for display
	out       io.Writer
	log       io.Writer
	json      bool
	lastOK    time.Time // last successful round in this session
}

func angelaHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".angela")
}

// expandHome turns a leading ~/ into the home directory, so flag
// defaults read the same on every machine
func expandHome(path string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return filepath.Join(filepath.Dir(angelaHome()), rest)
	}
	return path
}

// shortDuration prints 1h instead of 1h0m0s
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// defaultStatePath gives each monitored file its own state:
// ~/.angela/monitor/<name>-<hash of the absolute path>.json
func defaultStatePath(absFile string) string {
	sum := sha256.Sum256([]byte(absFile))
	name := fmt.Sprintf(
		"%s-%s.json",
		filepath.Base(absFile), hex.EncodeToString(sum[:])[:12],
	)
	return filepath.Join(angelaHome(), "monitor", name)
}

func newMonitorCmd() *cobra.Command {
	f := &monitorFlags{}

	cmd := &cobra.Command{
		Use:   "monitor [path]",
		Short: "Rescan a pinned dependency file periodically and alert only on changes",
		Long: `monitor rescans a dependency file pinned with == on an interval and
reports only what changed since the last round: NEW vulnerabilities
(for example a CVE just published for a version you pin) and RESOLVED
ones (the version was bumped or the advisory was withdrawn).

The first round records a baseline. Everything already reported is
saved in a state file, so stopping and restarting the monitor does not
repeat old alerts. Ctrl+C saves the state and exits.`,
		Example: `  angela monitor --file requirements.txt --interval 1h
  angela monitor --file requirements.txt --once
  angela monitor --file requirements.txt --once --json | jq .new`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.file = resolveFile(f.file, args)
			return runMonitor(cmd.Context(), f)
		},
	}

	cmd.Flags().StringVarP(
		&f.file, "file", "f", "pyproject.toml",
		"path to the dependency file (pin versions with ==)",
	)
	cmd.Flags().DurationVar(
		&f.interval, "interval", defaultMonitorInterval,
		"time between rounds (minimum 1m)",
	)
	cmd.Flags().StringVar(
		&f.state, "state", "",
		"state file (default ~/.angela/monitor/<file>-<hash>.json)",
	)
	cmd.Flags().StringVar(
		&f.logPath, "log", "~/.angela/monitor.log",
		`alert log, one line per alert ("" disables it)`,
	)
	cmd.Flags().BoolVar(
		&f.once, "once", false,
		"run a single round and exit (demos and CI)",
	)
	addJSONFlags(cmd)
	return cmd
}

func runMonitor(ctx context.Context, f *monitorFlags) error {
	if !f.once && f.interval < minMonitorInterval {
		return fmt.Errorf(
			"--interval must be at least %s to respect OSV.dev rate limits",
			shortDuration(minMonitorInterval),
		)
	}

	absFile, err := filepath.Abs(f.file)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", f.file, err)
	}
	if _, err = os.Stat(absFile); err != nil {
		return fmt.Errorf("dependency file: %w", err)
	}

	statePath := expandHome(f.state)
	if statePath == "" {
		statePath = defaultStatePath(absFile)
	}
	if err = os.MkdirAll(filepath.Dir(statePath), 0o750); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	state, err := monitor.LoadState(statePath)
	if err != nil {
		return err
	}

	logW, closeLog, err := openMonitorLog(expandHome(f.logPath))
	if err != nil {
		return err
	}
	defer closeLog()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := &monitorLoop{
		state:     state,
		statePath: statePath,
		file:      f.file,
		out:       stdout,
		log:       logW,
		json:      jsonMode(),
	}
	m.scan = newMonitorScan(absFile, m.warn)
	return m.run(ctx, f.interval, f.once)
}

func openMonitorLog(path string) (io.Writer, func(), error) {
	if path == "" {
		return io.Discard, func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, nil, fmt.Errorf("create log directory: %w", err)
	}
	lf, err := os.OpenFile( //nolint:gosec // path comes from the user's own flag
		path,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("open log: %w", err)
	}
	return lf, func() { _ = lf.Close() }, nil //nolint:errcheck // best effort on exit
}

// newMonitorScan builds the real scan round: re-read the file, query
// OSV.dev through collectScan, and turn the result into a Snapshot
func newMonitorScan(
	absFile string,
	warn func(string),
) monitorScanFunc {
	warned := map[string]bool{}
	return func(ctx context.Context) (monitor.Snapshot, error) {
		target, err := loadScanTarget(absFile)
		if err != nil {
			return monitor.Snapshot{}, err
		}
		for _, d := range target.Deps {
			if msg := pinWarning(d); msg != "" && !warned[d.Name+d.Spec] {
				warned[d.Name+d.Spec] = true
				warn(msg)
			}
		}

		stopSpinner := startSpinner(fmt.Sprintf(
			"Scanning %d dependencies...", len(target.Deps),
		))
		out := collectScan(ctx, target)
		stopSpinner()
		if out.Err != nil {
			return monitor.Snapshot{}, out.Err
		}
		return monitor.Snapshot{
			File:      absFile,
			ScannedAt: now().UTC(),
			Versions:  out.Versions,
			Vulns:     out.Vulns,
		}, nil
	}
}

// isPinned reports whether spec names exactly one version (== or ===)
func isPinned(spec string) bool {
	s := strings.TrimSpace(spec)
	if !strings.HasPrefix(s, "==") {
		return false
	}
	return !strings.ContainsAny(strings.TrimLeft(s, "="), ",*")
}

func pinWarning(d types.Dependency) string {
	if isPinned(d.Spec) {
		return ""
	}
	if pyproject.ExtractMinVersion(d.Spec) == "" {
		return fmt.Sprintf(
			"%s has no version and is not monitored", d.Name,
		)
	}
	return fmt.Sprintf(
		"%s%s is not pinned with ==; the monitor checks %s only",
		d.Name, d.Spec, pyproject.ExtractMinVersion(d.Spec),
	)
}

// run executes rounds until ctx is cancelled, or once when once is set
func (m *monitorLoop) run(
	ctx context.Context,
	interval time.Duration,
	once bool,
) error {
	if !m.json {
		every := "once"
		if !once {
			every = "every " + shortDuration(interval)
		}
		m.printf(
			"\n  %s %s %s\n  %s\n\n",
			ui.HiCyan(ui.Diamond),
			ui.HiCyan("monitoring "+m.file),
			ui.HiBlack("("+every+", Ctrl+C to stop)"),
			ui.HiBlack("state: "+m.statePath),
		)
	}

	for {
		scanErr, err := m.round(ctx)
		if err != nil {
			return err
		}
		if once {
			if scanErr != nil {
				return errAlreadyReported
			}
			return nil
		}
		if ctx.Err() == nil {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
				continue
			}
		}
		return m.shutdown()
	}
}

// round runs one scan. scanErr is a failed scan (reported, the state is
// left as it was, the loop goes on); err is fatal (the state could not
// be saved)
func (m *monitorLoop) round(ctx context.Context) (scanErr, err error) {
	snap, scanErr := m.scan(ctx)
	if interrupted := scanErr != nil && ctx.Err() != nil; interrupted {
		return nil, nil // cancelled by Ctrl+C, not a failure
	}
	if scanErr != nil {
		m.reportError(scanErr)
		return scanErr, nil
	}

	diff := monitor.Compare(m.state, snap)
	sortFindings(diff.New)
	sortFindings(diff.Resolved)
	m.report(snap, diff)

	m.state.Apply(snap, diff)
	if err := m.state.Save(m.statePath); err != nil {
		return nil, fmt.Errorf("save monitor state: %w", err)
	}
	m.lastOK = snap.ScannedAt
	return nil, nil
}

func (m *monitorLoop) shutdown() error {
	if err := m.state.Save(m.statePath); err != nil {
		return fmt.Errorf("save monitor state: %w", err)
	}
	if !m.json {
		m.printf(
			"\n  %s %s\n\n",
			ui.HiGreen(ui.Check),
			ui.HiGreen("state saved to "+m.statePath),
		)
	}
	return nil
}

func sortFindings(fs []monitor.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Package != fs[j].Package {
			return fs[i].Package < fs[j].Package
		}
		ri, rj := severityRank(
			fs[i].Vuln.Severity,
		), severityRank(
			fs[j].Vuln.Severity,
		)
		if ri != rj {
			return ri < rj
		}
		return fs[i].Vuln.ID < fs[j].Vuln.ID
	})
}

func (m *monitorLoop) printf(format string, a ...any) {
	_, _ = fmt.Fprintf(m.out, format, a...) //nolint:errcheck // terminal output
}

func (m *monitorLoop) logf(format string, a ...any) {
	line := now().UTC().Format(time.RFC3339) + " " +
		fmt.Sprintf(format, a...) + "\n"
	_, _ = io.WriteString(m.log, line) //nolint:errcheck
}

func (m *monitorLoop) warn(msg string) {
	m.logf("WARNING %s", msg)
	if m.json {
		// stderr, so stdout stays pure JSON
		msg = "warning: " + msg + "\n"
		_, _ = io.WriteString(os.Stderr, msg) //nolint:errcheck
		return
	}
	m.printf("  %s %s\n", ui.HiYellow("!"), ui.HiYellow(msg))
}

func (m *monitorLoop) reportError(err error) {
	m.logf("ERROR %s", err)
	if m.json {
		m.emitJSON(
			monitor.Snapshot{ScannedAt: now().UTC()},
			monitor.Diff{},
			err,
		)
		return
	}
	m.printf(
		"  %s %s %s\n",
		ui.HiBlack(now().Format("15:04")),
		ui.RedBold("scan failed, state kept:"),
		ui.HiRed(err.Error()),
	)
}
