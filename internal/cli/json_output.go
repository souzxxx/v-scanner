/*
json_output.go

Machine-readable output for --json and --json-compact (Desafio 3)

With either flag set, stdout carries only JSON: no banner, no spinner,
no colors. That keeps `angela scan --json | jq` working. Errors are
printed as {"error": "..."} and the process exits with code 1. If
OSV.dev fails, the report is still printed (vulnerabilities_scanned is
false, the cause is in "errors") and the exit code is also 1, so a CI
step never mistakes a failed query for a clean scan.

Key exports (package-internal):
  jsonMode     - reports whether --json or --json-compact was given
  addJSONFlags - registers both flags on scan, check, and update
  startSpinner - starts the spinner unless JSON output is on
  printReport  - writes a types.Report as indented or compact JSON

Connects to:
  update.go    - commands register the flags and call printReport
  scan_core.go - buildReport produces the types.Report printed here
*/

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/CarterPerez-dev/angela/internal/ui"
	"github.com/CarterPerez-dev/angela/pkg/types"
	"github.com/spf13/cobra"
)

var (
	jsonOutput  bool
	jsonCompact bool

	// stdout is replaced in tests to capture the JSON
	stdout io.Writer = os.Stdout
)

// errAlreadyReported makes the process exit 1 without printing again,
// because the failure is already inside the JSON that was printed
var errAlreadyReported = errors.New("already reported")

func jsonMode() bool {
	return jsonOutput || jsonCompact
}

// argsWantJSON catches --json when cobra failed before setting the flag
// (unknown flag, bad value), so the error still comes out as JSON
func argsWantJSON(args []string) bool {
	for _, a := range args {
		if a == "--json" || a == "--json-compact" {
			return true
		}
	}
	return false
}

func addJSONFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(
		&jsonOutput, "json", false,
		"print results as JSON (no banner, spinner, or colors)",
	)
	cmd.Flags().BoolVar(
		&jsonCompact, "json-compact", false,
		"print results as single-line JSON (for log aggregation)",
	)
	cmd.MarkFlagsMutuallyExclusive("json", "json-compact")
}

// startSpinner returns the function that stops it
func startSpinner(msg string) func() {
	if jsonMode() {
		return func() {}
	}
	spin := ui.NewSpinner(msg)
	spin.Start()
	return spin.Stop
}

func printReport(report types.Report) error {
	var (
		data []byte
		err  error
	)
	if jsonCompact {
		data, err = json.Marshal(report)
	} else {
		data, err = json.MarshalIndent(report, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	_, err = fmt.Fprintln(stdout, string(data))
	return err
}

// printReportFailingOn prints the report and, when scanErr is set, exits 1
// so a CI step cannot mistake a failed OSV query for a clean scan
func printReportFailingOn(report types.Report, scanErr error) error {
	if err := printReport(report); err != nil {
		return err
	}
	if scanErr != nil {
		return errAlreadyReported
	}
	return nil
}

func printJSONError(msg string) {
	data, err := json.Marshal(map[string]string{"error": msg})
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(stdout, string(data)) //nolint:errcheck // nothing left to report to
}
