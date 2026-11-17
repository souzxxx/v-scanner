/*
json_output.go

Machine-readable output for --json and --json-compact (Desafio 3)

With either flag set, stdout carries only JSON: no banner, no spinner,
no colors. That keeps `angela scan --json | jq` working. Errors are
printed as {"error": "..."} and the process exits with code 1.

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

func jsonMode() bool {
	return jsonOutput || jsonCompact
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

func printJSONError(msg string) {
	data, err := json.Marshal(map[string]string{"error": msg})
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(stdout, string(data)) //nolint:errcheck
}
