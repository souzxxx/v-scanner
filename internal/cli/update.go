/*
©AngelaMos | 2026
update.go

CLI commands and scan orchestration for angela

Defines all five cobra commands (init, update, check, scan, cache) and
the core runUpdate and runScan functions that coordinate PyPI version
fetching, OSV vulnerability scanning, dependency file writes, and result
output. The verbose and minSeverity flags are package-level and shared
with output.go.

Key exports:
  Execute - entry point called by main; sets up and runs the cobra root command

Connects to:
  main.go                - Execute called from main
  scan_core.go           - loadScanTarget and collectScan (config, parse, OSV, filters)
  pypi/client.go         - creates Client and calls FetchAllVersions
  osv/client.go          - calls NewClient and ScanPackages
  pyproject/parser.go    - calls ParseFile and ExtractMinVersion
  requirements/parser.go - calls ParseFile when the target file ends in .txt
  pyproject/writer.go    - calls UpdateFile after resolving new versions
  requirements/writer.go - calls UpdateFile when the target file ends in .txt
  output.go              - calls all Print functions to render results
  monitor.go             - newMonitorCmd registered on the root command
  ui                     - uses PrintBanner and NewSpinner
*/

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CarterPerez-dev/angela/internal/osv"
	"github.com/CarterPerez-dev/angela/internal/pypi"
	"github.com/CarterPerez-dev/angela/internal/pyproject"
	"github.com/CarterPerez-dev/angela/internal/requirements"
	"github.com/CarterPerez-dev/angela/internal/ui"
	"github.com/CarterPerez-dev/angela/pkg/types"
	"github.com/spf13/cobra"
)

var (
	verbose     bool
	minSeverity string
)

type updateFlags struct {
	file              string
	safe              bool
	vulns             bool
	includePrerelease bool
}

func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".angela", "cache")
}

// Execute sets up the CLI and runs the root command
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		switch {
		case errors.Is(err, errAlreadyReported):
		case jsonMode() || argsWantJSON(os.Args[1:]):
			printJSONError(err.Error())
		default:
			PrintError(err.Error())
		}
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "angela",
		Short: "Python dependency updater and vulnerability scanner",
		Long: `angela scans your pyproject.toml, updates dependencies to their
latest stable versions, and checks for known CVEs using OSV.dev.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(
			_ *cobra.Command, _ []string,
		) {
			if !jsonMode() {
				ui.PrintBanner()
			}
		},
	}

	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(
		func(cmd *cobra.Command, args []string) {
			if cmd.Root() == cmd {
				ui.PrintBannerWithArt()
			} else {
				ui.PrintBanner()
			}
			defaultHelp(cmd, args)
		},
	)

	root.PersistentFlags().BoolVarP(
		&verbose, "verbose", "v", false,
		"show full vulnerability details",
	)
	root.PersistentFlags().StringVar(
		&minSeverity, "min-severity", "",
		"minimum severity to report (critical, high, moderate, low)",
	)

	root.AddCommand(
		newInitCmd(),
		newUpdateCmd(),
		newCheckCmd(),
		newScanCmd(),
		newCacheCmd(),
		newMonitorCmd(),
	)
	return root
}

const pyprojectTemplate = `[project]
name = "%s"
version = "0.1.0"
description = ""
requires-python = ">=3.13"
dependencies = []

[tool.angela]
# Minimum severity to report (critical, high, moderate, low)
# min-severity = "moderate"

# Dependencies to skip during updates
# ignore = []

# Vulnerability IDs to suppress (accepted risk)
# ignore-vulns = []
`

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a new pyproject.toml with angela configuration",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runInit()
		},
	}
}

func runInit() error {
	if _, err := os.Stat("pyproject.toml"); err == nil {
		return fmt.Errorf("pyproject.toml already exists")
	}

	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	name := filepath.Base(dir)
	content := fmt.Sprintf(pyprojectTemplate, name)

	if err := os.WriteFile( //nolint:gosec // pyproject.toml needs 0644 for uv/pip reads
		"pyproject.toml",
		[]byte(content),
		0o644,
	); err != nil {
		return fmt.Errorf("write pyproject.toml: %w", err)
	}

	fmt.Printf(
		"\n  %s %s\n\n",
		ui.HiGreen(ui.Check),
		ui.HiGreen("Created pyproject.toml"),
	)
	return nil
}

func newUpdateCmd() *cobra.Command {
	f := &updateFlags{}

	cmd := &cobra.Command{
		Use:     "update [path]",
		Aliases: []string{"u"},
		Short:   "Update dependencies to latest stable versions",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.file = resolveFile(f.file, args)
			return runUpdate(cmd.Context(), f, false)
		},
	}

	cmd.Flags().StringVarP(
		&f.file, "file", "f", "pyproject.toml",
		"path to dependency file",
	)
	cmd.Flags().BoolVar(
		&f.safe, "safe", false,
		"skip major version bumps",
	)
	cmd.Flags().BoolVar(
		&f.vulns, "vulns", false,
		"also scan for vulnerabilities",
	)
	cmd.Flags().BoolVar(
		&f.includePrerelease, "include-prerelease", false,
		"include pre-release versions",
	)
	addJSONFlags(cmd)
	return cmd
}

func newCheckCmd() *cobra.Command {
	f := &updateFlags{}

	cmd := &cobra.Command{
		Use:     "check [path]",
		Aliases: []string{"c"},
		Short:   "Show available updates without modifying files",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.file = resolveFile(f.file, args)
			return runUpdate(cmd.Context(), f, true)
		},
	}

	cmd.Flags().StringVarP(
		&f.file, "file", "f", "pyproject.toml",
		"path to dependency file",
	)
	cmd.Flags().BoolVar(
		&f.safe, "safe", false,
		"skip major version bumps",
	)
	cmd.Flags().BoolVar(
		&f.vulns, "vulns", false,
		"also scan for vulnerabilities",
	)
	cmd.Flags().BoolVar(
		&f.includePrerelease, "include-prerelease", false,
		"include pre-release versions",
	)
	addJSONFlags(cmd)
	return cmd
}

func newScanCmd() *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:     "scan [path]",
		Aliases: []string{"s"},
		Short:   "Scan dependencies for known vulnerabilities",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file = resolveFile(file, args)
			return runScan(cmd.Context(), file)
		},
	}

	cmd.Flags().StringVarP(
		&file, "file", "f", "pyproject.toml",
		"path to dependency file",
	)
	addJSONFlags(cmd)
	return cmd
}

func newCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage the local response cache",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Remove all cached PyPI responses",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := pypi.NewClient(defaultCacheDir())
			if err != nil {
				return err
			}
			if err := client.ClearCache(); err != nil {
				return err
			}
			fmt.Printf(
				"  %s %s\n",
				ui.HiGreen(ui.Check),
				ui.HiGreen("Cache cleared."),
			)
			return nil
		},
	})

	return cmd
}

func runUpdate(
	ctx context.Context,
	f *updateFlags,
	dryRun bool,
) error {
	start := time.Now()

	target, err := loadScanTarget(f.file)
	if err != nil {
		return err
	}
	cfg, deps := target.Cfg, target.Deps

	stopSpinner := startSpinner(fmt.Sprintf(
		"Scanning %d dependencies...", len(deps),
	))

	client, err := pypi.NewClient(defaultCacheDir())
	if err != nil {
		stopSpinner()
		return err
	}

	names := make([]string, len(deps))
	for i, d := range deps {
		names[i] = d.Name
	}
	fetched := client.FetchAllVersions(ctx, names)

	versionMap := make(map[string][]string, len(fetched))
	var fetchErrs []error
	for _, r := range fetched {
		if r.Err != nil {
			fetchErrs = append(fetchErrs, r.Err)
			continue
		}
		versionMap[r.Name] = r.Versions
	}

	updates, updateSpecs := resolveUpdates(
		deps, versionMap, f.safe,
		f.includePrerelease, cfg.Ignore,
	)

	sortUpdates(updates)

	var out scanOutcome
	if f.vulns {
		out = collectScan(ctx, target)
	}

	stopSpinner()

	if out.Err != nil && !jsonMode() {
		PrintError(out.Err.Error())
	}

	updated := !dryRun && len(updateSpecs) > 0
	if updated {
		if err := updateDepsFile(
			f.file, updateSpecs,
		); err != nil {
			return fmt.Errorf("write updates: %w", err)
		}
	}

	res := types.ScanResult{
		Updates:         updates,
		Vulnerabilities: out.Vulns,
		TotalPackages:   len(deps),
		TotalUpdated:    len(updateSpecs),
		TotalVulns:      countVulns(out.Vulns),
		VulnsScanned:    f.vulns && out.Err == nil,
		Duration:        time.Since(start),
	}

	if jsonMode() {
		command := "update"
		if dryRun {
			command = "check"
		}
		return printReportFailingOn(
			buildReport(
				command, f.file, res, out.Versions,
				append(fetchErrs, out.Err)...,
			),
			out.Err,
		)
	}

	PrintVulnerabilities(out.Vulns)
	PrintUpdates(updates)
	PrintSkipped(updates)
	PrintSummary(res, updated)

	return nil
}

func runScan(ctx context.Context, file string) error {
	start := time.Now()

	target, err := loadScanTarget(file)
	if err != nil {
		return err
	}

	stopSpinner := startSpinner(fmt.Sprintf(
		"Scanning %d dependencies for vulnerabilities...",
		len(target.Deps),
	))
	out := collectScan(ctx, target)
	stopSpinner()

	res := types.ScanResult{
		Vulnerabilities: out.Vulns,
		TotalPackages:   len(target.Deps),
		TotalVulns:      countVulns(out.Vulns),
		VulnsScanned:    out.Err == nil,
		Duration:        time.Since(start),
	}

	if jsonMode() {
		return printReportFailingOn(
			buildReport("scan", file, res, out.Versions, out.Err),
			out.Err,
		)
	}

	if out.Err != nil {
		PrintError(out.Err.Error())
	}
	PrintVulnerabilities(out.Vulns)
	PrintSummary(res, false)

	return nil
}

func resolveUpdates(
	deps []types.Dependency,
	versionMap map[string][]string,
	safe bool,
	includePrerelease bool,
	ignoreDeps []string,
) ([]types.UpdateResult, map[string]string) {
	var results []types.UpdateResult
	specs := make(map[string]string)

	ignoreSet := make(map[string]bool, len(ignoreDeps))
	for _, name := range ignoreDeps {
		ignoreSet[pypi.NormalizeName(name)] = true
	}

	for _, dep := range deps {
		if ignoreSet[pypi.NormalizeName(dep.Name)] {
			results = append(results, types.UpdateResult{
				Name:    dep.Name,
				Skipped: true,
				Reason:  "ignored in config",
			})
			continue
		}

		versions, ok := versionMap[dep.Name]
		if !ok {
			results = append(results, types.UpdateResult{
				Name:    dep.Name,
				Skipped: true,
				Reason:  "not found on PyPI",
			})
			continue
		}

		currentStr := pyproject.ExtractMinVersion(dep.Spec)
		if currentStr == "" {
			results = append(results, types.UpdateResult{
				Name:    dep.Name,
				Skipped: true,
				Reason:  "no version specifier",
			})
			continue
		}

		current, err := pypi.ParseVersion(currentStr)
		if err != nil {
			results = append(results, types.UpdateResult{
				Name:    dep.Name,
				Skipped: true,
				Reason:  "unparseable version",
			})
			continue
		}

		var latest pypi.Version
		if includePrerelease {
			latest, err = latestAny(versions)
		} else {
			latest, err = pypi.LatestStable(versions)
		}
		if err != nil {
			results = append(results, types.UpdateResult{
				Name:    dep.Name,
				Skipped: true,
				Reason:  err.Error(),
			})
			continue
		}

		if latest.Compare(current) <= 0 {
			continue
		}

		change := pypi.ClassifyChange(current, latest)
		if safe && change == pypi.Major {
			results = append(results, types.UpdateResult{
				Name:    dep.Name,
				OldVer:  current.String(),
				NewVer:  latest.String(),
				Change:  change.String(),
				Skipped: true,
				Reason:  "major bump (use --all to include)",
			})
			continue
		}

		newSpec := ">=" + latest.String()
		results = append(results, types.UpdateResult{
			Name:    dep.Name,
			OldVer:  current.String(),
			NewVer:  latest.String(),
			OldSpec: dep.Spec,
			NewSpec: newSpec,
			Change:  change.String(),
		})
		specs[dep.Name] = newSpec
	}

	return results, specs
}

func scanForVulns(
	ctx context.Context,
	deps []types.Dependency,
) (map[string][]types.Vulnerability, error) {
	var queries []osv.PackageQuery
	for _, dep := range deps {
		ver := pyproject.ExtractMinVersion(dep.Spec)
		if ver == "" {
			continue
		}
		queries = append(queries, osv.PackageQuery{
			Name:    dep.Name,
			Version: ver,
		})
	}

	if len(queries) == 0 {
		return nil, nil
	}

	client := osv.NewClient()
	vulns, err := client.ScanPackages(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf(
			"vulnerability scan: %w", err,
		)
	}
	return vulns, nil
}

func latestAny(versions []string) (pypi.Version, error) {
	var latest pypi.Version
	var found bool

	for _, raw := range versions {
		v, err := pypi.ParseVersion(raw)
		if err != nil {
			continue
		}
		if !found || v.Compare(latest) > 0 {
			latest = v
			found = true
		}
	}

	if !found {
		return pypi.Version{}, fmt.Errorf("no versions found")
	}
	return latest, nil
}

func resolveFile(flagVal string, args []string) string {
	if len(args) > 0 {
		path := args[0]
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			return filepath.Join(path, "pyproject.toml")
		}
		return path
	}
	return flagVal
}

func isRequirementsTxt(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".txt")
}

func parseDeps(file string) ([]types.Dependency, error) {
	if isRequirementsTxt(file) {
		return requirements.ParseFile(file)
	}
	return pyproject.ParseFile(file)
}

func updateDepsFile(file string, specs map[string]string) error {
	if isRequirementsTxt(file) {
		return requirements.UpdateFile(file, specs)
	}
	return pyproject.UpdateFile(file, specs)
}

func resolveMinSeverity(configVal string) string {
	if minSeverity != "" {
		return minSeverity
	}
	if configVal != "" {
		return configVal
	}
	return "low"
}

func sortUpdates(updates []types.UpdateResult) {
	order := map[string]int{
		pypi.Major.String(): 0,
		pypi.Minor.String(): 1,
		pypi.Patch.String(): 2,
	}
	sort.Slice(updates, func(i, j int) bool {
		if updates[i].Skipped != updates[j].Skipped {
			return !updates[i].Skipped
		}
		oi := order[updates[i].Change]
		oj := order[updates[j].Change]
		if oi != oj {
			return oi < oj
		}
		return updates[i].Name < updates[j].Name
	})
}
