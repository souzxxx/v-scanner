/*
provisorio.go

TEMPORARY stand-in for the monitor core (card AR1, Arthur).

It implements just enough of the API agreed in the AR1 card so the
`angela monitor` command (card LN3) compiles and can be tested before
AR1 is merged. When AR1's internal/monitor/monitor.go lands on main,
DELETE THIS FILE: the declarations will collide on purpose, so the build
breaks until it is removed and the real implementation is used.

Agreed API (keep in sync with the AR1 card):
  Snapshot, Finding, Diff, State
  Key, LoadState, (*State).Save, Compare, (*State).Apply
*/

package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CarterPerez-dev/angela/internal/pypi"
	"github.com/CarterPerez-dev/angela/pkg/types"
)

const stateSchemaVersion = 1

// Snapshot is the result of one scan round
type Snapshot struct {
	File      string
	ScannedAt time.Time
	Versions  map[string]string
	Vulns     map[string][]types.Vulnerability
}

// Finding is one vulnerability affecting one pinned package version
type Finding struct {
	Package string
	Version string
	Vuln    types.Vulnerability
}

// Diff is what changed between the saved state and the current round
type Diff struct {
	Baseline bool
	New      []Finding
	Resolved []Finding
}

type knownEntry struct {
	Package   string    `json:"package"`
	Version   string    `json:"version"`
	ID        string    `json:"id"`
	Severity  string    `json:"severity"`
	Summary   string    `json:"summary"`
	FirstSeen time.Time `json:"first_seen"`
}

// State is what the monitor remembers between rounds and restarts
type State struct {
	SchemaVersion int                   `json:"schema_version"`
	File          string                `json:"file"`
	LastScan      time.Time             `json:"last_scan"`
	Known         map[string]knownEntry `json:"known"`
}

// Key identifies one finding for deduplication
func Key(pkg, version, vulnID string) string {
	return pypi.NormalizeName(pkg) + "@" + version + "#" + vulnID
}

// LoadState reads the state file; a missing file is an empty state
func LoadState(path string) (*State, error) {
	// the path comes from the user's own --state flag
	data, err := os.ReadFile(path) //nolint:gosec
	if errors.Is(err, os.ErrNotExist) {
		return &State{SchemaVersion: stateSchemaVersion}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state file %s is corrupted: %w", path, err)
	}
	return &s, nil
}

// Save writes the state atomically with 0o600 permissions
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "state-*.json")
	if err != nil {
		return err
	}
	// no-op after a successful rename
	defer os.Remove(tmp.Name()) //nolint:errcheck
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() //nolint:errcheck // already failing
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func findings(cur Snapshot) map[string]Finding {
	out := map[string]Finding{}
	for pkg, vulns := range cur.Vulns {
		ver := cur.Versions[pkg]
		for _, v := range vulns {
			out[Key(pkg, ver, v.ID)] = Finding{
				Package: pkg,
				Version: ver,
				Vuln:    v,
			}
		}
	}
	return out
}

// Compare reports what is new and what was resolved since prev
func Compare(prev *State, cur Snapshot) Diff {
	d := Diff{Baseline: prev == nil || prev.LastScan.IsZero()}
	now := findings(cur)
	for k, f := range now {
		if prev == nil || prev.Known == nil {
			d.New = append(d.New, f)
			continue
		}
		if _, ok := prev.Known[k]; !ok {
			d.New = append(d.New, f)
		}
	}
	if prev != nil {
		for k, e := range prev.Known {
			if _, ok := now[k]; !ok {
				d.Resolved = append(d.Resolved, Finding{
					Package: e.Package,
					Version: e.Version,
					Vuln: types.Vulnerability{
						ID: e.ID, Severity: e.Severity, Summary: e.Summary,
					},
				})
			}
		}
	}
	return d
}

// Apply records the current round in the state
func (s *State) Apply(cur Snapshot, d Diff) {
	if s.Known == nil {
		s.Known = map[string]knownEntry{}
	}
	s.SchemaVersion = stateSchemaVersion
	s.File = cur.File
	s.LastScan = cur.ScannedAt
	for _, f := range d.Resolved {
		delete(s.Known, Key(f.Package, f.Version, f.Vuln.ID))
	}
	for _, f := range d.New {
		s.Known[Key(f.Package, f.Version, f.Vuln.ID)] = knownEntry{
			Package:   f.Package,
			Version:   f.Version,
			ID:        f.Vuln.ID,
			Severity:  f.Vuln.Severity,
			Summary:   f.Vuln.Summary,
			FirstSeen: cur.ScannedAt,
		}
	}
}
