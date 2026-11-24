package monitor

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/angela/pkg/types"
)

func TestCompare(t *testing.T) {
	firstScan := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	vulnA := types.Vulnerability{
		ID:       "GHSA-aaaa",
		Severity: "high",
		Summary:  "Vulnerability A",
	}
	vulnB := types.Vulnerability{
		ID:       "GHSA-bbbb",
		Severity: "moderate",
		Summary:  "Vulnerability B",
	}

	snapshot := func(
		pkg, version string,
		vulns ...types.Vulnerability,
	) Snapshot {
		return Snapshot{
			File:      "req.txt",
			ScannedAt: firstScan,
			Versions:  map[string]string{pkg: version},
			Vulns:     map[string][]types.Vulnerability{pkg: vulns},
		}
	}

	initial := snapshot("django", "3.2.0", vulnA)
	prev := &State{}
	prev.Apply(initial, Compare(prev, initial))

	normalized := snapshot("Django", "3.2.0", vulnA)
	normalized.Versions = map[string]string{"django": "3.2.0"}

	tests := []struct {
		name         string
		prev         *State
		cur          Snapshot
		wantBaseline bool
		wantNew      []string
		wantResolved []string
	}{
		{
			name:         "baseline without state",
			cur:          initial,
			wantBaseline: true,
			wantNew:      []string{"django@3.2.0#GHSA-aaaa"},
		},
		{
			name:         "baseline with empty state",
			prev:         &State{},
			cur:          initial,
			wantBaseline: true,
			wantNew:      []string{"django@3.2.0#GHSA-aaaa"},
		},
		{
			name: "unchanged",
			prev: prev,
			cur:  initial,
		},
		{
			name:    "new vulnerability for same version",
			prev:    prev,
			cur:     snapshot("django", "3.2.0", vulnA, vulnB),
			wantNew: []string{"django@3.2.0#GHSA-bbbb"},
		},
		{
			name:         "version changed",
			prev:         prev,
			cur:          snapshot("django", "4.2.16", vulnB),
			wantNew:      []string{"django@4.2.16#GHSA-bbbb"},
			wantResolved: []string{"django@3.2.0#GHSA-aaaa"},
		},
		{
			name:         "advisory removed",
			prev:         prev,
			cur:          snapshot("django", "3.2.0"),
			wantResolved: []string{"django@3.2.0#GHSA-aaaa"},
		},
		{
			name: "normalized package name",
			prev: prev,
			cur:  normalized,
		},
		{
			name: "duplicate finding",
			prev: prev,
			cur:  snapshot("django", "3.2.0", vulnA, vulnB, vulnB),
			wantNew: []string{
				"django@3.2.0#GHSA-bbbb",
			},
		},
	}

	keys := func(findings []Finding) []string {
		result := make([]string, 0, len(findings))
		for _, finding := range findings {
			result = append(result, Key(
				finding.Package,
				finding.Version,
				finding.Vuln.ID,
			))
		}
		slices.Sort(result)
		return result
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.prev, tt.cur)

			if got.Baseline != tt.wantBaseline {
				t.Errorf(
					"Baseline = %v, want %v",
					got.Baseline, tt.wantBaseline,
				)
			}
			if gotKeys := keys(got.New); !slices.Equal(gotKeys, tt.wantNew) {
				t.Errorf("New = %v, want %v", gotKeys, tt.wantNew)
			}
			gotResolved := keys(got.Resolved)
			if !slices.Equal(gotResolved, tt.wantResolved) {
				t.Errorf(
					"Resolved = %v, want %v",
					gotResolved, tt.wantResolved,
				)
			}
		})
	}
}

func TestStateRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	firstScan := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	cur := Snapshot{
		File:      "req.txt",
		ScannedAt: firstScan,
		Versions:  map[string]string{"django": "3.2.0"},
		Vulns: map[string][]types.Vulnerability{
			"django": {
				{
					ID:       "GHSA-aaaa",
					Severity: "high",
					Summary:  "Vulnerability A",
				},
			},
		},
	}

	state, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState for missing file: %v", err)
	}

	state.Apply(cur, Compare(state, cur))

	// A second round must preserve when the finding was first seen.
	cur.ScannedAt = firstScan.Add(time.Hour)
	state.Apply(cur, Compare(state, cur))

	if err = state.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	diff := Compare(loaded, cur)
	if diff.Baseline || len(diff.New) != 0 || len(diff.Resolved) != 0 {
		t.Fatalf("restart repeated findings: %+v", diff)
	}

	entry, ok := loaded.Known[Key("django", "3.2.0", "GHSA-aaaa")]
	if !ok {
		t.Fatal("saved finding is missing")
	}
	if !entry.FirstSeen.Equal(firstScan) {
		t.Errorf("FirstSeen = %v, want %v", entry.FirstSeen, firstScan)
	}
	if entry.Package != "django" || entry.Version != "3.2.0" ||
		entry.ID != "GHSA-aaaa" || entry.Severity != "high" ||
		entry.Summary != "Vulnerability A" {
		t.Errorf("finding changed after restart: %+v", entry)
	}
	if loaded.SchemaVersion != stateSchemaVersion {
		t.Errorf("SchemaVersion = %d", loaded.SchemaVersion)
	}
	if loaded.File != cur.File || !loaded.LastScan.Equal(cur.ScannedAt) {
		t.Errorf("scan metadata changed after restart: %+v", loaded)
	}

	// When the advisory disappears, Apply must remove it from state.
	cur.Vulns = nil
	state.Apply(cur, Compare(state, cur))
	if len(state.Known) != 0 {
		t.Errorf("resolved finding remained in state: %+v", state.Known)
	}
}

func TestLoadStateCorrupted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	content := []byte(`{"known":`)

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadState(path)
	if err == nil || !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("expected clear corruption error, got %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(content) {
		t.Fatal("LoadState changed the corrupted file")
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		pkg  string
		want string
	}{
		{"Django", "django@3.2.0#GHSA-aaaa"},
		{"django", "django@3.2.0#GHSA-aaaa"},
		{"My_Package.Name", "my-package-name@3.2.0#GHSA-aaaa"},
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			got := Key(tt.pkg, "3.2.0", "GHSA-aaaa")
			if got != tt.want {
				t.Errorf("Key = %q, want %q", got, tt.want)
			}
		})
	}
}
