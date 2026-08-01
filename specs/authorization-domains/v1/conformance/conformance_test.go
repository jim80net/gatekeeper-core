// Package conformance is intentionally implementation-independent. It imports
// no production Gatekeeper policy, canonicalization, store, or engine package.
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

const exactObject = "credential://pa/google-service-account-keyfile/v1"

type actionRegistry struct {
	SchemaVersion   string `json:"schema_version"`
	RegistryVersion string `json:"registry_version"`
	Actions         []struct {
		Name    string `json:"name"`
		Meaning string `json:"meaning"`
	} `json:"actions"`
}

type coverageManifest struct {
	SchemaVersion    string `json:"schema_version"`
	ObjectID         string `json:"object_id"`
	EnforcementClaim bool   `json:"enforcement_claim"`
	NeutralReplay    struct {
		Schema                 string `json:"schema"`
		SchemaFile             string `json:"schema_file"`
		IndependentCheckerHead string `json:"independent_checker_head"`
		Coverage               []struct {
			Name           string   `json:"name"`
			Critical       bool     `json:"critical"`
			RequiredTraced bool     `json:"required_traced"`
			MapsTo         []string `json:"maps_to"`
		} `json:"coverage"`
	} `json:"neutral_replay"`
	Seams []struct {
		ID              string `json:"id"`
		Kind            string `json:"kind"`
		Critical        bool   `json:"critical"`
		Owner           string `json:"owner"`
		State           string `json:"state"`
		TraceAction     string `json:"trace_action"`
		NegativeFixture string `json:"negative_fixture"`
		KnownGap        string `json:"known_gap"`
	} `json:"seams"`
}

type fixtureDocument struct {
	SchemaVersion string        `json:"schema_version"`
	ObjectID      string        `json:"object_id"`
	Cases         []fixtureCase `json:"cases"`
	TraceActions  []string      `json:"trace_actions"`
}

type fixtureCase struct {
	Name                      string `json:"name"`
	Kind                      string `json:"kind"`
	Protected                 bool   `json:"protected"`
	Action                    string `json:"action"`
	Generation                int    `json:"generation"`
	CurrentGeneration         int    `json:"current_generation"`
	ExpectedGeneration        int    `json:"expected_generation"`
	ContextValid              bool   `json:"context_valid"`
	Exception                 string `json:"exception"`
	AuditAvailable            bool   `json:"audit_available"`
	ReplayAvailable           bool   `json:"replay_available"`
	ExpectedDecision          string `json:"expected_decision"`
	ExpectedEffect            bool   `json:"expected_effect"`
	CandidateValid            bool   `json:"candidate_valid"`
	ExpectedPublish           bool   `json:"expected_publish"`
	ExpectedLastGood          int    `json:"expected_last_good"`
	IdempotentReplay          bool   `json:"idempotent_replay"`
	WorkerStopped             bool   `json:"worker_stopped"`
	ExceptionRemoved          bool   `json:"exception_removed"`
	ProtectedMaterialAbsent   bool   `json:"protected_material_absent"`
	ArtifactsReadable         bool   `json:"artifacts_readable"`
	ExpectedArchiveComplete   bool   `json:"expected_archive_complete"`
	ProcessTreeBounded        bool   `json:"process_tree_bounded"`
	EnvironmentReconstructed  bool   `json:"environment_reconstructed"`
	UIDOrContainerProbePassed bool   `json:"uid_or_container_probe_passed"`
	ExpectedIsolationClaim    string `json:"expected_isolation_claim"`
}

func readStrictJSON(t *testing.T, relative string, dst any) {
	t.Helper()
	f, err := os.Open(filepath.Join("..", relative))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		t.Fatalf("decode %s: %v", relative, err)
	}
	if decoder.More() {
		t.Fatalf("%s contains trailing JSON values", relative)
	}
}

func TestInitialActionRegistryIsReadOnly(t *testing.T) {
	var registry actionRegistry
	readStrictJSON(t, "action-registry.json", &registry)
	if registry.SchemaVersion != "authorization-domains/v1" || registry.RegistryVersion != "1" {
		t.Fatalf("unexpected registry version: %#v", registry)
	}
	if len(registry.Actions) != 1 || registry.Actions[0].Name != "read" || registry.Actions[0].Meaning == "" {
		t.Fatalf("initial registry must contain exactly read: %#v", registry.Actions)
	}
}

func TestCoverageManifestIsHonestAndComplete(t *testing.T) {
	var manifest coverageManifest
	var fixtures fixtureDocument
	readStrictJSON(t, "coverage-manifest.json", &manifest)
	readStrictJSON(t, filepath.Join("fixtures", "cases.json"), &fixtures)

	if manifest.ObjectID != exactObject || fixtures.ObjectID != exactObject {
		t.Fatalf("object pin mismatch: manifest=%q fixtures=%q", manifest.ObjectID, fixtures.ObjectID)
	}
	if manifest.EnforcementClaim {
		t.Fatal("D1 contract proposal must not claim runtime enforcement")
	}
	fixtureNames := make(map[string]bool, len(fixtures.Cases))
	for _, c := range fixtures.Cases {
		fixtureNames[c.Name] = true
	}
	traces := make(map[string]bool, len(fixtures.TraceActions))
	for _, action := range fixtures.TraceActions {
		traces[action] = true
	}
	seenSeams := map[string]bool{}
	for _, seam := range manifest.Seams {
		if !seam.Critical || seam.ID == "" || seam.Owner == "" || seam.KnownGap == "" {
			t.Errorf("critical seam metadata incomplete: %#v", seam)
		}
		if seam.State != "contract_only" {
			t.Errorf("D1 seam %q state = %q, want contract_only", seam.ID, seam.State)
		}
		if !fixtureNames[seam.NegativeFixture] {
			t.Errorf("seam %q references missing negative fixture %q", seam.ID, seam.NegativeFixture)
		}
		if !traces[seam.TraceAction] {
			t.Errorf("seam %q has untraced critical action %q", seam.ID, seam.TraceAction)
		}
		if seenSeams[seam.ID] {
			t.Errorf("duplicate seam %q", seam.ID)
		}
		seenSeams[seam.ID] = true
	}
	if len(seenSeams) != 6 {
		t.Fatalf("got %d critical seams, want 6", len(seenSeams))
	}
	if manifest.NeutralReplay.Schema != "gatekeeper.auth-domains.replay/v1" ||
		manifest.NeutralReplay.SchemaFile != "neutral-replay.schema.json" ||
		manifest.NeutralReplay.IndependentCheckerHead != "1cc451f1ff89aaf8a495b7495a5634ad2609690e" {
		t.Fatalf("neutral replay pin mismatch: %#v", manifest.NeutralReplay)
	}
	wantNeutral := map[string]bool{
		"ordinary-work":        false,
		"protected-read-pep":   true,
		"protected-read-audit": true,
	}
	if len(manifest.NeutralReplay.Coverage) != len(wantNeutral) {
		t.Fatalf("got %d neutral seams, want %d", len(manifest.NeutralReplay.Coverage), len(wantNeutral))
	}
	for _, seam := range manifest.NeutralReplay.Coverage {
		critical, ok := wantNeutral[seam.Name]
		if !ok || critical != seam.Critical || !seam.RequiredTraced || len(seam.MapsTo) == 0 {
			t.Errorf("invalid neutral seam: %#v", seam)
		}
		for _, implementationSeam := range seam.MapsTo {
			if !seenSeams[implementationSeam] {
				t.Errorf("neutral seam %q maps to unknown implementation seam %q", seam.Name, implementationSeam)
			}
		}
	}
}

func TestIndependentTransitionFixtures(t *testing.T) {
	var doc fixtureDocument
	readStrictJSON(t, filepath.Join("fixtures", "cases.json"), &doc)
	if doc.SchemaVersion != "authorization-domains/v1" {
		t.Fatalf("schema version = %q", doc.SchemaVersion)
	}
	seen := map[string]bool{}
	for _, tc := range doc.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Name == "" || seen[tc.Name] {
				t.Fatalf("fixture name empty or duplicate: %q", tc.Name)
			}
			seen[tc.Name] = true
			switch tc.Kind {
			case "evaluate":
				decision, effect := independentEvaluate(tc)
				if decision != tc.ExpectedDecision || effect != tc.ExpectedEffect {
					t.Fatalf("got decision=%s effect=%v, want decision=%s effect=%v", decision, effect, tc.ExpectedDecision, tc.ExpectedEffect)
				}
			case "compile":
				published := tc.CandidateValid
				lastGood := tc.CurrentGeneration
				if published != tc.ExpectedPublish || lastGood != tc.ExpectedLastGood {
					t.Fatal("compile expectation mismatch")
				}
			case "publish":
				published, lastGood := independentPublish(tc)
				if published != tc.ExpectedPublish || lastGood != tc.ExpectedLastGood {
					t.Fatalf("got publish=%v last_good=%d, want publish=%v last_good=%d", published, lastGood, tc.ExpectedPublish, tc.ExpectedLastGood)
				}
			case "revoke":
				effect := tc.Generation == tc.CurrentGeneration
				if effect != tc.ExpectedEffect || tc.CurrentGeneration != tc.ExpectedLastGood {
					t.Fatal("revoke successor did not invalidate stale generation")
				}
			case "archive":
				complete := tc.WorkerStopped && tc.ExceptionRemoved && tc.ProtectedMaterialAbsent && tc.ArtifactsReadable
				if complete != tc.ExpectedArchiveComplete {
					t.Fatalf("archive complete=%v, want %v", complete, tc.ExpectedArchiveComplete)
				}
			case "lifecycle":
				claim := "unproved"
				if tc.UIDOrContainerProbePassed {
					claim = "proved_boundary"
				}
				if claim != tc.ExpectedIsolationClaim {
					t.Fatalf("isolation claim=%q, want %q", claim, tc.ExpectedIsolationClaim)
				}
			default:
				t.Fatalf("unknown fixture kind %q", tc.Kind)
			}
		})
	}
}

func independentEvaluate(tc fixtureCase) (decision string, effect bool) {
	if !tc.Protected {
		return "permit_unblocked", true
	}
	if tc.Action != "read" || tc.Generation != tc.CurrentGeneration || !tc.ContextValid {
		return "deny_blocked", false
	}
	if tc.Exception != "exact" {
		return "deny_blocked", false
	}
	decision = "permit_exception"
	return decision, tc.AuditAvailable && tc.ReplayAvailable
}

func independentPublish(tc fixtureCase) (bool, int) {
	if !tc.CandidateValid || tc.ExpectedGeneration != tc.CurrentGeneration {
		return false, tc.CurrentGeneration
	}
	// An idempotent replay returns the previously admitted successor rather than
	// creating another generation; the fixture's last-good remains +1.
	return true, tc.CurrentGeneration + 1
}

func TestCriticalTraceActionSetIsStable(t *testing.T) {
	var manifest coverageManifest
	var fixtures fixtureDocument
	readStrictJSON(t, "coverage-manifest.json", &manifest)
	readStrictJSON(t, filepath.Join("fixtures", "cases.json"), &fixtures)
	want := make([]string, 0, len(manifest.Seams))
	for _, seam := range manifest.Seams {
		want = append(want, seam.TraceAction)
	}
	got := append([]string(nil), fixtures.TraceActions...)
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("trace actions mismatch\n got: %s\nwant: %s", fmt.Sprint(got), fmt.Sprint(want))
	}
}
