// Package conformance is intentionally implementation-independent. It imports
// no production Gatekeeper policy, canonicalization, store, or engine package.
package conformance

import (
	"encoding/json"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
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
	DomainContext    struct {
		FixtureFile                     string   `json:"fixture_file"`
		MintSource                      string   `json:"mint_source"`
		RejectOverrideSources           []string `json:"reject_override_sources"`
		KeyConsumers                    []string `json:"key_consumers"`
		SamePrincipalCrossDomainFixture bool     `json:"same_principal_cross_domain_fixture"`
	} `json:"domain_context"`
	NeutralReplay struct {
		Schema                  string `json:"schema"`
		SchemaFile              string `json:"schema_file"`
		LifecycleContractSHA256 string `json:"lifecycle_contract_sha256"`
		LifecycleProbeRegistry  string `json:"lifecycle_probe_registry"`
		IndependentCheckerHead  string `json:"independent_checker_head"`
		Coverage                []struct {
			Name           string   `json:"name"`
			Critical       bool     `json:"critical"`
			RequiredTraced bool     `json:"required_traced"`
			MapsTo         []string `json:"maps_to"`
		} `json:"coverage"`
	} `json:"neutral_replay"`
	Seams []coverageSeam `json:"seams"`
}

type coverageSeam struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Critical        bool   `json:"critical"`
	Owner           string `json:"owner"`
	State           string `json:"state"`
	TraceAction     string `json:"trace_action"`
	NegativeFixture string `json:"negative_fixture"`
	KnownGap        string `json:"known_gap"`
}

type fixtureDocument struct {
	SchemaVersion string        `json:"schema_version"`
	ObjectID      string        `json:"object_id"`
	Cases         []fixtureCase `json:"cases"`
	TraceActions  []string      `json:"trace_actions"`
}

type domainContextFixtureDocument struct {
	SchemaVersion string              `json:"schema_version"`
	ObjectID      string              `json:"object_id"`
	Cases         []domainContextCase `json:"cases"`
}

type domainContextCase struct {
	Name                    string `json:"name"`
	PrincipalPublicKey      string `json:"principal_public_key"`
	ObservedHost            string `json:"observed_host"`
	ResolvedDomainID        string `json:"resolved_domain_id"`
	ClaimedDomainID         string `json:"claimed_domain_id"`
	OverrideSource          string `json:"override_source"`
	OverrideDomainID        string `json:"override_domain_id"`
	ExpectedContextID       string `json:"expected_context_id"`
	ExpectedMint            bool   `json:"expected_mint"`
	ExpectedResolutionCalls int    `json:"expected_resolution_calls"`
}

type lifecycleProbeRegistry struct {
	SchemaVersion     string   `json:"schema_version"`
	SourceSHA256      string   `json:"source_sha256"`
	SyntheticObject   string   `json:"synthetic_object"`
	Action            string   `json:"action"`
	Claims            []string `json:"claims"`
	ClaimInvalidators []string `json:"claim_invalidators"`
	ProbeCount        int      `json:"probe_count"`
	Probes            []struct {
		ID       string `json:"id"`
		Expected string `json:"expected"`
		Reason   string `json:"reason,omitempty"`
	} `json:"probes"`
}

type fixtureCase struct {
	Name                     string `json:"name"`
	Kind                     string `json:"kind"`
	Protected                bool   `json:"protected"`
	Action                   string `json:"action"`
	Generation               int    `json:"generation"`
	CurrentGeneration        int    `json:"current_generation"`
	ExpectedGeneration       int    `json:"expected_generation"`
	ContextValid             bool   `json:"context_valid"`
	Exception                string `json:"exception"`
	AuditAvailable           bool   `json:"audit_available"`
	ReplayAvailable          bool   `json:"replay_available"`
	ExpectedDecision         string `json:"expected_decision"`
	ExpectedEffect           bool   `json:"expected_effect"`
	CandidateValid           bool   `json:"candidate_valid"`
	ExpectedPublish          bool   `json:"expected_publish"`
	ExpectedLastGood         int    `json:"expected_last_good"`
	IdempotentReplay         bool   `json:"idempotent_replay"`
	WorkerStopped            bool   `json:"worker_stopped"`
	ExceptionRemoved         bool   `json:"exception_removed"`
	ProtectedMaterialAbsent  bool   `json:"protected_material_absent"`
	ArtifactsReadable        bool   `json:"artifacts_readable"`
	ExpectedArchiveComplete  bool   `json:"expected_archive_complete"`
	ProcessTreeBounded       bool   `json:"process_tree_bounded"`
	EnvironmentReconstructed bool   `json:"environment_reconstructed"`
	PoolsBounded             bool   `json:"pools_bounded"`
	TimeoutsEnforced         bool   `json:"timeouts_enforced"`
	ProcessGroupManaged      bool   `json:"process_group_managed"`
	DedicatedUIDProbePassed  bool   `json:"dedicated_uid_probe_passed"`
	ContainerProbePassed     bool   `json:"container_probe_passed"`
	ExpectedIsolationClaim   string `json:"expected_isolation_claim"`
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

func TestPinnedLifecycleProbeRegistry(t *testing.T) {
	var registry lifecycleProbeRegistry
	readStrictJSON(t, "lifecycle-probes.json", &registry)
	if registry.SourceSHA256 != "4a5d12ff96b136db5bd7e78c9467a222c242be99c060d5a17fe267725bc9caff" {
		t.Fatalf("lifecycle source pin = %q", registry.SourceSHA256)
	}
	if registry.SyntheticObject != "fixture://authorization-domains/protected/exact-read-object" || registry.Action != "read" {
		t.Fatalf("lifecycle registry widened protected binding: object=%q action=%q", registry.SyntheticObject, registry.Action)
	}
	if registry.ProbeCount != 38 || len(registry.Probes) != registry.ProbeCount {
		t.Fatalf("probe count metadata=%d actual=%d, want 38", registry.ProbeCount, len(registry.Probes))
	}
	wantPrefixes := map[string]int{"UID": 7, "CTR": 7, "PROC": 6, "ENV": 4, "LIFE": 8, "PA": 5, "ROOT": 1}
	gotPrefixes := map[string]int{}
	seen := map[string]bool{}
	for _, probe := range registry.Probes {
		prefix := probe.ID
		if i := strings.IndexByte(prefix, '-'); i >= 0 {
			prefix = prefix[:i]
		}
		if probe.ID == "" || probe.Expected == "" || seen[probe.ID] {
			t.Errorf("invalid or duplicate probe: %#v", probe)
		}
		seen[probe.ID] = true
		gotPrefixes[prefix]++
	}
	if !reflect.DeepEqual(gotPrefixes, wantPrefixes) {
		t.Fatalf("probe family counts = %#v, want %#v", gotPrefixes, wantPrefixes)
	}
}

func TestCoverageManifestIsHonestAndComplete(t *testing.T) {
	var manifest coverageManifest
	var fixtures fixtureDocument
	var domainFixtures domainContextFixtureDocument
	readStrictJSON(t, "coverage-manifest.json", &manifest)
	readStrictJSON(t, filepath.Join("fixtures", "cases.json"), &fixtures)
	readStrictJSON(t, "domain-context-cases.json", &domainFixtures)

	if manifest.ObjectID != exactObject || fixtures.ObjectID != exactObject || domainFixtures.ObjectID != exactObject {
		t.Fatalf("object pin mismatch: manifest=%q fixtures=%q domain_fixtures=%q", manifest.ObjectID, fixtures.ObjectID, domainFixtures.ObjectID)
	}
	if manifest.EnforcementClaim {
		t.Fatal("D1 contract proposal must not claim runtime enforcement")
	}
	fixtureNames := make(map[string]bool, len(fixtures.Cases))
	for _, c := range fixtures.Cases {
		fixtureNames[c.Name] = true
	}
	for _, c := range domainFixtures.Cases {
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
	if len(seenSeams) != 8 {
		t.Fatalf("got %d critical seams, want 8", len(seenSeams))
	}
	if manifest.DomainContext.FixtureFile != "domain-context-cases.json" ||
		manifest.DomainContext.MintSource != "server_observed_host" ||
		!manifest.DomainContext.SamePrincipalCrossDomainFixture ||
		!reflect.DeepEqual(manifest.DomainContext.RejectOverrideSources, []string{"client", "worker"}) ||
		!reflect.DeepEqual(manifest.DomainContext.KeyConsumers, []string{"storage", "replay", "rate_limit", "audit"}) {
		t.Fatalf("domain context contract mismatch: %#v", manifest.DomainContext)
	}
	if manifest.NeutralReplay.Schema != "gatekeeper.auth-domains.replay/v1" ||
		manifest.NeutralReplay.SchemaFile != "neutral-replay.schema.json" ||
		manifest.NeutralReplay.LifecycleContractSHA256 != "4a5d12ff96b136db5bd7e78c9467a222c242be99c060d5a17fe267725bc9caff" ||
		manifest.NeutralReplay.LifecycleProbeRegistry != "lifecycle-probes.json" ||
		manifest.NeutralReplay.IndependentCheckerHead != "8e376c79d64bc720b280ab839058cc71ca774990" {
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
				if !tc.ProcessTreeBounded || !tc.EnvironmentReconstructed || !tc.PoolsBounded || !tc.TimeoutsEnforced || !tc.ProcessGroupManaged {
					t.Fatalf("lifecycle fixture must exercise all hygiene controls: %#v", tc)
				}
				claim := "unproved"
				if tc.DedicatedUIDProbePassed && tc.ContainerProbePassed {
					claim = "proved_linux_user+proved_container"
				} else if tc.DedicatedUIDProbePassed {
					claim = "proved_linux_user"
				} else if tc.ContainerProbePassed {
					claim = "proved_container"
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

type resolvedDomainContext struct {
	ContextID          string
	DomainID           string
	PrincipalPublicKey string
	ClaimedDomainID    string
}

func independentResolveDomainContext(tc domainContextCase) (resolvedDomainContext, bool, int) {
	if tc.OverrideSource != "none" || tc.OverrideDomainID != "" {
		return resolvedDomainContext{}, false, 0
	}
	resolvedByObservedHost := map[string]string{
		"alpha.fixture.invalid": "community-alpha",
		"beta.fixture.invalid":  "community-beta",
	}
	domainID, ok := resolvedByObservedHost[tc.ObservedHost]
	if !ok || domainID != tc.ResolvedDomainID || tc.PrincipalPublicKey == "" {
		return resolvedDomainContext{}, false, 1
	}
	return resolvedDomainContext{
		ContextID:          "ctx-" + domainID,
		DomainID:           domainID,
		PrincipalPublicKey: tc.PrincipalPublicKey,
		ClaimedDomainID:    tc.ClaimedDomainID,
	}, true, 1
}

func independentContextKeys(context resolvedDomainContext, objectID string) map[string]string {
	return map[string]string{
		"storage":    strings.Join([]string{"storage", context.DomainID, objectID}, "|"),
		"replay":     strings.Join([]string{"replay", context.DomainID, context.ContextID, "decision-fixture", "pep-fixture", "1"}, "|"),
		"rate_limit": strings.Join([]string{"rate-limit", context.DomainID, context.PrincipalPublicKey, "read", objectID, "window-fixture"}, "|"),
		"audit":      strings.Join([]string{"audit", context.DomainID, context.ContextID, "sequence-fixture"}, "|"),
	}
}

func TestDomainContextIsServerMintedAndKeysAreDomainScoped(t *testing.T) {
	var doc domainContextFixtureDocument
	readStrictJSON(t, "domain-context-cases.json", &doc)
	if doc.SchemaVersion != "authorization-domains/v1" || doc.ObjectID != exactObject {
		t.Fatalf("unexpected DomainContext fixture header: %#v", doc)
	}

	byPrincipal := map[string][]map[string]string{}
	seenOverrides := map[string]bool{}
	seenCases := map[string]bool{}
	for _, tc := range doc.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Name == "" || seenCases[tc.Name] {
				t.Fatalf("DomainContext fixture name empty or duplicate: %q", tc.Name)
			}
			seenCases[tc.Name] = true
			context, minted, resolutionCalls := independentResolveDomainContext(tc)
			if minted != tc.ExpectedMint || resolutionCalls != tc.ExpectedResolutionCalls {
				t.Fatalf("minted=%v calls=%d, want minted=%v calls=%d", minted, resolutionCalls, tc.ExpectedMint, tc.ExpectedResolutionCalls)
			}
			if !minted {
				if (tc.OverrideSource != "client" && tc.OverrideSource != "worker") || tc.OverrideDomainID == "" {
					t.Fatalf("rejected fixture lacks a client/worker override: %#v", tc)
				}
				seenOverrides[tc.OverrideSource] = true
				return
			}
			if context.DomainID != tc.ResolvedDomainID || context.ClaimedDomainID != tc.ClaimedDomainID {
				t.Fatalf("claimed/resolved context collapsed: %#v", context)
			}
			if context.ContextID != tc.ExpectedContextID {
				t.Fatalf("server-minted context ID=%q, want %q", context.ContextID, tc.ExpectedContextID)
			}
			if context.ClaimedDomainID == context.DomainID {
				t.Fatalf("fixture must keep claimed and resolved communities distinct: %#v", context)
			}
			keys := independentContextKeys(context, doc.ObjectID)
			for consumer, key := range keys {
				if !strings.Contains(key, "|"+context.DomainID+"|") {
					t.Errorf("%s key does not use resolved domain: %q", consumer, key)
				}
				if strings.Contains(key, "|"+context.ClaimedDomainID+"|") {
					t.Errorf("%s key used claimed domain: %q", consumer, key)
				}
			}
			byPrincipal[context.PrincipalPublicKey] = append(byPrincipal[context.PrincipalPublicKey], keys)
		})
	}
	if !seenOverrides["client"] || !seenOverrides["worker"] {
		t.Fatalf("override rejection coverage = %#v", seenOverrides)
	}
	keys := byPrincipal["fixture-pubkey-same-principal"]
	if len(keys) != 2 {
		t.Fatalf("same-principal cross-community cases = %d, want 2", len(keys))
	}
	for consumer := range keys[0] {
		if keys[0][consumer] == keys[1][consumer] {
			t.Errorf("same public key crossed communities in %s key: %q", consumer, keys[0][consumer])
		}
	}
}

func TestCheckerImportsOnlyStandardLibrary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			pkg, err := build.Default.Import(path, ".", build.FindOnly)
			if err != nil || !pkg.Goroot {
				t.Errorf("independent checker imports non-standard package %q", path)
			}
		}
	}
}

func criticalTraceCoverageProblems(manifest coverageManifest, traceActions []string) []string {
	traces := make(map[string]bool, len(traceActions))
	for _, action := range traceActions {
		traces[action] = true
	}
	var problems []string
	for _, seam := range manifest.Seams {
		if seam.Critical && !traces[seam.TraceAction] {
			problems = append(problems, fmt.Sprintf("critical seam %q is untraced by %q", seam.ID, seam.TraceAction))
		}
	}
	return problems
}

func TestUntracedOrUnknownCriticalSeamFailsCoverage(t *testing.T) {
	var manifest coverageManifest
	var fixtures fixtureDocument
	readStrictJSON(t, "coverage-manifest.json", &manifest)
	readStrictJSON(t, filepath.Join("fixtures", "cases.json"), &fixtures)

	if problems := criticalTraceCoverageProblems(manifest, fixtures.TraceActions); len(problems) != 0 {
		t.Fatalf("valid manifest failed trace coverage: %v", problems)
	}
	withoutMint := make([]string, 0, len(fixtures.TraceActions)-1)
	for _, action := range fixtures.TraceActions {
		if action != "domain_context_minted" {
			withoutMint = append(withoutMint, action)
		}
	}
	if problems := criticalTraceCoverageProblems(manifest, withoutMint); len(problems) == 0 {
		t.Fatal("untraced critical DomainContext seam passed coverage")
	}
	unknown := manifest
	unknown.Seams = append(append([]coverageSeam(nil), manifest.Seams...), coverageSeam{
		ID: "unknown-critical-seam", Critical: true, TraceAction: "unknown_critical_action",
	})
	if problems := criticalTraceCoverageProblems(unknown, fixtures.TraceActions); len(problems) == 0 {
		t.Fatal("unknown critical trace action passed coverage")
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
