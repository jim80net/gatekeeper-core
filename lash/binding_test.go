package lash

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jim80net/gatekeeper-core/canonical"
)

func TestBindingRejectsPlanAndEnvironmentSubstitution(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	plan := testPlan()
	auth := Authorization{
		DecisionID: "decision-1", Decision: canonical.Allow, DomainID: "domain-pa", ContextID: "context-1",
		Action: "read_credential", PolicyDigest: digest("policy"),
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	binding, err := Seal(auth, plan, "host-key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(binding, plan, now, publicKey); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}

	mutated := plan
	mutated.Argv = append([]string(nil), plan.Argv...)
	mutated.Argv[1] = "other"
	if err := Verify(binding, mutated, now, publicKey); err == nil {
		t.Fatal("argv substitution passed binding verification")
	}
	mutated = plan
	mutated.Environment = append([]EnvVar(nil), plan.Environment...)
	mutated.Environment[0].Value = "attacker"
	if err := Verify(binding, mutated, now, publicKey); err == nil {
		t.Fatal("environment substitution passed binding verification")
	}
	mutated = plan
	mutated.ExecutableSHA256 = digest("different artifact")
	if err := Verify(binding, mutated, now, publicKey); err == nil {
		t.Fatal("artifact substitution passed binding verification")
	}
}

func TestBindingCannotSealNonAllowDecision(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	auth := Authorization{
		DecisionID: "decision-1", Decision: canonical.Deny, DomainID: "domain-pa", ContextID: "context-1",
		Action: "read_credential", PolicyDigest: digest("policy"), IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if _, err := Seal(auth, testPlan(), "host-key-1", privateKey); err == nil {
		t.Fatal("non-allow decision produced an execution binding")
	}
}

func TestCanonicalPlanNormalizesUnorderedSets(t *testing.T) {
	first := testPlan()
	second := testPlan()
	second.Environment[0], second.Environment[1] = second.Environment[1], second.Environment[0]
	second.LogicalCredentials[0], second.LogicalCredentials[1] = second.LogicalCredentials[1], second.LogicalCredentials[0]
	one, err := PlanDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	two, err := PlanDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatalf("equivalent plans produced different digests: %s != %s", one, two)
	}
}

func TestBoundArtifactKeepsVerifiedFileDescription(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tool")
	original := []byte("verified executable bytes")
	if err := os.WriteFile(path, original, 0o700); err != nil {
		t.Fatal(err)
	}
	bound, err := OpenBoundArtifact(path, digestBytes(original))
	if err != nil {
		t.Fatal(err)
	}
	defer bound.File.Close()

	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte("attacker replacement"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == string(original) {
		t.Fatal("test did not replace executable path")
	}
	fromDescriptor := make([]byte, len(original))
	if _, err := bound.File.ReadAt(fromDescriptor, 0); err != nil {
		t.Fatal(err)
	}
	if string(fromDescriptor) != string(original) {
		t.Fatal("bound descriptor no longer identifies verified bytes")
	}
}

func testPlan() ExecutionPlan {
	return ExecutionPlan{
		Schema: PlanSchema, Executable: "/usr/bin/example", ExecutableSHA256: digest("binary"),
		Argv: []string{"/usr/bin/example", "safe"}, WorkingDirectory: "/workspace",
		Environment: []EnvVar{{Name: "PATH", Value: "/usr/bin"}, {Name: "LANG", Value: "C"}},
		UID:         1000, GID: 1000, SandboxProfile: "fleet-default",
		LogicalCredentials: []string{"credential:github", "credential:pypi"},
	}
}

func digest(value string) string { return digestBytes([]byte(value)) }

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
