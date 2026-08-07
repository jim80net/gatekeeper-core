// Package lash contains the execution-envelope primitives for the Gatekeeper
// Lash prototype. It deliberately does not execute commands: the first proof
// is that a deterministic authorization can be bound to the exact artifact,
// argv, working directory, and reconstructed environment an executor receives.
package lash

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jim80net/gatekeeper-core/canonical"
)

const (
	PlanSchema    = "gatekeeper.lash.execution-plan/v1"
	BindingSchema = "gatekeeper.lash.authorization-binding/v1"
)

// EnvVar is one explicitly reconstructed environment entry. An execution plan
// never inherits the caller's ambient environment.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ExecutionPlan is the closed input to a future executor. ExecutableSHA256 is
// the digest of the bytes opened for execution, not merely the path string.
type ExecutionPlan struct {
	Schema             string   `json:"schema"`
	Executable         string   `json:"executable"`
	ExecutableSHA256   string   `json:"executable_sha256"`
	Argv               []string `json:"argv"`
	WorkingDirectory   string   `json:"working_directory"`
	Environment        []EnvVar `json:"environment"`
	UID                uint32   `json:"uid"`
	GID                uint32   `json:"gid"`
	SandboxProfile     string   `json:"sandbox_profile"`
	LogicalCredentials []string `json:"logical_credentials"`
}

// Authorization is the deterministic Gatekeeper decision being materialized.
// It intentionally has no model output: advisory classification must already
// have been reduced to deterministic policy before this structure is signed.
type Authorization struct {
	DecisionID   string             `json:"decision_id"`
	Decision     canonical.Decision `json:"decision"`
	DomainID     string             `json:"domain_id"`
	ContextID    string             `json:"context_id"`
	Action       string             `json:"action"`
	PolicyDigest string             `json:"policy_digest"`
	IssuedAt     time.Time          `json:"issued_at"`
	ExpiresAt    time.Time          `json:"expires_at"`
}

// Binding cryptographically joins an authorization to one canonical plan.
type Binding struct {
	Schema        string        `json:"schema"`
	Authorization Authorization `json:"authorization"`
	PlanDigest    string        `json:"plan_digest"`
	SignerID      string        `json:"signer_id"`
	Signature     string        `json:"signature"`
}

// CanonicalPlan validates and returns a deterministic JSON representation.
func CanonicalPlan(plan ExecutionPlan) ([]byte, error) {
	if plan.Schema != PlanSchema {
		return nil, fmt.Errorf("lash: unsupported plan schema %q", plan.Schema)
	}
	if !filepath.IsAbs(plan.Executable) || !filepath.IsAbs(plan.WorkingDirectory) {
		return nil, errors.New("lash: executable and working directory must be absolute")
	}
	if len(plan.Argv) == 0 || plan.Argv[0] != plan.Executable {
		return nil, errors.New("lash: argv[0] must equal the absolute executable")
	}
	if !validSHA256(plan.ExecutableSHA256) {
		return nil, errors.New("lash: executable digest must be lowercase SHA-256")
	}
	if plan.SandboxProfile == "" {
		return nil, errors.New("lash: sandbox profile is required")
	}
	for _, value := range append(append([]string{}, plan.Argv...), plan.WorkingDirectory, plan.SandboxProfile) {
		if strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("lash: plan values cannot contain NUL")
		}
	}

	canonical := plan
	canonical.Environment = append([]EnvVar(nil), plan.Environment...)
	sort.Slice(canonical.Environment, func(i, j int) bool {
		return canonical.Environment[i].Name < canonical.Environment[j].Name
	})
	for i, env := range canonical.Environment {
		if env.Name == "" || strings.ContainsAny(env.Name, "=\x00") || strings.IndexByte(env.Value, 0) >= 0 {
			return nil, fmt.Errorf("lash: invalid environment entry %q", env.Name)
		}
		if i > 0 && canonical.Environment[i-1].Name == env.Name {
			return nil, fmt.Errorf("lash: duplicate environment entry %q", env.Name)
		}
	}
	canonical.LogicalCredentials = append([]string(nil), plan.LogicalCredentials...)
	sort.Strings(canonical.LogicalCredentials)
	for i, id := range canonical.LogicalCredentials {
		if id == "" || strings.IndexByte(id, 0) >= 0 {
			return nil, errors.New("lash: logical credential identifiers must be non-empty")
		}
		if i > 0 && canonical.LogicalCredentials[i-1] == id {
			return nil, fmt.Errorf("lash: duplicate logical credential %q", id)
		}
	}
	return json.Marshal(canonical)
}

// PlanDigest returns the digest signed into the authorization binding.
func PlanDigest(plan ExecutionPlan) (string, error) {
	encoded, err := CanonicalPlan(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Seal signs one deterministic authorization and exact execution plan.
func Seal(auth Authorization, plan ExecutionPlan, signerID string, key ed25519.PrivateKey) (Binding, error) {
	if err := validateAuthorization(auth); err != nil {
		return Binding{}, err
	}
	if signerID == "" || len(key) != ed25519.PrivateKeySize {
		return Binding{}, errors.New("lash: signer identity and Ed25519 private key are required")
	}
	digest, err := PlanDigest(plan)
	if err != nil {
		return Binding{}, err
	}
	binding := Binding{Schema: BindingSchema, Authorization: auth, PlanDigest: digest, SignerID: signerID}
	payload, err := bindingPayload(binding)
	if err != nil {
		return Binding{}, err
	}
	binding.Signature = hex.EncodeToString(ed25519.Sign(key, payload))
	return binding, nil
}

// Verify proves that the signed authorization still names this exact plan.
func Verify(binding Binding, plan ExecutionPlan, now time.Time, key ed25519.PublicKey) error {
	if binding.Schema != BindingSchema || len(key) != ed25519.PublicKeySize {
		return errors.New("lash: invalid binding schema or verification key")
	}
	if err := validateAuthorization(binding.Authorization); err != nil {
		return err
	}
	if now.Before(binding.Authorization.IssuedAt) || !now.Before(binding.Authorization.ExpiresAt) {
		return errors.New("lash: authorization is not currently valid")
	}
	digest, err := PlanDigest(plan)
	if err != nil {
		return err
	}
	if digest != binding.PlanDigest {
		return errors.New("lash: execution plan differs from authorized plan")
	}
	signature, err := hex.DecodeString(binding.Signature)
	if err != nil {
		return errors.New("lash: invalid binding signature encoding")
	}
	payload, err := bindingPayload(binding)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, payload, signature) {
		return errors.New("lash: binding signature does not verify")
	}
	return nil
}

// BoundArtifact holds open the exact file description whose bytes were
// checked. A future Linux executor must execute from this descriptor (for
// example with execveat/AT_EMPTY_PATH); reopening the path would reintroduce
// the check/use substitution this type is designed to prevent.
type BoundArtifact struct {
	File   *os.File
	Digest string
}

func OpenBoundArtifact(path, expectedDigest string) (*BoundArtifact, error) {
	if !filepath.IsAbs(path) || !validSHA256(expectedDigest) {
		return nil, errors.New("lash: absolute artifact path and SHA-256 digest required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("lash: open artifact: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		file.Close()
		return nil, fmt.Errorf("lash: hash artifact: %w", err)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if digest != expectedDigest {
		file.Close()
		return nil, errors.New("lash: artifact bytes differ from authorized digest")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, fmt.Errorf("lash: rewind artifact: %w", err)
	}
	return &BoundArtifact{File: file, Digest: digest}, nil
}

func validateAuthorization(auth Authorization) error {
	if auth.DecisionID == "" || auth.DomainID == "" || auth.ContextID == "" || auth.Action == "" || !validSHA256(auth.PolicyDigest) {
		return errors.New("lash: incomplete deterministic authorization")
	}
	if auth.Decision != canonical.Allow {
		return errors.New("lash: only a deterministic allow can authorize execution")
	}
	if auth.IssuedAt.IsZero() || !auth.ExpiresAt.After(auth.IssuedAt) {
		return errors.New("lash: invalid authorization lifetime")
	}
	return nil
}

func bindingPayload(binding Binding) ([]byte, error) {
	binding.Signature = ""
	return json.Marshal(binding)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
