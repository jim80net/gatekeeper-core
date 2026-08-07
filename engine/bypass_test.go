package engine_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
	"github.com/jim80net/gatekeeper-core/engine"
)

// defaultEngine loads the shipped gatekeeper.toml and stubs the precondition
// executor to report the given current branch (for the bare-`git push` rule).
func defaultEngine(t *testing.T, currentBranch string) *engine.Engine {
	t.Helper()
	eng, _ := defaultEngineWithConfig(t, currentBranch)
	return eng
}

func defaultEngineWithConfig(t *testing.T, currentBranch string) (*engine.Engine, *config.Config) {
	t.Helper()
	cfg, err := config.LoadFile("../gatekeeper.toml")
	if err != nil {
		t.Fatalf("LoadFile(gatekeeper.toml): %v", err)
	}
	eng, err := engine.New(cfg, false)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	eng.SetExecCommand(func(ctx context.Context, cwd, command, toolInput string) (string, error) {
		return currentBranch + "\n", nil
	})
	return eng, cfg
}

// TestPushToMainBypassClasses asserts the shipped push-to-main rules deny every
// bypass class the fleet's glob deny-list misses (design §2.4, §7). These are
// the regression fixtures that justify the boundary regex over glob enumeration.
func TestPushToMainBypassClasses(t *testing.T) {
	// On a feature branch so the bare-push precondition rule does NOT fire;
	// every deny here comes from the EXPLICIT-main boundary rule.
	eng := defaultEngine(t, "feature-branch")

	denied := []string{
		"git push origin main",
		"git push origin master",
		"git push -u origin main",
		"git push -u origin master", // master parity
		"git push --quiet origin main",
		"git push origin HEAD:main",
		"git push origin HEAD:master", // master parity
		"git push origin main:main",
		"git push origin :main",              // branch delete via colon refspec
		"git push origin +main",              // force refspec
		"git push origin refs/heads/main",    // fully-qualified ref
		"git push origin refs/heads/master",  // fully-qualified master
		"FOO=bar git push origin main",       // env-prefix
		"git -C /some/repo push origin main", // -C path form
	}
	for _, cmd := range denied {
		t.Run("deny/"+cmd, func(t *testing.T) {
			v, err := eng.Evaluate(bashInput(cmd))
			if err != nil {
				t.Fatal(err)
			}
			if v.Decision != canonical.Deny {
				t.Errorf("expected DENY for %q, got %s (%s)", cmd, v.Decision, v.Reason)
			}
		})
	}
}

// TestPushToMainFalsePositiveGuards asserts branches whose name merely CONTAINS
// "main"/"master" are NOT denied (the (?=\s|$|:) boundary), so real work isn't
// blocked.
func TestPushToMainFalsePositiveGuards(t *testing.T) {
	eng := defaultEngine(t, "feature-branch")

	allowed := []string{
		"git push origin feature-branch",
		"git push origin main-feature", // branch literally named main-feature
		"git push origin main-branch",  // branch literally named main-branch
		"git push origin mainline",
		"git push origin feature/main-thing",
		"git push origin maintenance",
		"git push origin feature/main",            // ref ENDING in /main but not refs/heads/main
		"git push origin refs/heads/feature/main", // fully-qualified feature ref
		"git status",                      // non-push git command must not trip the push rule
		"git commit -m 'promote to main'", // 'main' in a commit message must not trip it
	}
	for _, cmd := range allowed {
		t.Run("allow/"+cmd, func(t *testing.T) {
			v, err := eng.Evaluate(bashInput(cmd))
			if err != nil {
				t.Fatal(err)
			}
			if v.Decision == canonical.Deny {
				t.Errorf("expected NOT-deny for %q, got DENY (%s)", cmd, v.Reason)
			}
		})
	}
}

// TestForcePushFlagPositionBypassesDenied locks the shipped template against
// the older rule that matched force flags only immediately after `git push`.
// The branch precondition is explicitly modelled as a feature worktree so an
// overlapping protected-branch deny cannot hide a weak force-push backstop.
func TestForcePushFlagPositionBypassesDenied(t *testing.T) {
	eng, cfg := defaultEngineWithConfig(t, "feature-branch")
	forceRule := canonical.RuleProvenance{}
	for _, rule := range cfg.Rules {
		if rule.Reason == "Destructive: git force push" {
			forceRule = canonical.RuleProvenance{Source: rule.Source, Index: rule.SourceIndex}
			break
		}
	}
	if forceRule.Index == 0 {
		t.Fatal("shipped template has no force-push rule provenance")
	}
	denied := []string{
		"git push --force",
		"git push -f",
		"git push --force-with-lease=origin/main",
		"git push origin main --force",
		"git push origin main -f",
		"git push -u origin feature -f",
		"cd /tmp && git push origin main --force",
	}
	for _, cmd := range denied {
		t.Run(cmd, func(t *testing.T) {
			verdict, err := eng.Evaluate(bashInput(cmd))
			if err != nil {
				t.Fatal(err)
			}
			if verdict.Decision != canonical.Deny {
				t.Fatalf("force-push bypass was not denied: decision=%s reason=%q", verdict.Decision, verdict.Reason)
			}
			if !strings.Contains(verdict.Reason, "Destructive: git force push") {
				t.Fatalf("force-push backstop did not carry the deny: reason=%q", verdict.Reason)
			}
			matchedForceRule := false
			for _, provenance := range verdict.Rules {
				if provenance == forceRule {
					matchedForceRule = true
					break
				}
			}
			if !matchedForceRule {
				t.Fatalf("deny came from overlapping policy but not force-push rule: rules=%#v", verdict.Rules)
			}
		})
	}
}

// TestBarePushOnMainDenied covers the implicit rule: a bare `git push` while the
// current branch IS main/master is denied via the precondition; on a feature
// branch it is allowed.
func TestBarePushOnMainDenied(t *testing.T) {
	t.Run("on main -> deny", func(t *testing.T) {
		eng := defaultEngine(t, "main")
		v, err := eng.Evaluate(bashInput("git push"))
		if err != nil {
			t.Fatal(err)
		}
		if v.Decision != canonical.Deny {
			t.Errorf("bare push on main: got %s, want deny", v.Decision)
		}
	})
	t.Run("on feature -> allow", func(t *testing.T) {
		eng := defaultEngine(t, "feature-branch")
		v, err := eng.Evaluate(bashInput("git push"))
		if err != nil {
			t.Fatal(err)
		}
		if v.Decision != canonical.Allow {
			t.Errorf("bare push on feature: got %s, want allow", v.Decision)
		}
	})
}
