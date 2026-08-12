package canonical_test

import (
	"testing"

	"github.com/jim80net/gatekeeper-core/canonical"
)

func TestParseShellPlanSeparatesInvocationsFromMentions(t *testing.T) {
	plan, err := canonical.ParseShellPlan(`echo '{"command":"rm -rf /path"}' && rm -rf /actual`)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Invocations) != 2 {
		t.Fatalf("invocations = %d, want 2: %#v", len(plan.Invocations), plan.Invocations)
	}
	if plan.Invocations[0].Executable != "echo" || plan.Invocations[1].Executable != "rm" {
		t.Fatalf("executables = %q, %q, want echo, rm", plan.Invocations[0].Executable, plan.Invocations[1].Executable)
	}
	if plan.ParserVersion != canonical.ShellPlanParserVersion || len(plan.SourceDigest) != 64 {
		t.Fatalf("provenance = version %q digest %q", plan.ParserVersion, plan.SourceDigest)
	}
}

func TestParseShellPlanFindsCommandSubstitutionInvocation(t *testing.T) {
	plan, err := canonical.ParseShellPlan(`echo "$(rm -rf /actual)"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Invocations) != 2 || plan.Invocations[1].Executable != "rm" {
		t.Fatalf("invocations = %#v, want outer echo and nested rm", plan.Invocations)
	}
}

func TestParseShellPlanUnwrapsClosedLiteralWrappers(t *testing.T) {
	plan, err := canonical.ParseShellPlan(`env FOO=bar timeout 5 nohup rm -rf /actual`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"env", "timeout", "nohup", "rm"}
	if len(plan.Invocations) != len(want) {
		t.Fatalf("invocations = %#v, want %v", plan.Invocations, want)
	}
	for i := range want {
		if plan.Invocations[i].Executable != want[i] {
			t.Fatalf("invocation %d executable = %q, want %q", i, plan.Invocations[i].Executable, want[i])
		}
	}
}
