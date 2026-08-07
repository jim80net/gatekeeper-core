package lash

import (
	"testing"
	"time"

	"github.com/jim80net/gatekeeper-core/canonical"
)

func TestClassifierCannotLoosenDeterministicDeny(t *testing.T) {
	guard := NarrowingGuard{MaxNarrowings: 2, Window: time.Minute}
	got := guard.Resolve(time.Now(), "domain", "classifier-v1", digest("plan"), canonical.Deny, AdviceNoNarrowing)
	if got != EffectiveDeny {
		t.Fatalf("classifier loosened deterministic deny: %s", got)
	}
}

func TestSustainedClassifierDisagreementFallsBackVisibly(t *testing.T) {
	var observations []ClassifierObservation
	guard := NarrowingGuard{
		MaxNarrowings: 2, Window: time.Minute,
		Observe: func(observation ClassifierObservation) { observations = append(observations, observation) },
	}
	now := time.Unix(1_800_000_000, 0)
	for i, want := range []EffectiveDecision{EffectiveDeny, EffectiveDeny, EffectiveAllow} {
		got := guard.Resolve(now.Add(time.Duration(i)*time.Second), "domain/seat", "classifier-v1", digest("plan"), canonical.Allow, AdviceNarrow)
		if got != want {
			t.Fatalf("decision %d: got %s, want %s", i, got, want)
		}
	}
	if len(observations) != 3 || observations[2].Reason != "classifier_narrowing_rate_limited" || observations[2].NarrowingsInWindow != 3 {
		t.Fatalf("availability fallback was not observable: %#v", observations)
	}

	got := guard.Resolve(now.Add(2*time.Minute), "domain/seat", "classifier-v1", digest("plan"), canonical.Allow, AdviceNarrow)
	if got != EffectiveDeny {
		t.Fatalf("new window did not re-arm bounded narrowing: %s", got)
	}
}

func TestSustainedUnknownCannotBlockDeterministicAllowForever(t *testing.T) {
	guard := NarrowingGuard{MaxNarrowings: 1, Window: time.Minute, Observe: func(ClassifierObservation) {}}
	now := time.Unix(1_800_000_000, 0)
	if got := guard.Resolve(now, "domain/seat", "classifier-v1", digest("plan"), canonical.Allow, AdviceUnknown); got != EffectiveReview {
		t.Fatalf("first unknown did not request review: %s", got)
	}
	if got := guard.Resolve(now.Add(time.Second), "domain/seat", "classifier-v1", digest("plan"), canonical.Allow, AdviceUnknown); got != EffectiveAllow {
		t.Fatalf("sustained unknown did not fall back to deterministic allow: %s", got)
	}
}

func TestInvalidAvailabilityGuardCannotCreateDenial(t *testing.T) {
	guard := NarrowingGuard{MaxNarrowings: 10, Observe: func(ClassifierObservation) {}}
	got := guard.Resolve(time.Now(), "domain/seat", "classifier-v1", digest("plan"), canonical.Allow, AdviceNarrow)
	if got != EffectiveAllow {
		t.Fatalf("invalid guard created classifier denial: %s", got)
	}
}

func TestUnavailableObserverDisarmsClassifierNarrowing(t *testing.T) {
	guard := NarrowingGuard{MaxNarrowings: 10, Window: time.Minute}
	got := guard.Resolve(time.Now(), "domain/seat", "classifier-v1", digest("plan"), canonical.Allow, AdviceNarrow)
	if got != EffectiveAllow {
		t.Fatalf("unobservable classifier narrowing changed deterministic allow: %s", got)
	}
}

func TestZeroSpendBudgetRejectsPaidCallsBeforeReservation(t *testing.T) {
	budget := ClassifierBudget{MaxCalls: 2, MaxInputTokens: 100, MaxOutputTokens: 20, MaxCostMicros: 0}
	if err := budget.Reserve(ClassifierEstimate{InputTokens: 10, OutputTokens: 2, CostMicros: 1}); err == nil {
		t.Fatal("paid classifier call passed zero-spend budget")
	}
	if got := budget.Usage(); got.Calls != 0 {
		t.Fatalf("rejected call consumed budget: %#v", got)
	}
	if err := budget.Reserve(ClassifierEstimate{InputTokens: 10, OutputTokens: 2}); err != nil {
		t.Fatalf("zero-cost local classifier rejected: %v", err)
	}
	if err := budget.Reserve(ClassifierEstimate{InputTokens: 90, OutputTokens: 18}); err != nil {
		t.Fatalf("exact remaining budget rejected: %v", err)
	}
	if err := budget.Reserve(ClassifierEstimate{}); err == nil {
		t.Fatal("call-count overflow passed budget")
	}
}
