package lash

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jim80net/gatekeeper-core/canonical"
)

// Advice is an untrusted classifier result. It is deliberately unable to
// express an authoritative allow.
type Advice string

const (
	AdviceNoNarrowing Advice = "no_narrowing"
	AdviceNarrow      Advice = "narrow"
	AdviceUnknown     Advice = "unknown"
)

type EffectiveDecision string

const (
	EffectiveAllow  EffectiveDecision = "allow"
	EffectiveDeny   EffectiveDecision = "deny"
	EffectiveReview EffectiveDecision = "human_review"
)

// ClassifierObservation is emitted for every advisory result. PlanDigest is
// non-secret correlation material; raw commands and model prompts are excluded.
type ClassifierObservation struct {
	At                    time.Time
	Scope                 string
	ClassifierVersion     string
	PlanDigest            string
	DeterministicDecision canonical.Decision
	Advice                Advice
	Effective             EffectiveDecision
	Reason                string
	NarrowingsInWindow    uint32
}

type ObserveClassifier func(ClassifierObservation)

// NarrowingGuard bounds classifier-created denial outages. A deterministic
// deny is never loosened. When a deterministic allow and classifier narrowing
// disagree too often in a scope, further narrowing is bypassed until the next
// window and the deterministic allow wins visibly.
type NarrowingGuard struct {
	MaxNarrowings uint32
	Window        time.Duration
	Observe       ObserveClassifier

	mu     sync.Mutex
	scopes map[string]narrowingWindow
}

type narrowingWindow struct {
	started time.Time
	count   uint32
}

func (g *NarrowingGuard) Resolve(at time.Time, scope, classifierVersion, planDigest string, deterministic canonical.Decision, advice Advice) EffectiveDecision {
	result := EffectiveReview
	reason := "classifier_unknown_requires_review"
	count := uint32(0)

	if deterministic == canonical.Deny {
		result = EffectiveDeny
		reason = "deterministic_deny"
	} else if deterministic != canonical.Allow {
		result = EffectiveReview
		reason = "deterministic_abstain_requires_review"
	} else {
		switch advice {
		case AdviceNoNarrowing:
			result = EffectiveAllow
			reason = "deterministic_allow"
		case AdviceNarrow:
			if g.Observe == nil {
				result = EffectiveAllow
				reason = "classifier_observer_unavailable"
			} else {
				count, result, reason = g.applyNarrowing(at, scope, EffectiveDeny, "classifier_narrowed_deterministic_allow")
			}
		default:
			if g.Observe == nil {
				result = EffectiveAllow
				reason = "classifier_observer_unavailable"
			} else {
				count, result, reason = g.applyNarrowing(at, scope, EffectiveReview, "classifier_unknown_requires_review")
			}
		}
	}

	if g.Observe != nil {
		g.Observe(ClassifierObservation{
			At: at, Scope: scope, ClassifierVersion: classifierVersion,
			PlanDigest: planDigest, DeterministicDecision: deterministic,
			Advice: advice, Effective: result, Reason: reason,
			NarrowingsInWindow: count,
		})
	}
	return result
}

func (g *NarrowingGuard) applyNarrowing(at time.Time, scope string, narrowed EffectiveDecision, narrowedReason string) (uint32, EffectiveDecision, string) {
	if g.Window <= 0 || scope == "" {
		return 0, EffectiveAllow, "classifier_narrowing_guard_invalid"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.scopes == nil {
		g.scopes = make(map[string]narrowingWindow)
	}
	window := g.scopes[scope]
	if window.started.IsZero() || at.Sub(window.started) >= g.Window || at.Before(window.started) {
		window = narrowingWindow{started: at}
	}
	window.count++
	g.scopes[scope] = window
	if g.MaxNarrowings == 0 || window.count > g.MaxNarrowings {
		return window.count, EffectiveAllow, "classifier_narrowing_rate_limited"
	}
	return window.count, narrowed, narrowedReason
}

// ClassifierEstimate reserves capacity before a classifier call. CostMicros is
// provider-estimated spend in millionths of the configured currency unit.
type ClassifierEstimate struct {
	InputTokens  uint64
	OutputTokens uint64
	CostMicros   uint64
}

// ClassifierBudget makes trigger rate and spend explicit. A zero CostMicros
// limit is a hard no-spend policy: only estimates with zero external cost pass.
type ClassifierBudget struct {
	MaxCalls        uint64
	MaxInputTokens  uint64
	MaxOutputTokens uint64
	MaxCostMicros   uint64

	mu           sync.Mutex
	calls        uint64
	inputTokens  uint64
	outputTokens uint64
	costMicros   uint64
}

type ClassifierUsage struct {
	Calls        uint64
	InputTokens  uint64
	OutputTokens uint64
	CostMicros   uint64
}

// Reserve fails before a call when its estimated usage would cross a limit.
func (b *ClassifierBudget) Reserve(estimate ClassifierEstimate) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.MaxCalls == 0 {
		return errors.New("lash: classifier calls disabled by budget")
	}
	if estimate.CostMicros > 0 && b.MaxCostMicros == 0 {
		return errors.New("lash: paid classifier call denied by zero-spend budget")
	}
	if exceeds(b.calls, 1, b.MaxCalls) ||
		exceeds(b.inputTokens, estimate.InputTokens, b.MaxInputTokens) ||
		exceeds(b.outputTokens, estimate.OutputTokens, b.MaxOutputTokens) ||
		exceeds(b.costMicros, estimate.CostMicros, b.MaxCostMicros) {
		return fmt.Errorf("lash: classifier estimate exceeds configured budget")
	}
	b.calls++
	b.inputTokens += estimate.InputTokens
	b.outputTokens += estimate.OutputTokens
	b.costMicros += estimate.CostMicros
	return nil
}

func (b *ClassifierBudget) Usage() ClassifierUsage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return ClassifierUsage{Calls: b.calls, InputTokens: b.inputTokens, OutputTokens: b.outputTokens, CostMicros: b.costMicros}
}

func exceeds(current, addition, limit uint64) bool {
	return addition > limit || current > limit-addition
}
