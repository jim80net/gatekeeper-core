package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/jim80net/gatekeeper-core/canonical"
)

// CompiledRule is the admitted form of a rule. Engine construction consumes
// this type so it cannot reinterpret or partially duplicate config validity.
type CompiledRule struct {
	ToolRegex         *regexp2.Regexp
	InputRegex        *regexp2.Regexp
	PreconditionCmd   string
	PreconditionRegex *regexp2.Regexp
	Decision          canonical.Decision
	Reason            string
	Provenance        canonical.RuleProvenance
}

// Validate checks and compiles every configuration rule. It is the sole
// semantic authority for config admission.
func (c *Config) Validate() error {
	_, err := c.CompiledRules()
	return err
}

// CompiledRules validates the complete config and returns its admitted,
// compiled rules. It reports all semantic problems in one pass and returns no
// partial rule set on error.
func (c *Config) CompiledRules() ([]CompiledRule, error) {
	if c == nil {
		return nil, errors.New("config is nil")
	}

	var problems []error
	if c.OnError != "" && c.OnError != OnErrorAbstain && c.OnError != OnErrorDeny {
		problems = append(problems, fmt.Errorf("on_error must be %q or %q, got %q", OnErrorAbstain, OnErrorDeny, c.OnError))
	}

	compiled := make([]CompiledRule, 0, len(c.Rules))
	for i, rule := range c.Rules {
		label := fmt.Sprintf("rule %d", i+1)
		var ruleInvalid bool

		var toolRegex *regexp2.Regexp
		if strings.TrimSpace(rule.Tool) == "" {
			problems = append(problems, fmt.Errorf("%s: tool is required", label))
			ruleInvalid = true
		} else if re, err := regexp2.Compile(rule.Tool, regexp2.None); err != nil {
			problems = append(problems, fmt.Errorf("%s: invalid tool regex: %w", label, err))
			ruleInvalid = true
		} else {
			toolRegex = re
		}

		var inputRegex *regexp2.Regexp
		if strings.TrimSpace(rule.Input) == "" {
			problems = append(problems, fmt.Errorf("%s: input is required", label))
			ruleInvalid = true
		} else if re, err := regexp2.Compile(rule.Input, regexp2.None); err != nil {
			problems = append(problems, fmt.Errorf("%s: invalid input regex: %w", label, err))
			ruleInvalid = true
		} else {
			inputRegex = re
		}

		var decision canonical.Decision
		switch rule.Decision {
		case "allow":
			decision = canonical.Allow
		case "deny":
			decision = canonical.Deny
		default:
			problems = append(problems, fmt.Errorf("%s: decision must be %q or %q, got %q", label, "allow", "deny", rule.Decision))
			ruleInvalid = true
		}

		pairedPrecondition := (rule.Precondition == "") == (rule.PreconditionMatch == "")
		if !pairedPrecondition {
			problems = append(problems, fmt.Errorf("%s: precondition and precondition_match must be set together", label))
			ruleInvalid = true
		}

		var preconditionRegex *regexp2.Regexp
		if rule.PreconditionMatch != "" {
			re, err := regexp2.Compile(rule.PreconditionMatch, regexp2.None)
			if err != nil {
				problems = append(problems, fmt.Errorf("%s: invalid precondition_match regex: %w", label, err))
				ruleInvalid = true
			} else {
				preconditionRegex = re
			}
		}

		if !ruleInvalid {
			compiled = append(compiled, CompiledRule{
				ToolRegex:         toolRegex,
				InputRegex:        inputRegex,
				PreconditionCmd:   rule.Precondition,
				PreconditionRegex: preconditionRegex,
				Decision:          decision,
				Reason:            rule.Reason,
				Provenance: canonical.RuleProvenance{
					Source: rule.Source,
					Index:  rule.SourceIndex,
				},
			})
		}
	}

	if err := errors.Join(problems...); err != nil {
		return nil, err
	}
	return compiled, nil
}
