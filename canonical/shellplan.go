package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ShellPlanParserVersion is part of the decision provenance. Parser upgrades
// must change this value so stored decisions never imply semantic parity across
// parser generations.
const ShellPlanParserVersion = "mvdan.cc/sh/v3@v3.10.0/bash"

// SourceSpan identifies the exact byte range occupied by an invocation.
type SourceSpan struct {
	Start uint
	End   uint
}

// ShellInvocation is one statically identified simple command. Arguments are
// literal shell values, not source spellings; quoted data remains an argument
// of its actual executable and cannot manufacture another invocation.
type ShellInvocation struct {
	ID               string
	Executable       string
	Arguments        []string
	ArgumentLiterals []bool
	Source           string
	Span             SourceSpan
}

// OpaqueShellInvocation records a simple command whose executable is dynamic.
// Its literal arguments remain available for conservative rule evaluation, but
// it can never produce parsed executable provenance.
type OpaqueShellInvocation struct {
	Arguments        []string
	ArgumentLiterals []bool
	Source           string
	Span             SourceSpan
}

// ShellHeredoc binds a here-document to its exact parsed redirection. Multiple
// redirections may share a source line but have different execution semantics.
type ShellHeredoc struct {
	OperatorOffset uint
	Line           uint
	Delimiter      string
	Executable     bool
}

// ShellPlan is the versioned, non-executing interpretation used by Bash rules.
type ShellPlan struct {
	SourceDigest      string
	ParserVersion     string
	Invocations       []ShellInvocation
	OpaqueInvocations []OpaqueShellInvocation
	Heredocs          []ShellHeredoc
}

// ParseShellPlan parses Bash source without expansion or execution. A command
// whose executable cannot be reduced to a literal is omitted; callers retain
// the legacy policy path for that unsupported case during shadow rollout.
func ParseShellPlan(source string) (ShellPlan, error) {
	sum := sha256.Sum256([]byte(source))
	plan := ShellPlan{
		SourceDigest:  hex.EncodeToString(sum[:]),
		ParserVersion: ShellPlanParserVersion,
	}

	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "gatekeeper-input")
	if err != nil {
		return plan, fmt.Errorf("parse shell plan: %w", err)
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, ok := node.(*syntax.Stmt); ok {
			collectExecutableHeredocs(&plan, stmt)
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		executable, ok := literalWord(call.Args[0])
		if !ok {
			arguments := make([]string, len(call.Args)-1)
			argumentLiterals := make([]bool, len(call.Args)-1)
			for i, word := range call.Args[1:] {
				arguments[i], argumentLiterals[i] = literalWord(word)
			}
			start, end := call.Pos().Offset(), call.End().Offset()
			if start <= uint(len(source)) && end <= uint(len(source)) && end >= start {
				plan.OpaqueInvocations = append(plan.OpaqueInvocations, OpaqueShellInvocation{
					Arguments:        arguments,
					ArgumentLiterals: argumentLiterals,
					Source:           source[start:end],
					Span:             SourceSpan{Start: start, End: end},
				})
			}
			return true
		}
		arguments := make([]string, len(call.Args)-1)
		argumentLiterals := make([]bool, len(call.Args)-1)
		for i, word := range call.Args[1:] {
			arguments[i], argumentLiterals[i] = literalWord(word)
		}
		start, end := call.Pos().Offset(), call.End().Offset()
		if start > uint(len(source)) || end > uint(len(source)) || end < start {
			return true
		}
		plan.Invocations = append(plan.Invocations, ShellInvocation{
			ID:               fmt.Sprintf("invocation-%d", len(plan.Invocations)+1),
			Executable:       filepath.Base(executable),
			Arguments:        arguments,
			ArgumentLiterals: argumentLiterals,
			Source:           source[start:end],
			Span:             SourceSpan{Start: start, End: end},
		})
		appendWrappedInvocations(&plan, source[start:end], SourceSpan{Start: start, End: end}, executable, arguments, argumentLiterals)
		return true
	})
	sort.Slice(plan.Heredocs, func(i, j int) bool {
		return plan.Heredocs[i].OperatorOffset < plan.Heredocs[j].OperatorOffset
	})
	return plan, nil
}

func collectExecutableHeredocs(plan *ShellPlan, stmt *syntax.Stmt) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	executable, ok := literalWord(call.Args[0])
	if !ok {
		return
	}
	arguments := make([]string, len(call.Args)-1)
	literals := make([]bool, len(call.Args)-1)
	for i, word := range call.Args[1:] {
		arguments[i], literals[i] = literalWord(word)
	}
	for depth := 0; depth < 8; depth++ {
		innerExecutable, innerArguments, innerLiterals, unwrapped := unwrapLiteralWrapper(executable, arguments, literals)
		if !unwrapped {
			break
		}
		executable, arguments, literals = innerExecutable, innerArguments, innerLiterals
	}
	// Executable is the historical field name for the conservative body-retention
	// bit. Preserve the body unless the resolved consumer is proved to consume
	// data: unknown wrappers and executables must not turn code into an inert
	// mention merely because ShellPlan cannot classify them yet.
	executableHeredoc := !isProvedDataHeredocConsumer(filepath.Base(executable))
	for _, redirect := range stmt.Redirs {
		if redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc {
			continue
		}
		delimiter, literal := literalWord(redirect.Word)
		if !literal || delimiter == "" {
			continue
		}
		plan.Heredocs = append(plan.Heredocs, ShellHeredoc{
			OperatorOffset: redirect.OpPos.Offset(),
			Line:           redirect.OpPos.Line(),
			Delimiter:      delimiter,
			Executable:     executableHeredoc,
		})
	}
}

func isProvedDataHeredocConsumer(executable string) bool {
	switch executable {
	case "cat":
		return true
	default:
		return false
	}
}

func appendWrappedInvocations(plan *ShellPlan, source string, span SourceSpan, executable string, arguments []string, literals []bool) {
	for depth := 0; depth < 8; depth++ {
		innerExecutable, innerArguments, innerLiterals, ok := unwrapLiteralWrapper(executable, arguments, literals)
		if !ok {
			return
		}
		plan.Invocations = append(plan.Invocations, ShellInvocation{
			ID:               fmt.Sprintf("invocation-%d", len(plan.Invocations)+1),
			Executable:       filepath.Base(innerExecutable),
			Arguments:        append([]string(nil), innerArguments...),
			ArgumentLiterals: append([]bool(nil), innerLiterals...),
			Source:           source,
			Span:             span,
		})
		executable, arguments, literals = filepath.Base(innerExecutable), innerArguments, innerLiterals
	}
}

// unwrapLiteralWrapper is deliberately closed: each admitted wrapper has a
// reviewed argv contract. Unknown wrappers and dynamic payloads are not guessed.
func unwrapLiteralWrapper(executable string, arguments []string, literals []bool) (string, []string, []bool, bool) {
	commandAt := -1
	switch filepath.Base(executable) {
	case "command", "nohup":
		for i, argument := range arguments {
			if !literals[i] {
				return "", nil, nil, false
			}
			if argument == "--" {
				commandAt = i + 1
				break
			}
			if !strings.HasPrefix(argument, "-") {
				commandAt = i
				break
			}
		}
	case "nice":
		for i := 0; i < len(arguments); i++ {
			if !literals[i] {
				return "", nil, nil, false
			}
			argument := arguments[i]
			if argument == "--" {
				commandAt = i + 1
				break
			}
			if argument == "-n" || argument == "--adjustment" {
				if i+1 >= len(arguments) || !literals[i+1] {
					return "", nil, nil, false
				}
				i++
				continue
			}
			if strings.HasPrefix(argument, "--adjustment=") {
				continue
			}
			if isNiceNumericAdjustment(argument) {
				continue
			}
			if isNiceAttachedAdjustment(argument) {
				continue
			}
			if strings.HasPrefix(argument, "-") {
				return "", nil, nil, false
			}
			commandAt = i
			break
		}
	case "env":
		for i := 0; i < len(arguments); i++ {
			if !literals[i] {
				return "", nil, nil, false
			}
			argument := arguments[i]
			if argument == "--" {
				commandAt = i + 1
				break
			}
			if argument == "-S" || argument == "--split-string" {
				return "", nil, nil, false
			}
			if argument == "-u" || argument == "--unset" || argument == "-C" || argument == "--chdir" {
				i++
				continue
			}
			if strings.HasPrefix(argument, "-") || strings.Contains(argument, "=") {
				continue
			}
			commandAt = i
			break
		}
	case "timeout":
		seenDuration := false
		for i := 0; i < len(arguments); i++ {
			if !literals[i] {
				return "", nil, nil, false
			}
			argument := arguments[i]
			if !seenDuration {
				if argument == "--" {
					continue
				}
				if argument == "-s" || argument == "--signal" || argument == "-k" || argument == "--kill-after" {
					i++
					continue
				}
				if strings.HasPrefix(argument, "-") {
					continue
				}
				seenDuration = true
				continue
			}
			commandAt = i
			break
		}
	default:
		return "", nil, nil, false
	}
	if commandAt < 0 || commandAt >= len(arguments) || !literals[commandAt] || arguments[commandAt] == "" {
		return "", nil, nil, false
	}
	return arguments[commandAt], arguments[commandAt+1:], literals[commandAt+1:], true
}

func isNiceNumericAdjustment(argument string) bool {
	if len(argument) < 2 || argument[0] != '-' {
		return false
	}
	for _, r := range argument[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isNiceAttachedAdjustment(argument string) bool {
	if !strings.HasPrefix(argument, "-n") || len(argument) <= len("-n") {
		return false
	}
	value := argument[len("-n"):]
	if value[0] == '-' || value[0] == '+' {
		value = value[1:]
	}
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func literalWord(word *syntax.Word) (string, bool) {
	var value strings.Builder
	var appendParts func([]syntax.WordPart) bool
	appendParts = func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				value.WriteString(part.Value)
			case *syntax.SglQuoted:
				if part.Dollar {
					return false
				}
				value.WriteString(part.Value)
			case *syntax.DblQuoted:
				if part.Dollar || !appendParts(part.Parts) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if !appendParts(word.Parts) {
		return "", false
	}
	return value.String(), true
}
