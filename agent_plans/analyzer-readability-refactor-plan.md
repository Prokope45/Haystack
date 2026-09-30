# Analyzer Readability Refactor Plan

## Goals

- Make both language analyzers easier to navigate without changing findings or analysis behavior.
- Separate orchestration, scope analysis, interprocedural interpretation, and evidence handling into cohesive named responsibilities.
- Preserve existing language-specific source/sink rules, taint semantics, directive behavior, limits, and bridge protocol.
- Avoid speculative abstractions, a shared cross-language taint engine, and algorithm rewrites.

## Implementation Phases

### 1. Characterize existing behavior

- Run `go test ./internal/analyzer/... ./internal/flow ./internal/index ./internal/scanner` before edits.
- Preserve current direct and interprocedural flow, safe-input, depth-limit, unrelated-call, hardcoded-secret, deduplication, and evidence-selection behavior.
- Add focused regression coverage for directive-driven skipping and metadata, plus Python syntax-error and bridge-output handling where not already covered.
- Treat characterization findings as behavior to preserve during this refactor; separate any discovered behavior changes from this work.

### 2. Clarify Go analyzer orchestration

- Refactor `internal/analyzer/golang/analyzer.go` so `Analyze` coordinates parsing, per-function analysis, interprocedural analysis, and evidence merging.
- Extract named helpers for directive selection, analyzing one function body, and merging duplicate flows.
- Encapsulate per-function tracker/evidence state where doing so reduces parameter passing and improves ownership.
- Keep the signatures of `MatchSource` and `MatchSink` stable because the index builder also calls them.

### 3. Decompose Go interprocedural analysis

- Keep interpreter state and resource limits together.
- Separate source-root discovery, call resolution, statement processing, expression evaluation, argument mapping, and evidence construction into clearly named responsibilities.
- Split `interprocedural.go` into focused same-package files only along cohesive boundaries.
- Preserve same-file resolution, recursion and invocation limits, cancellation, flow caps, and evidence selection.

### 4. Clarify Python adapter and embedded bridge

- In `internal/analyzer/python/analyzer.go`, separate directive/depth decisions, subprocess execution, result decoding, and metadata application without changing invocation or error behavior.
- Keep `bridge.py` self-contained because it is embedded and executed through `python -c`.
- Replace deeply nested interprocedural closures with a small analyzer object that owns existing state and provides named methods for root discovery, expression evaluation, argument mapping, assignment, block processing, invocation, and evidence emission.
- Decompose local scope analysis into named assignment, secret-detection, and sink-flow steps where that improves navigation.
- Preserve Python-specific source/sink coverage, root heuristics, traversal, and evidence identity.

### 5. Verify

- Run focused analyzer tests after each language refactor.
- Run `go test ./internal/analyzer/... ./internal/flow ./internal/index ./internal/scanner` and `go test ./...`.
- Run `go vet ./...` and `golangci-lint run ./...` when available.
- Ensure Python analyzer tests execute with `python3` available; those tests skip when Python is absent.

## Guardrails

- Do not introduce a shared cross-language taint engine; the language implementations have intentionally different AST handling, rules, roots, directives, and limits.
- Do not change source/sink semantics, directive matching, evidence identity/preference, JSON fields, the embedded bridge protocol, or error semantics.
- Prefer cohesive helpers and state-owning interpreter structures over generic frameworks or pattern abstractions that add indirection without improving readability.
