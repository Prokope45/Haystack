# Codebase Refactoring Plan

## Goals

- Reduce complexity without changing scanner behavior.
- Preserve existing test purposes and assertions.
- Preserve public-in-practice APIs, JSON fields, candidate IDs, cache identities, output formats, and error semantics.
- Improve package responsibility boundaries incrementally.
- Organize declarations into focused, named files within each package.
- Avoid speculative abstractions and premature package moves.

## File Organization Standard

Use focused files within the existing package boundaries:

- `interface.go`: interfaces and behavioral contracts.
- `constants.go`: package constants and fixed values.
- `enums.go`: named enum-like types and their values.
- `models.go`: cohesive data structures.
- `options.go`: constructor and service options.
- `errors.go`: sentinel and typed errors.
- Implementation files: one service, component, rule, formatter, or workflow.

Do not split tightly coupled declarations into artificial files. Keep test-only helpers in `_test.go` files, preserve same-package test access, and do not change exported names, JSON tags, package names, or visibility merely to reorganize files. Prefer focused files of roughly 200–300 lines where that improves navigation, without enforcing an arbitrary line limit.

## Implementation Phases

### 1. Characterization and baseline

Preserve and strengthen coverage for scanner request precedence, discovery behavior, candidate IDs, directive matching, planner budgets and fallback, findings and fingerprints, cache states, parser errors, CLI exit codes, MCP responses, and text/JSON/SARIF output.

Verify with:

```bash
go test ./...
go vet ./...
go test -race ./...
```

### 2. Declaration organization

Split mixed declaration files while keeping package paths and behavior unchanged. Initial targets include `internal/analyzer`, `internal/findings`, `internal/planning`, `internal/output`, `internal/index`, `internal/mcp`, `internal/config`, `internal/ai`, and `internal/scanner`.

Move declarations mechanically, run `gofmt`, and test after each package. Test changes should be limited to imports, package declarations, or required test setup.

### 3. Scanner decomposition

Keep `NewScanner`, `NewScannerWithCache`, `Scanner.Scan`, `Scanner.ScanCode`, `Scanner.ScanFile`, and `Scanner.GetAnalysisPlan` unchanged. Extract private stages for discovery, loading, indexing, candidate discovery, planning, directive construction, analysis execution, normalization, diff filtering, cache policy, and telemetry. Preserve the existing differences between repository and in-memory scan summaries and fallback behavior.

### 4. Invocation-local analyzer directives

Remove shared mutable directive state from concurrent scan execution by passing directives through an invocation or creating per-scan analyzer instances. Preserve analyzer evidence and matching behavior initially, then add concurrent and race tests.

### 5. Shared planner budget enforcement

Move candidate caps, deep-candidate downgrades, stable ordering, defaults, and reason strings into shared planning policy applied to deterministic and AI plans alike.

### 6. Cache policy isolation

Keep `internal/cache` as storage infrastructure. Isolate scanner and AI cache identities, validation, and hit/miss/bypass policy without changing key contents or cache behavior.

### 7. Findings normalization decomposition

Separate finding identity, fingerprinting, metadata lookup, severity/confidence policy, enrichment, and classification while retaining `Normalizer` as the orchestration API and preserving the serialized finding contract.

### 8. AI policy clarification

Centralize disabled, optional, and required behavior while keeping planning and classification ports separate. Add a table-driven policy matrix without changing expected fallback results.

### 9. Deeper package-boundary improvements

After the preceding work is stable, consider separating evidence models from analyzer execution, reducing index coupling to concrete analyzers, improving language frontend boundaries, introducing stable directed candidate graphs, separating issue models from Markdown rendering, and reducing presentation duplication.

## Explicit Initial Non-Goals

- Do not rewrite Go taint analysis or the Python bridge.
- Do not introduce project-wide cross-file analysis in the initial refactor.
- Do not change candidate IDs, cache keys, JSON/SARIF schemas, CLI parsing, source/sink semantics, or output behavior.
- Do not move packages across the `internal` boundary.
- Do not add compatibility shims without a concrete consumer requirement.

## Verification

After each refactoring batch:

```bash
gofmt -w <changed Go files>
go test ./...
go vet ./...
```

Before completion:

```bash
go test -race ./...
go run ./cmd/scanner --format json --no-color ./testdata/go
go run ./cmd/scanner --format sarif --no-color ./testdata/go
```
