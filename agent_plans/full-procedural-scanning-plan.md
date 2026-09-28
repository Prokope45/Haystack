# Full Procedural Scanning Plan

## Objective

Extend Haystack's deterministic taint analysis from bounded, same-file function
calls to project-wide procedural flows for Go and Python. A scan should trace
untrusted data through functions, methods, classes, lambdas, closures, and
cross-file calls until it reaches a security-sensitive sink, subject to explicit
resource budgets.

The analyzer remains static and offline. It must not execute scanned code or
require AI services to produce source-to-sink evidence.

## Current Baseline

- Go and Python snippets support bounded same-file argument and return flows.
- The Go analyzer resolves unambiguous same-file functions and methods, and
  tracks basic struct-field flows.
- The Python analyzer resolves uniquely named same-file functions and methods.
- Candidate discovery can associate same-file sources and sinks through local
  call edges.
- Repository scanning analyzes source files individually; its analysis interface
  does not yet provide a project-wide symbol or call graph to language analyzers.
- Ambiguous dispatch, general function values, closure captures, lambdas, and
  cross-file calls are incomplete or unresolved.

## Scope

### Included

- Go and Python source files discovered within the scan target.
- Local functions, methods, constructors, function values, lambdas, and closures.
- Calls and returns across files in the scanned Go module/package set or Python
  module/package set.
- Taint propagation through arguments, return values, captured variables,
  receivers, and object fields/attributes.
- Bounded analysis of recursion, branches, loops, and multiple possible dispatch
  targets.
- Project-aware source/sink candidate discovery, adaptive planning, evidence,
  cache invalidation, and CLI/MCP reporting.

### Boundaries

- Do not execute source code, import scanned Python modules, or require network
  access to build the project graph.
- Treat external libraries and framework behavior through explicit summaries for
  known sources, sinks, and sanitizers. Unknown external code remains opaque.
- When dynamic dispatch cannot be resolved precisely, use a bounded set of
  plausible in-project targets or report the path as unresolved; do not silently
  claim complete coverage.
- Keep analysis confined to files accepted by the scanner's existing discovery
  and exclusion rules.

## Design Requirements

### 1. Project-level analysis model

Introduce a project analysis input that contains the discovered source units,
their language/package identity, parser results, and configured budgets. Build a
stable symbol index and call graph before running source-to-sink propagation.
Keep snippet scans supported by constructing a one-file project input.

Use stable symbol identities that distinguish packages/modules, receiver types,
methods, nested functions, and source locations. Avoid resolving calls by a bare
function name when that name can refer to multiple declarations.

### 2. Go resolution

- Group files by Go module and package, respecting build constraints and scan
  exclusions.
- Resolve package-local functions, receiver methods, interface implementations,
  function values, and cross-file references.
- Use type information when available; tolerate incomplete modules and
  dependencies without preventing a scan.
- Bound interface and function-value target sets, and retain uncertainty in
  analysis metadata when a call has multiple possible targets.

### 3. Python resolution

- Build module and package identities from discovered `.py` files and relative
  imports without importing or executing them.
- Index functions, classes, methods, nested functions, lambdas, decorators, and
  assignments of callables.
- Resolve `self`/`cls` calls and known inheritance relationships where possible.
- Handle unresolved monkey-patching, reflection, and dynamically constructed
  callables conservatively and within the path budget.

### 4. Interprocedural data flow

Replace the current per-function-only propagation with composable function
summaries or an equivalent bounded context-sensitive engine. Summaries should
represent:

- Which parameters can affect each return value or sink.
- Sources created within a function and how they can reach returns or sinks.
- Sanitization/validation effects for recognized operations.
- Receiver, field, and captured-variable flows needed by callers.

Apply summaries at call sites so tainted arguments enter the correct parameters
and tainted returns flow back to the correct assignment. Preserve call-site
context so an untainted invocation does not inherit taint from another call to
the same function. Use a bounded fixpoint or equivalent strategy for recursion
and mutually recursive functions.

Track closures and lambdas as callable units with explicit captured-variable and
parameter mappings. Preserve source, transformation, call/return, and sink
locations in evidence.

### 5. Control flow, aliases, and object state

Add a staged path from the current syntactic propagation to bounded control-flow
analysis. Merge taint states at branches, iterate loop summaries to a bounded
fixpoint, and distinguish assignments that overwrite tainted values. Add
field-sensitive object/attribute tracking and bounded alias handling for common
Go pointers/structs and Python objects/containers.

Make sanitizer handling explicit. Do not treat arbitrary helper calls as
sanitizers; a transformation preserves taint unless a recognized summary says
otherwise.

### 6. Candidate planning and budgets

Discover source-to-sink candidates over the project call graph, not just within
one function or file. The planner should see representative source locations,
sink locations, likely call paths, and estimated complexity.

Enforce deterministic limits regardless of planner output:

- Maximum call depth and summary/fixpoint iterations.
- Maximum candidate and path counts.
- Maximum dispatch targets per call site.
- Scan timeout and cancellation.

Surface when a flow was bounded or unresolved instead of presenting a partial
analysis as exhaustive. Keep the default limits suitable for local CLI/MCP
scans, and expose configuration only when the behavior is documented and
validated.

### 7. Evidence and cache behavior

Evidence should identify the source, ordered call/return/transform steps, and
sink, including file and line at every relevant transition. Keep the finding
associated with the sink candidate and mark analysis as interprocedural.

Update the scanner behavior version whenever the new analysis can change scan
results, so cached results from earlier analyzers are invalidated. Include any
new analysis options and relevant parser/module identity in cache keys.

## Implementation Phases

### Phase 1 — Shared project model

- Define project/source-unit, symbol, call-edge, and function-summary models.
- Pass project context through repository scans while preserving one-file
  snippet scans.
- Add deterministic symbol identity, graph limits, and telemetry for unresolved
  calls and budget exhaustion.

### Phase 2 — Go project-wide flows

- Build package-aware Go symbols and call edges across files.
- Add type-informed receiver/interface and function-value resolution.
- Support call arguments, returns, methods, struct fields, closures, and
  goroutine/deferred call sites within the defined budgets.
- Validate against cross-file and interface-dispatch fixtures.

### Phase 3 — Python project-wide flows

- Build module/package symbols without executing Python code.
- Resolve cross-module functions, classes, methods, inheritance, lambdas,
  closures, and callable assignments.
- Validate imports, receiver/attribute flows, and unresolved dynamic dispatch.

### Phase 4 — Control flow and summary refinement

- Add branch and loop state merging, bounded recursion/fixpoint handling, and
  improved alias/field tracking.
- Add sanitizer summaries and negative cases for safe or unrelated calls.
- Review false-positive and false-negative behavior on representative projects.

### Phase 5 — Adaptive planning, output, and rollout

- Update candidate discovery and planner inputs to reflect cross-file paths and
  analysis cost.
- Expose bounded-analysis diagnostics through CLI, JSON/SARIF, and MCP.
- Version/invalidate caches, update README/configuration docs, and benchmark cold
  scans on small, medium, and large Go/Python projects.

## Validation Plan

### Unit and integration tests

- Source in one file to sink in another through multiple function arguments and
  return values.
- Go receiver methods, interface dispatch, function values, and cross-package
  calls.
- Python cross-module calls, class inheritance, `self`/`cls` methods, lambdas,
  nested functions, and closure captures.
- Taint through and out of struct fields/object attributes.
- Branches, loops, early returns, recursion, and mutually recursive functions.
- Multiple call sites where only one passes tainted input.
- Sanitized input and unrelated safe calls that must not produce findings.
- Ambiguous/dynamic calls and exhausted budgets with clear bounded-analysis
  metadata.
- End-to-end CLI and MCP scans with cache miss/hit behavior and cache-version
  invalidation.

### Performance and correctness checks

- Measure call graph construction and taint propagation separately.
- Benchmark cold scan time, memory, number of summaries/paths, and dispatch-target
  expansion on representative project sizes.
- Run the complete test suite, race tests for shared scanner paths, static
  analysis/vet checks, and deterministic-output comparisons.
- Compare findings against hand-reviewed positive and negative fixtures; AI
  classification must not substitute for deterministic flow evidence.

## Acceptance Criteria

1. Repository scans can trace a source through same-file and cross-file Go and
   Python calls to a sink, including supported methods, lambdas, and closures.
2. Argument and return propagation remains call-site-sensitive; unrelated safe
   invocations do not inherit taint.
3. Recursion, dynamic dispatch, and project size remain bounded by deterministic
   budgets, with incompleteness visible in diagnostics.
4. Findings provide a useful file/line call path and map to the correct sink
   candidate.
5. Existing snippet, CLI, MCP, cache, and offline behavior remains covered by
   automated tests.
