# Scanner Caching Implementation Plan

## Goal

Add a layered, content-addressed caching system to the scanner so repeated scans reuse previous deterministic and AI analysis results when all relevant inputs are unchanged.

The caching system must:

* Avoid repeating identical deterministic analysis.
* Avoid unnecessary Jev/System-One API calls and token consumption.
* Correctly invalidate stale results when scanner behavior, rules, configuration, prompts, or AI models change.
* Support `--no-cache` for forced fresh scans.
* Be usable by both the CLI and MCP through the shared scanner service.
* Remain optional: disabling/removing the cache must not change scanner correctness.
* Provide enough metadata/debugging information to understand cache behavior.
* Establish a foundation for future incremental repository analysis.

---

# Phase 1 — Inspect the Existing Prototype

Before modifying architecture, inspect the existing repository and identify:

* Scanner service entry point.
* `ScanRequest` / `ScanResult`.
* AST parsing/indexing implementation.
* Candidate discovery.
* Reachability analysis.
* Deterministic analysis planner.
* SAST/data-flow implementation.
* AI planner integration.
* AI classifier integration.
* Finding model.
* CLI command implementation.
* MCP scanner integration.
* Existing configuration system.
* Existing version information.
* Existing tests.

Do not restructure unrelated components.

Produce a short architecture assessment before implementation identifying:

1. Where the cache abstraction should live.
2. Where cache lookup should occur in the scan pipeline.
3. Which existing structs should contribute to cache keys.
4. Which AI request/response structures can be cached independently.
5. Which analysis stages are currently deterministic and therefore safe to cache.

---

# Phase 2 — Introduce the Cache Abstraction

Create a dedicated internal cache package.

Suggested structure:

```text
internal/
├── cache/
│   ├── cache.go
│   ├── key.go
│   ├── disk.go
│   ├── metadata.go
│   └── cache_test.go
```

Start with a filesystem-backed implementation.

Do not introduce Redis, PostgreSQL, SQLite, or another external service yet.

## Cache interface

Create an abstraction similar to:

```go
type Cache interface {
    Get(ctx context.Context, key CacheKey) ([]byte, bool, error)
    Put(ctx context.Context, key CacheKey, value []byte, metadata CacheMetadata) error
    Delete(ctx context.Context, key CacheKey) error
    Clear(ctx context.Context) error
}
```

The exact API may be adapted to the existing project architecture.

The cache implementation must:

* Be safe against corrupted cache entries.
* Use atomic writes.
* Create missing directories automatically.
* Avoid partially written cache files.
* Handle cache misses without returning errors.
* Return useful errors for actual filesystem failures.
* Be safe when multiple scanner processes access the cache concurrently.

---

# Phase 3 — Content-Addressed Cache Keys

Do not key the cache solely by source code.

Create canonical cache-key inputs containing all relevant analysis inputs.

For example:

```go
type CacheKeyInput struct {
    SourceHash       string
    Language         string
    ScannerVersion   string
    RulesVersion     string
    AnalysisStrategy string
    AnalysisConfig   string
}
```

Serialize the fields deterministically and hash them with SHA-256.

Conceptually:

```text
cache_key =
SHA256(
    source_hash
    + language
    + scanner_version
    + rules_version
    + analysis_strategy
    + canonical_analysis_config
)
```

The implementation must ensure that equivalent configurations produce identical keys.

Do not depend on Go map iteration order when generating canonical configuration data.

---

# Phase 4 — Versioning and Invalidation

Caching must not cause stale security results.

Include version information for anything capable of changing analysis behavior.

At minimum consider:

```text
Scanner version
Rule version
Language/parser version
Analysis strategy
Analysis configuration
```

For AI stages additionally include:

```text
AI provider
AI model
AI model version
Prompt version
Request schema version
Response schema version
AI configuration
```

Changing any relevant value must produce a different cache key.

Examples:

```text
scanner v0.1 + rules v1
        ↓
cache A

scanner v0.2 + rules v2
        ↓
cache B
```

Do not manually delete old cache entries simply because a new scanner version is released.

Old entries may remain until cache eviction/cleanup is implemented.

---

# Phase 5 — Final Scan Result Cache

Implement the first user-visible cache around the complete scan result.

Pipeline:

```text
ScanRequest
    ↓
Canonicalize request
    ↓
Calculate cache key
    ↓
Cache lookup
    ├── HIT → deserialize ScanResult → return
    │
    └── MISS
          ↓
       normal scan
          ↓
       ScanResult
          ↓
       cache result
          ↓
       return
```

This should happen at the shared scanner-service layer so both CLI and MCP benefit from it.

Do not implement separate CLI and MCP caches.

## Cache entry

Store:

```text
ScanResult
+
CacheMetadata
```

Example metadata:

```json
{
  "cache_key": "...",
  "created_at": "...",
  "scanner_version": "0.1.0",
  "rules_version": "...",
  "language": "go",
  "strategy": "adaptive",
  "source_hash": "..."
}
```

The serialized result should contain everything necessary to reproduce the normal scan output.

---

# Phase 6 — CLI Cache Controls

Add:

```bash
--no-cache
```

This must bypass cache reads and writes for that invocation.

Example:

```bash
scanner scan-code \
  --lang go \
  --code '...' \
  --no-cache
```

Also consider:

```bash
--refresh-cache
```

only if it fits naturally with the existing CLI conventions.

Do not require both flags if one can cleanly express the intended behavior.

Normal scans should use the cache by default.

---

# Phase 7 — Cache Visibility

Add cache information to verbose output.

Normal output may show only:

```text
Cache: hit
```

or:

```text
Cache: miss
```

For verbose mode, expose stage information such as:

```text
Cache:
  final result: HIT
```

Later, when layered caching exists:

```text
Cache:
  AST:             HIT
  candidates:      HIT
  analysis plan:   HIT
  SAST evidence:   HIT
  AI planner:      HIT
  AI classifier:   MISS
  final result:    MISS
```

Do not make verbose cache diagnostics part of the machine-readable JSON/SARIF finding format unless useful to the existing output contract.

---

# Phase 8 — AI Planner Cache

Implement a separate cache for AI planning.

Do not rely exclusively on the final scan-result cache.

Reason:

If the source remains unchanged but another part of the scan requires recomputation, the scanner should still be able to reuse an existing AI planning result.

Create an AI-specific cache key based on the complete planner input.

Conceptually:

```text
AI planner cache key =
SHA256(
    canonical planner input
    + provider
    + model
    + model version
    + prompt version
    + request schema version
)
```

The planner input should include all information that can affect the decision, including relevant:

* candidate data,
* source/sink information,
* transformations,
* reachability,
* estimated cost,
* security class,
* analysis configuration.

Do not cache solely based on candidate ID.

Candidate IDs may remain stable even when candidate characteristics change.

---

# Phase 9 — AI Classifier Cache

Add an independent cache for AI classification.

Cache based on the complete classification evidence plus:

```text
provider
model
model version
prompt version
schema version
classification configuration
```

Conceptually:

```text
Evidence
  ↓
Canonical representation
  ↓
SHA-256
  ↓
AI classification cache
```

A classifier result must not be reused if the evidence changes.

Do not treat the AI classification cache as authoritative security truth.

The deterministic scanner remains the security ground truth.

---

# Phase 10 — Separate Deterministic and AI Caches

Maintain independent invalidation.

Example:

```text
Source
  ↓
Deterministic SAST
  ↓
Evidence
  ↓
AI classifier
```

If the AI model changes:

```text
Deterministic cache → reusable
AI cache            → miss
```

If a SAST rule changes:

```text
Deterministic cache → miss
AI cache            → likely miss because evidence changed
```

If only the AI prompt changes:

```text
Deterministic cache → reusable
AI cache            → miss
```

This separation is important for controlling AI costs.

---

# Phase 11 — Cache Serialization

Use a stable serialization format.

JSON is acceptable for the first implementation because it provides:

* inspectability,
* easy debugging,
* portability,
* straightforward schema evolution.

Each entry should contain:

```text
schema_version
metadata
payload
```

Example:

```json
{
  "schema_version": 1,
  "metadata": {
    "created_at": "...",
    "scanner_version": "..."
  },
  "payload": {
    "...": "..."
  }
}
```

If cache schema changes, the implementation should treat incompatible entries as cache misses rather than crashing.

---

# Phase 12 — Filesystem Layout

Use an OS-appropriate cache directory.

Prefer platform conventions rather than hardcoding `~/.cache`.

For example:

```text
Linux:
~/.cache/<scanner>/

macOS:
~/Library/Caches/<scanner>/

Windows:
%LOCALAPPDATA%/<scanner>/Cache/
```

Allow an explicit override such as:

```bash
SCANNER_CACHE_DIR=/path/to/cache
```

or the project's existing configuration mechanism.

The exact configuration mechanism should follow the conventions already present in the prototype.

Suggested internal layout:

```text
cache/
├── scan/
├── planner/
├── classifier/
└── metadata/
```

Use the hash to distribute files into subdirectories to avoid excessive files in a single directory:

```text
scan/
  ab/
    abcdef....json
```

---

# Phase 13 — Cache Safety

Treat cache contents as untrusted persisted data.

The cache implementation must:

* Validate schema versions.
* Validate deserialized structures.
* Handle malformed JSON.
* Handle truncated files.
* Handle deleted files during reads.
* Avoid arbitrary file paths derived directly from user input.
* Sanitize/validate cache keys.
* Never execute cached content.
* Never interpret cached AI output as executable instructions.

AI output remains data.

---

# Phase 14 — Cache Concurrency

Account for concurrent CI jobs.

Two identical scans may start simultaneously:

```text
Job A → cache MISS
Job B → cache MISS
```

Both may perform the analysis.

This is acceptable for the initial implementation.

Do not build complicated distributed locking yet.

However, cache writes must be atomic so that:

```text
Job A writing
+
Job B reading
```

cannot result in corrupted JSON.

Use:

```text
write temporary file
        ↓
fsync/close as appropriate
        ↓
atomic rename
```

where supported.

---

# Phase 15 — Tests

Add comprehensive cache tests.

## Cache unit tests

Test:

* cache miss,
* cache hit,
* put/get,
* delete,
* clear,
* malformed entry,
* missing entry,
* corrupted entry,
* concurrent reads,
* concurrent writes,
* atomic replacement,
* invalid schema version.

## Key tests

Verify that:

```text
same input → same key
```

and:

```text
source changed → different key
language changed → different key
scanner version changed → different key
rules version changed → different key
strategy changed → different key
configuration changed → different key
```

AI-specific:

```text
model changed → different key
provider changed → different key
prompt version changed → different key
evidence changed → different key
```

---

# Phase 16 — End-to-End Scan Tests

Add a test similar to the provided command-injection example.

First run:

```text
cache miss
scan performed
finding generated
result cached
```

Second run:

```text
cache hit
no analysis performed
same finding returned
```

Assert that the results are equivalent.

The test should specifically verify that expensive stages are not invoked on a final-result cache hit.

For example, mock:

```text
planner
classifier
analyzer
```

and verify their call counts.

Expected:

```text
first scan:
  analyzer:   1
  planner:    1
  classifier: 1

second scan:
  analyzer:   0
  planner:    0
  classifier: 0
```

---

# Phase 17 — AI Cache Tests

Create a mocked AI provider.

Test:

```text
first identical planner request
→ provider called

second identical planner request
→ provider not called
```

Then change:

```text
model
```

and verify:

```text
provider called again
```

Do the same for classifier requests.

Also test AI failure:

```text
AI request fails
↓
deterministic fallback
↓
scan completes
```

A failed AI request should not result in a poisoned successful cache entry.

Do not cache incomplete/error results as successful analysis results.

---

# Phase 18 — Metrics

Extend analysis statistics with cache information.

For example:

```go
type CacheStats struct {
    FinalResultHits       int
    FinalResultMisses     int
    PlannerHits           int
    PlannerMisses         int
    ClassifierHits        int
    ClassifierMisses      int
}
```

Potentially track:

```text
bytes read
bytes written
cache lookup latency
```

but don't over-engineer this initially.

Expose useful metrics in verbose/debug output.

---

# Phase 19 — Benchmarking

Benchmark:

```text
cold scan
warm scan
```

using the provided command-injection example.

Measure:

```text
cold scan duration
warm scan duration
CPU
memory
AI requests
AI tokens
```

The expected warm-cache result should be dramatically cheaper than the cold scan.

The benchmark should also cover a repository scan where only a subset of data is eventually cached.

---

# Phase 20 — Future Incremental Analysis

Do not implement full incremental analysis in this phase.

However, design the cache interfaces so the following can eventually be cached independently:

```text
Source
 ↓
AST
 ↓
Program Index
 ↓
Reachability
 ↓
Candidates
 ↓
Analysis Plan
 ↓
SAST Evidence
 ↓
AI Classification
 ↓
Final Finding
```

The first implementation may only cache:

```text
Final ScanResult
AI planner result
AI classifier result
```

This is intentional.

Later, add:

```text
AST/index cache
candidate cache
reachability cache
SAST evidence cache
```

with dependency-aware invalidation.

---

# Phase 21 — Documentation

Update the scanner documentation with:

## Cache behavior

Explain:

* caching is enabled by default,
* identical scans reuse results,
* cache keys incorporate scanner/rule/configuration versions,
* AI results are cached independently,
* cache misses trigger normal analysis,
* cache does not change security semantics.

## CLI

Document:

```bash
scanner scan-code ...
scanner scan-code ... --no-cache
```

## Cache location

Document the default platform-specific location and override mechanism.

## Debugging

Document verbose cache output.

## CI/CD

Explain that persistent CI cache storage can significantly reduce repeated analysis.

For ephemeral CI runners, explain that cache persistence must be configured by the CI system if cross-job reuse is desired.

---

# Phase 22 — CI/CD Considerations

Do not make the scanner depend on a persistent cache.

The scanner must work correctly when:

```text
cache is empty
cache is deleted
cache is unavailable
```

CI behavior should be:

```text
persistent runner:
    reuse scanner cache

ephemeral runner:
    cold scan unless CI cache is restored
```

The scanner should never fail a security scan merely because its cache is unavailable.

Cache errors should generally degrade to normal scanning unless the error indicates a serious filesystem/configuration problem that the existing CLI policy considers fatal.

---

# Phase 23 — MCP Integration

The MCP server should automatically benefit from the shared scanner cache.

Do not create an MCP-specific cache.

Architecture:

```text
MCP
 ↓
Scanner Service
 ↓
Cache
 ↓
Analysis
```

The same scan request should produce the same cached result whether invoked through:

```text
CLI
```

or:

```text
MCP
```

If the MCP API eventually exposes cache controls, keep them aligned with the scanner service rather than implementing independent logic.

---

# Acceptance Criteria

The implementation is complete when all of the following are true:

### Basic caching

* [ ] Cache abstraction exists.
* [ ] Filesystem cache works without external services.
* [ ] Cache keys are content-addressed.
* [ ] Scanner/rule/configuration versions affect keys.
* [ ] Cache entries are versioned.
* [ ] Corrupt entries behave as cache misses.
* [ ] Cache writes are atomic.

### Scan caching

* [ ] First scan produces a cache miss.
* [ ] Result is persisted.
* [ ] Identical second scan produces a cache hit.
* [ ] Identical scan does not rerun expensive analysis.
* [ ] Returned findings are equivalent to the cold scan.
* [ ] `--no-cache` forces fresh analysis.

### AI caching

* [ ] Planner results are cached independently.
* [ ] Classifier results are cached independently.
* [ ] Provider/model/version affect AI cache keys.
* [ ] Prompt/schema versions affect AI cache keys.
* [ ] Changed evidence invalidates classifier results.
* [ ] AI failures do not create successful cache entries.

### Correctness

* [ ] Changing source invalidates the relevant cache.
* [ ] Changing scanner version invalidates relevant cache.
* [ ] Changing rules invalidates relevant cache.
* [ ] Changing analysis configuration invalidates relevant cache.
* [ ] Removing the cache does not change scanner findings.
* [ ] AI remains optional.
* [ ] Cached AI output is never treated as authoritative security truth.

### Observability

* [ ] Cache hit/miss is visible in verbose output.
* [ ] Cache statistics are available.
* [ ] Cold vs warm performance is benchmarked.

### Architecture

* [ ] CLI and MCP share the same cache through the scanner service.
* [ ] Cache implementation is isolated from analyzer/rule logic.
* [ ] No external cache service is required.
* [ ] Architecture supports future AST/candidate/reachability/SAST caches.

---

# Recommended Implementation Order

Implement in this order:

```text
1. Inspect prototype
        ↓
2. Cache interface
        ↓
3. Filesystem backend
        ↓
4. Canonical cache keys
        ↓
5. Final ScanResult cache
        ↓
6. --no-cache
        ↓
7. Cache diagnostics
        ↓
8. AI planner cache
        ↓
9. AI classifier cache
        ↓
10. Cache tests
        ↓
11. End-to-end tests
        ↓
12. Benchmarks
        ↓
13. Documentation
```

Do **not** implement incremental AST/reachability/SAST caching yet.

The first milestone should simply prove:

```text
cold scan
    ↓
analysis
    ↓
cache

same scan
    ↓
cache HIT
    ↓
result
```

Then prove that AI calls behave similarly:

```text
candidate/evidence
    ↓
AI request
    ↓
AI cache

same request
    ↓
AI cache HIT
    ↓
zero additional API/token usage
```

The final design should leave room for progressively finer-grained caching without requiring a redesign of the scanner.

## Architectural principle

The cache is a **performance optimization, not a security mechanism**.

The scanner must produce the same security conclusions with or without the cache. A cache hit should be semantically equivalent to rerunning the corresponding analysis with the same inputs.

The key invariant is:

> **Caching may eliminate computation; it must never change security semantics.**
