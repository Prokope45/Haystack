# Adaptive AI-Assisted SAST — OpenCode Implementation Design Plan

## 1. Objective

Modify the existing Go SAST scanner architecture to support **AI-assisted adaptive analysis**.

The scanner must remain fully functional without AI/ML services. Deterministic AST/static analysis remains the foundation and authoritative security-analysis mechanism.

The optional AI layer, initially targeting external **Jev/System-One-style models**, should have a larger role than simple post-analysis classification:

1. Identify security-relevant regions and candidates.
2. Prioritize candidates for expensive analysis.
3. Select an appropriate analysis depth/strategy.
4. Potentially prioritize vulnerability classes.
5. Help determine which candidate paths deserve deeper analysis.
6. Classify/validate evidence after deterministic analysis.
7. Provide reasoning metadata that can be surfaced through CLI, JSON, SARIF, and MCP.

Do **not** embed Jev, Kev, or another ML model into the scanner.

The scanner communicates with externally deployed AI services through an API.

---

# 2. Core Architectural Principle

The scanner should implement a **neuro-symbolic / hybrid SAST architecture**:

```text
Source Code
     |
     v
AST / Parsing
     |
     v
Program Index
     |
     v
Lightweight Candidate Discovery
     |
     v
Analysis Planning
     |
     +-----------------------------+
     |                             |
     | AI disabled                 | AI enabled
     |                             |
     v                             v
Deterministic Planner       External Jev API
     |                             |
     +-------------+---------------+
                   |
                   v
            Analysis Plan
                   |
                   v
          Adaptive SAST Engine
                   |
                   v
          Security Rule Engine
                   |
                   v
                Evidence
                   |
                   v
          Optional AI Validation
                   |
                   v
               Finding
```

The AI model must **not replace static analysis**.

The model should primarily answer questions such as:

* Which candidates deserve deeper analysis?
* Which vulnerability classes are relevant?
* How much analysis should be performed?
* Which candidate paths should be analyzed first?
* Is additional analysis warranted?
* Does the resulting evidence appear consistent with a vulnerability classification?

The deterministic engine remains responsible for establishing the actual source/sink/data-flow evidence.

---

# 3. Required Design Properties

The implementation must satisfy these properties.

## 3.1 Offline operation

The following must work with no network connection:

```bash
scanner .
scanner ./src
scanner . --diff HEAD~1
```

No AI service may be required for normal SAST.

## 3.2 AI is optional

Configuration should support:

```text
disabled
optional
required
```

### disabled

Never contact the AI service.

### optional

Use AI when available.

If AI fails:

```text
AI failure
    ↓
deterministic fallback planner
    ↓
continue scan
```

### required

AI failures may fail the scan, subject to explicit configuration.

Never make "required" the default.

---

# 4. Separate AI Responsibilities

Do not create one generic `Classifier` interface that handles everything.

Separate AI responsibilities into explicit interfaces.

Recommended abstractions:

```go
type AnalysisPlanner interface {
    Plan(
        ctx context.Context,
        input AnalysisPlanningInput,
    ) (AnalysisPlan, error)
}
```

and:

```go
type FindingClassifier interface {
    Classify(
        ctx context.Context,
        input ClassificationInput,
    ) (ClassificationResult, error)
}
```

Potentially add:

```go
type CandidateRanker interface {
    Rank(
        ctx context.Context,
        input CandidateRankingInput,
    ) ([]RankedCandidate, error)
}
```

However, avoid unnecessary interfaces until concrete requirements justify them.

The initial implementation can expose planning and classification through one external provider while keeping the internal interfaces separated.

---

# 5. New Analysis Pipeline

Implement the scanner as a staged pipeline.

## Stage 1 — Source discovery

Discover:

* source files
* language
* file size
* Git status where applicable
* excluded paths

Do not send the entire repository to an AI model.

---

## Stage 2 — AST parsing

Parse source files into language-specific AST representations.

Go:

```text
go/parser
go/ast
go/token
go/types
```

Python should use the selected parser strategy from the existing architecture.

The AST layer should identify:

* functions
* methods
* classes
* imports
* calls
* assignments
* variables
* literals
* control-flow constructs
* function parameters
* return values
* security-sensitive APIs

---

# 6. Program Index

Introduce a lightweight program index.

Conceptually:

```go
type ProgramIndex struct {
    Files       []FileInfo
    Functions   []FunctionInfo
    Calls       []CallInfo
    Imports     []ImportInfo
    Sources     []SourceInfo
    Sinks       []SinkInfo
    References  []ReferenceInfo
}
```

The index should be cheap to construct.

Its purpose is to allow the scanner to answer questions without immediately performing expensive data-flow analysis.

Examples:

```text
Where are exec.Command calls?

Which functions call this function?

Which files interact with SQL?

Which functions receive HTTP parameters?

Which functions deserialize external data?

Which files contain filesystem operations?
```

---

# 7. Candidate Discovery

After indexing, generate security-analysis candidates.

Examples:

```text
HTTP parameter → exec.Command
HTTP parameter → SQL execution
file path parameter → filesystem operation
request body → deserialization
environment variable → sensitive operation
```

A candidate should contain structured evidence.

Example:

```go
type AnalysisCandidate struct {
    ID              string
    Language        string
    File            string
    Function        string

    VulnerabilityClasses []string

    Sources         []SourceRef
    Sinks           []SinkRef
    Transformations []TransformationRef

    EstimatedCost   AnalysisCost
    Metadata        map[string]any
}
```

Do not perform deep data-flow analysis yet.

---

# 8. Analysis Planning

Introduce an explicit analysis-planning stage.

```go
type AnalysisPlan struct {
    Candidates []CandidatePlan
}
```

Each candidate plan should specify something similar to:

```go
type CandidatePlan struct {
    CandidateID       string
    Priority          int
    Analyze           bool

    Depth             int
    Interprocedural   bool
    ControlFlow       bool

    VulnerabilityClasses []string

    Reason            string
}
```

The plan should be executable by the deterministic SAST engine.

---

# 9. Deterministic Planner

Implement a deterministic planner first.

It should work without AI.

Example heuristics:

```text
Known source + known sink:
    high priority

Known sink with unknown source:
    medium priority

Known source with no known sink:
    low/medium priority

No security-sensitive behavior:
    don't deeply analyze
```

Additional signals may include:

* source/sink distance
* number of transformations
* sanitizer presence
* reachable/unreachable path
* number of functions crossed
* vulnerability class
* framework/API context
* candidate complexity

This planner is the fallback when AI is disabled or unavailable.

---

# 10. AI Analysis Planner

Implement an optional external AI planning provider.

The AI should receive **structured candidate information**, not arbitrary repository contents.

Example request:

```json
{
  "language": "go",
  "candidate": {
    "source": {
      "type": "function_parameter",
      "name": "input"
    },
    "sink": {
      "type": "shell_execution",
      "api": "os/exec.Command"
    },
    "transformations": [
      "string formatting"
    ],
    "files": 2,
    "estimated_depth": 4
  }
}
```

The AI should return a constrained structured response.

Example:

```json
{
  "analyze": true,
  "priority": 95,
  "depth": 6,
  "interprocedural": true,
  "control_flow": false,
  "vulnerability_classes": [
    "command_injection"
  ],
  "reason": "External input reaches a shell execution sink without an identified sanitizer."
}
```

The scanner must validate this response against a strict schema.

Do not trust arbitrary model-generated instructions.

---

# 11. AI Must Not Be Allowed Unlimited Authority

The AI plan must be constrained.

For example:

```text
requested depth = 1000
maximum configured depth = 10

→ scanner uses depth 10
```

Likewise:

```text
requested candidate count = 100000
configured maximum = 1000

→ scanner uses 1000
```

The model can select among capabilities exposed by the scanner, but cannot invent new capabilities.

Use bounded enums/configuration rather than arbitrary model commands.

For example:

```go
type AnalysisMode string

const (
    AnalysisShallow AnalysisMode = "shallow"
    AnalysisMedium  AnalysisMode = "medium"
    AnalysisDeep    AnalysisMode = "deep"
)
```

---

# 12. Candidate Prioritization

Support ranking candidates.

Example:

```text
Candidate A → priority 95
Candidate B → priority 82
Candidate C → priority 31
Candidate D → priority 12
```

The scanner can then allocate its analysis budget accordingly.

For example:

```yaml
analysis:
  max_candidates: 100
  max_deep_candidates: 25
```

This allows the scanner to scale analysis cost.

---

# 13. Analysis Budgets

Introduce explicit resource controls.

Potential configuration:

```yaml
analysis:
  max_depth: 8
  max_interprocedural_depth: 5
  max_candidates: 1000
  max_deep_candidates: 100
  max_paths_per_candidate: 500
  timeout: 30s
```

These limits must be enforced by the deterministic scanner regardless of AI recommendations.

---

# 14. Adaptive Analysis Modes

Support at least three modes:

### Shallow

```text
AST
source/sink detection
local data flow
```

### Medium

```text
AST
source/sink
local data flow
limited call graph
limited interprocedural analysis
```

### Deep

```text
AST
source/sink
data flow
call graph
interprocedural analysis
control-flow analysis
larger path budget
```

The AI planner can recommend the mode, but the scanner executes it.

---

# 15. AI Validation / Classification

After deterministic analysis, optionally send focused evidence back to the external AI service.

Example:

```json
{
  "language": "go",
  "vulnerability": "command_injection",
  "evidence": {
    "source": "function parameter input",
    "sink": "exec.Command",
    "flow": [
      "input",
      "fmt.Sprintf",
      "exec.Command"
    ]
  }
}
```

Return:

```json
{
  "label": "command_injection",
  "probabilities": {
    "command_injection": 0.94,
    "safe": 0.03,
    "uncertain": 0.03
  }
}
```

Preserve:

* provider
* model
* model version
* probabilities
* request metadata
* latency where appropriate

Do not treat model probability as CVSS severity.

---

# 16. AI Planning and AI Classification Must Be Distinct

The scanner should be able to operate in these configurations:

```text
SAST only
```

```text
SAST + AI planning
```

```text
SAST + AI classification
```

```text
SAST + AI planning + AI classification
```

This allows benchmarking each component independently.

---

# 17. Measuring the Value of AI Planning

Add instrumentation specifically for adaptive analysis.

Track:

```go
type AnalysisStats struct {
    FilesDiscovered          int
    FilesParsed              int

    CandidatesDiscovered     int
    CandidatesAnalyzed       int
    CandidatesSkipped        int

    ShallowAnalyses          int
    MediumAnalyses           int
    DeepAnalyses             int

    PathsConsidered          int
    PathsAnalyzed            int

    AIPlanningRequests       int
    AIPlanningLatency        time.Duration

    AIClassificationRequests int
    AIClassificationLatency  time.Duration
}
```

The scanner should be able to answer:

```text
How many candidates existed?
How many received deep analysis?
How much analysis was skipped?
How much time did AI planning consume?
How much deterministic analysis time was saved?
Did adaptive analysis miss findings?
```

---

# 18. Benchmark Adaptive vs Full Analysis

Create benchmark modes.

### Full deterministic

Analyze every eligible candidate.

### Adaptive deterministic

Use deterministic prioritization.

### Adaptive AI

Use the external AI planner.

Compare:

```text
Total runtime
CPU
Memory
Candidates analyzed
Paths analyzed
Findings
True positives
False positives
False negatives
AI latency
```

Do not claim AI is beneficial merely because it reduces runtime.

The central metric is:

```text
security coverage vs analysis cost
```

A faster scanner that misses important vulnerabilities is not necessarily an improvement.

---

# 19. Ground-Truth Testing

Build a test corpus containing:

```text
known vulnerable examples
known safe examples
edge cases
sanitized flows
false-positive cases
```

For every adaptive optimization, compare results against a full-analysis baseline.

Example:

```text
Full analysis:
    findings = 20

Adaptive analysis:
    findings = 20

Missed findings:
    0
```

Also measure:

```text
analysis paths:
    full = 10,000
    adaptive = 2,000
```

This is the evidence required to determine whether the optimization is useful.

---

# 20. Safety Rule for Adaptive Skipping

The scanner should distinguish between:

```text
"not prioritized"
```

and:

```text
"proven safe"
```

If AI decides not to deeply analyze a candidate, do not report:

```text
SAFE
```

Report internally:

```text
SKIPPED_BY_ANALYSIS_POLICY
```

or:

```text
LOW_PRIORITY
```

This prevents an optimization decision from being confused with a security conclusion.

---

# 21. AI Failure Behavior

Every AI request must have:

* explicit timeout
* bounded request size
* bounded response size
* validation
* retry policy
* error handling
* logging

Optional mode:

```text
AI unavailable
    ↓
deterministic planner
    ↓
continue
```

Required mode:

```text
AI unavailable
    ↓
scanner error
```

Do not silently convert a required AI failure into success.

---

# 22. External Provider Architecture

Maintain provider abstraction.

Example:

```text
internal/
└── ai/
    ├── planner.go
    ├── classifier.go
    ├── provider.go
    └── providers/
        ├── jev/
        │   └── client.go
        └── ...
```

Do not place Jev-specific logic into:

```text
analyzer/
rules/
flow/
findings/
```

The scanner should depend on interfaces.

---

# 23. Configuration

Extend configuration approximately as follows:

```yaml
ai:
  mode: optional

  planner:
    enabled: true
    provider: jev
    endpoint: "https://jev.example.com/api"
    timeout: 5s

  classifier:
    enabled: true
    provider: jev
    endpoint: "https://jev.example.com/api"
    timeout: 5s

analysis:
  strategy: adaptive

  max_depth: 8
  max_interprocedural_depth: 5
  max_candidates: 1000
  max_deep_candidates: 100
  max_paths_per_candidate: 500
```

Exact Jev API fields must be determined through current API documentation before implementation.

Do not invent an API schema.

---

# 24. CLI

Add explicit controls.

Examples:

```bash
scanner .
```

Default behavior should remain safe and deterministic.

AI planning:

```bash
scanner . --ai-planner
```

AI classification:

```bash
scanner . --ai-classifier
```

Both:

```bash
scanner . --ai-planner --ai-classifier
```

Analysis strategy:

```bash
scanner . --analysis full
scanner . --analysis adaptive
```

Potentially:

```bash
scanner . --analysis adaptive --ai-planner
```

Debug analysis:

```bash
scanner . --verbose-analysis
```

This should expose information such as:

```text
Candidates discovered: 81
Deep analysis: 13
Medium analysis: 27
Shallow analysis: 41
Skipped: 0
AI planning latency: 84ms
```

Avoid exposing sensitive source code in normal logs.

---

# 25. JSON Output

Extend JSON output with analysis metadata.

Example:

```json
{
  "findings": [],
  "analysis": {
    "strategy": "adaptive",
    "candidates_discovered": 81,
    "candidates_analyzed": 81,
    "deep": 13,
    "medium": 27,
    "shallow": 41,
    "ai_planning": {
      "enabled": true,
      "provider": "jev",
      "model": "..."
    }
  }
}
```

AI metadata should be optional.

---

# 26. Finding Model

Maintain the existing distinction between:

```text
SAST confidence
AI probability
severity
CVSS
```

Do not combine these into one score.

Example:

```go
type Finding struct {
    ID          string
    Fingerprint string

    Category    string
    CWE         []string

    Severity    Severity
    Confidence  float64

    Evidence    []Evidence

    Classification *ClassificationResult

    AnalysisMetadata *AnalysisMetadata
}
```

---

# 27. Analysis Metadata

Add metadata describing how the finding was reached.

Example:

```go
type AnalysisMetadata struct {
    Strategy        string
    Priority        int
    Depth           int
    Interprocedural bool

    PlannerProvider string
    PlannerModel    string
}
```

This is useful for debugging and research.

---

# 28. MCP Integration

MCP should expose the scanner's adaptive capabilities without duplicating analysis logic.

Existing tools remain:

```text
scan
scan_diff
scan_file
explain_finding
get_remediation
get_security_status
prepare_issue
create_issue
```

Potential additional tool:

```text
get_analysis_plan
```

This should be read-only.

Example:

```text
Agent
  ↓
get_analysis_plan
  ↓
candidate prioritization
  ↓
analysis strategy
```

This is especially useful for debugging AI-agent workflows.

---

# 29. MCP Diff Scanning

`scan_diff` should become one of the primary workflows.

Example:

```text
AI Agent
    ↓
changes code
    ↓
scan_diff
    ↓
AST/index changed files
    ↓
candidate discovery
    ↓
AI planning
    ↓
adaptive SAST
    ↓
findings
```

Avoid scanning the entire repository when the agent only changed a small region unless dependency/call-graph analysis determines that broader analysis is necessary.

---

# 30. Issue Creation

Keep issue creation separate from analysis.

The pipeline remains:

```text
scan_diff
    ↓
finding
    ↓
prepare_issue
    ↓
agent reviews
    ↓
create_issue
```

AI planning must never automatically create issues.

Issue creation remains an explicit side effect requiring authorization.

---

# 31. Repository Structure

Modify the existing repository toward:

```text
internal/
├── analyzer/
│   ├── analyzer.go
│   ├── go/
│   └── python/
│
├── index/
│   ├── index.go
│   ├── functions.go
│   ├── calls.go
│   └── references.go
│
├── candidates/
│   ├── candidate.go
│   ├── discovery.go
│   └── ranking.go
│
├── planning/
│   ├── planner.go
│   ├── deterministic.go
│   ├── plan.go
│   └── budget.go
│
├── flow/
│   ├── graph.go
│   └── analyzer.go
│
├── rules/
│   ├── rule.go
│   ├── command_injection.go
│   ├── sql_injection.go
│   └── path_traversal.go
│
├── ai/
│   ├── planner.go
│   ├── classifier.go
│   ├── models.go
│   └── providers/
│       └── jev/
│           └── client.go
│
├── findings/
│   ├── finding.go
│   ├── fingerprint.go
│   └── normalize.go
│
├── scanner/
│   └── scanner.go
│
├── issues/
├── mcp/
├── config/
└── output/
```

The exact organization may be adjusted to match the existing repository.

Do not perform a large restructuring without first inspecting the current implementation.

---

# 32. Implementation Order

Implement incrementally.

## Phase 1 — Understand current implementation

Before changing code:

1. Inspect repository.
2. Identify existing analyzer interfaces.
3. Identify current AST implementation.
4. Identify current source/sink implementation.
5. Identify current flow implementation.
6. Identify current finding model.
7. Identify existing classifier code.
8. Identify CLI.
9. Identify MCP implementation.
10. Identify existing tests.

Produce a short architecture assessment before making structural changes.

---

## Phase 2 — Introduce program indexing

Implement:

```text
AST
 ↓
ProgramIndex
```

Do not introduce AI yet.

Add tests.

---

## Phase 3 — Candidate discovery

Implement:

```text
ProgramIndex
 ↓
AnalysisCandidate[]
```

Start with command injection.

Example:

```text
function parameter
      ↓
exec.Command
```

Add tests for:

* positive candidate
* unrelated function
* sanitized input
* multiple candidates

---

## Phase 4 — Deterministic planning

Implement:

```text
Candidate[]
 ↓
DeterministicPlanner
 ↓
AnalysisPlan
```

Add analysis budgets and depth.

Verify that the planner can reduce expensive analysis without changing findings relative to the full-analysis baseline.

---

## Phase 5 — Adaptive SAST

Implement:

```text
AnalysisPlan
 ↓
Flow Analyzer
```

Support:

```text
shallow
medium
deep
```

Measure runtime and path counts.

---

## Phase 6 — External AI planner

Only after deterministic adaptive analysis works.

Implement:

```text
AnalysisPlanner
     ↓
Jev API client
```

Use a mock HTTP server for tests.

Test:

* success
* timeout
* connection failure
* authentication failure
* malformed response
* invalid plan
* oversized response
* rate limiting
* server error

---

## Phase 7 — AI validation/classification

Implement separately:

```text
Evidence
 ↓
FindingClassifier
 ↓
Jev API
```

Do not mix this with planning logic.

---

## Phase 8 — CLI configuration

Add:

```text
--analysis full|adaptive
--ai-planner
--ai-classifier
```

and corresponding configuration-file options.

---

## Phase 9 — MCP

Expose:

```text
scan
scan_diff
scan_file
get_analysis_plan
explain_finding
get_remediation
```

Ensure MCP calls the same `Scanner` service as the CLI.

---

## Phase 10 — Issue lifecycle

Only after scanning and MCP are stable:

```text
prepare_issue
create_issue
deduplication
```

---

# 33. Testing Strategy

The following test layers are mandatory.

## Unit

Test:

* AST parsing
* indexing
* source detection
* sink detection
* candidate discovery
* deterministic ranking
* analysis plans
* budgets
* flow analysis
* rules
* AI response validation
* fingerprints

## Integration

Test:

```text
source
→ AST
→ index
→ candidate
→ planner
→ deep SAST
→ finding
```

Then:

```text
source
→ AST
→ candidate
→ Jev planner
→ analysis plan
→ SAST
→ Jev classifier
→ finding
```

## Failure tests

Verify that:

```text
Jev unavailable
```

does not break optional-mode SAST.

---

# 34. Security Requirements

Never allow AI output to directly execute arbitrary operations.

AI output must be treated as untrusted data.

The AI may select only from predefined:

```text
analysis modes
depth ranges
vulnerability classes
candidate IDs
```

Never allow the model to:

* execute shell commands
* access arbitrary files
* modify source code
* make arbitrary HTTP requests
* create issues
* modify CI configuration

MCP write operations remain separately authorized.

---

# 35. Performance Goals

Measure:

```text
startup time
AST parsing time
indexing time
candidate discovery time
planning time
data-flow time
rule execution time
AI latency
total scan time
```

The optimization objective is not simply:

```text
minimum runtime
```

Instead measure:

```text
Detection coverage / compute cost
```

Track:

```text
precision
recall
F1
false positives
false negatives
CPU
memory
latency
```

---

# 36. Research Tasks

Before implementing the Jev client, investigate the current Jev API.

Determine:

* API endpoint
* authentication
* request schema
* response schema
* supported decision primitives
* model/version selection
* maximum input size
* rate limits
* timeout behavior
* deployment model
* licensing
* privacy/data-retention implications

Also investigate alternative System-One-style models/providers.

The architecture must not depend on Jev-specific semantics.

The generic abstraction should allow:

```text
Jev
Other System-One provider
Future local model
Deterministic planner
```

---

# 37. Important Architectural Constraint

Do not optimize prematurely.

The first working scanner should prove:

```text
AST
 ↓
candidate discovery
 ↓
deterministic planning
 ↓
deep SAST
 ↓
finding
```

Then demonstrate that AI planning can produce:

```text
same or acceptable security coverage
+
less expensive analysis
```

Only after this is demonstrated should AI-guided skipping/depth reduction become a default optimization.

---

# 38. Final Architecture

The target architecture should become:

```text
                         Source
                           |
                           v
                    ┌─────────────┐
                    │ AST / Parse │
                    └──────┬──────┘
                           |
                           v
                    ┌─────────────┐
                    │ Program     │
                    │ Index       │
                    └──────┬──────┘
                           |
                           v
                 ┌───────────────────┐
                 │ Candidate         │
                 │ Discovery         │
                 └─────────┬─────────┘
                           |
                           v
                 ┌───────────────────┐
                 │ Analysis Planner  │
                 │                   │
                 │ Deterministic     │
                 │        +          │
                 │ Optional AI/Jev   │
                 └─────────┬─────────┘
                           |
                 ┌─────────┼──────────┐
                 v         v          v
              Shallow    Medium      Deep
                 \         |          /
                  \        |         /
                   └───────┼────────┘
                           |
                           v
                  Security Rules
                           |
                           v
                       Evidence
                           |
                           v
                 ┌──────────────────┐
                 │ Optional AI      │
                 │ Classification   │
                 └────────┬─────────┘
                          |
                          v
                       Finding
                          |
             ┌────────────┼─────────────┐
             v            v             v
            CLI         SARIF          MCP
                                        |
                                        v
                                  Issue Provider
```

## Design Philosophy

The final system should answer four different questions with four different mechanisms:

```text
AST / Index:
"What exists in this program?"

SAST:
"What can this program actually do?"

AI Planner:
"Where should we spend our limited analysis budget?"

AI Classifier:
"What does this collected security evidence most likely represent?"
```

No single component should be responsible for all four.

The most important property of the architecture is that **removing the AI service must reduce optimization/intelligence, not eliminate the scanner's fundamental ability to detect vulnerabilities.**

The long-term goal is an adaptive SAST engine that can analyze large repositories more efficiently by allocating expensive static-analysis work toward the code paths most likely to contain meaningful security behavior, while retaining deterministic analysis as the security ground truth.
