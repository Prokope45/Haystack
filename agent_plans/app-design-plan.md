# AI-Assisted Static Security Scanner

## POC Design & Implementation Specification

## 1. Project Objective

Build a standalone, high-performance security scanner written in **Go** that combines traditional Static Application Security Testing (SAST) with an **optional external ML classification service** and an **MCP server for AI-agent integration**.

The scanner must be usable independently of any particular CI/CD platform and should support:

* Local developer workflows
* GitHub Actions
* Woodpecker CI
* GitLab CI
* Jenkins
* Other CI/CD systems
* AI coding agents through MCP

The scanner's core capability is language-aware static analysis using ASTs, semantic analysis, source/sink detection, data-flow analysis, and deterministic security rules.

An optional external classifier can enhance candidate findings by calling either:

* A separately deployed **Kev instance**
* A separately deployed **Jev instance**
* A future compatible classification service

The classifier is **not required** for SAST operation.

The MCP interface allows AI agents to:

1. Scan code they have created or modified.
2. Scan only a Git diff when appropriate.
3. Inspect and understand findings.
4. Obtain remediation information.
5. Create security issues for discovered vulnerabilities.
6. Avoid duplicate issues through stable finding fingerprints.
7. Optionally update or close issues after remediation.

---

# 2. Core Architectural Principles

## 2.1 SAST is the primary security engine

The scanner must be capable of identifying vulnerabilities without an ML classifier.

The core pipeline is:

```text
Source Code
    ↓
AST Parsing
    ↓
Semantic Analysis
    ↓
Source / Sink Detection
    ↓
Data-Flow Analysis
    ↓
Deterministic Security Rules
    ↓
SAST Findings
```

The classifier is an enhancement to this pipeline, not a dependency.

---

# 3. Optional Classifier Architecture

The classifier must be implemented as an **API client**, not as an embedded model.

The scanner must never:

* Bundle Kev model weights.
* Bundle Jev model weights.
* Perform local Kev inference.
* Perform local Jev inference.
* Depend on Python ML runtimes for classification.
* Require a GPU for normal SAST operation.

Instead:

```text
                     ┌──────────────────────┐
                     │      SAST Engine     │
                     └──────────┬───────────┘
                                │
                         Candidate Finding
                                │
                     ┌──────────▼───────────┐
                     │ Optional Classifier  │
                     │      API Client      │
                     └──────────┬───────────┘
                                │
                         HTTP/API Request
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
              Kev Service             Jev Service
```

The scanner should therefore support:

```text
SAST only
```

and:

```text
SAST + Kev
```

and:

```text
SAST + Jev
```

without changing the SAST implementation.

---

# 4. Classifier Interface

The scanner should expose a generic classifier abstraction.

Conceptually:

```go
type Classifier interface {
    Classify(
        context.Context,
        ClassificationInput,
    ) (ClassificationResult, error)
}
```

The implementation should distinguish the **classifier interface** from the **HTTP/API client**.

For example:

```text
internal/
└── classifier/
    ├── classifier.go
    └── api/
        └── client.go
```

The classifier API client should be configurable to point at a separately deployed service.

Conceptually:

```yaml
classifier:
  enabled: true
  provider: kev
  endpoint: "https://kev.example.com/api"
```

The exact configuration format should be determined during implementation.

---

# 5. Supported Classifier Providers

Initial conceptual providers:

```text
Kev
Jev
```

The scanner should not assume that the external service is necessarily hosted by the scanner project.

For example:

```text
scanner
   │
   │ HTTPS
   ▼
Kev deployment
```

or:

```text
scanner
   │
   │ HTTPS
   ▼
Jev deployment
```

The scanner only needs to understand the agreed API contract.

---

# 6. Classifier API Contract

Before implementing the client, the coding agent must research the actual Kev/Jev API contract.

Document:

* Endpoint
* HTTP method
* Authentication
* Request schema
* Response schema
* Error behavior
* Timeout behavior
* Rate limits
* Model/version identification
* Maximum input size
* Supported classification questions
* Probability format
* Health-check endpoint if available

The scanner should define an internal normalized API rather than leaking provider-specific schemas throughout the codebase.

For example:

```go
type ClassificationInput struct {
    Language string
    Question string
    Evidence Evidence
}

type ClassificationResult struct {
    Provider       string
    Model          string
    Label          string
    Probabilities  map[string]float64
    Metadata       map[string]any
}
```

The actual structures should be adapted to the researched API.

---

# 7. Classifier Disabled Behavior

This is a critical requirement.

If the classifier is disabled or unavailable, SAST must still work.

For example:

```bash
scanner .
```

should perform:

```text
File discovery
    ↓
AST
    ↓
Data flow
    ↓
Security rules
    ↓
Findings
```

No network request should be required.

If configured:

```bash
scanner . --classifier
```

the pipeline becomes:

```text
File discovery
    ↓
AST
    ↓
Data flow
    ↓
Security rules
    ↓
Candidate findings
    ↓
Classifier API
    ↓
Enhanced findings
```

---

# 8. Classifier Failure Policy

The scanner must have an explicit policy for classifier failures.

For example:

```text
SAST finding exists
        ↓
Classifier unavailable
        ↓
Should scanner fail?
```

Default behavior should be configurable.

Recommended conceptual modes:

```text
optional
required
disabled
```

### `disabled`

Never call the classifier.

### `optional`

Attempt classification.

If the classifier is unavailable:

```text
SAST continues
```

### `required`

Failure to reach the classifier causes an appropriate scanner error.

This allows CI environments to choose their desired behavior.

---

# 9. Classifier Timeout

The classifier API must have an explicit timeout.

For example:

```text
SAST
  ↓
Candidate
  ↓
HTTP request
  ↓
timeout
  ↓
fallback to unclassified SAST finding
```

The scanner should never hang indefinitely waiting for an external classifier.

---

# 10. SAST and Classifier Responsibility

The responsibilities should remain clearly separated.

### SAST determines:

* What code is doing.
* Where input originates.
* Where input flows.
* What operation receives it.
* Which security rules are triggered.
* Source location.
* Static evidence.

### Kev/Jev determines:

* Classification of security evidence.
* Security relevance.
* Vulnerability category.
* Classification probabilities.
* Other model-specific decisions supported by the external service.

### Intelligence providers determine:

* CWE metadata.
* CVE information.
* OSV advisories.
* CVSS.
* CISA KEV status.
* Authoritative remediation information.

This gives:

```text
SAST
  ↓
Evidence
  ↓
Optional Classifier
  ↓
Classification
  ↓
Security Intelligence
  ↓
Finding
```

---

# 11. High-Level Architecture

```text
                         Source Repository
                                │
                                ▼
                     ┌────────────────────┐
                     │ File Discovery     │
                     └─────────┬──────────┘
                               │
                               ▼
                     ┌────────────────────┐
                     │ Language Detector  │
                     └─────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
              Go Analyzer          Python Analyzer
                    │                     │
                    └──────────┬──────────┘
                               ▼
                    ┌────────────────────┐
                    │ Common Evidence    │
                    │ Representation     │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │ Data-Flow Engine    │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │ Security Rules     │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │ Candidate Findings │
                    └─────────┬──────────┘
                              │
                    ┌─────────┴──────────┐
                    │ Optional           │
                    │ Classifier         │
                    └─────────┬──────────┘
                              │
                    HTTP/API │
                              ▼
                    ┌────────────────────┐
                    │ Kev / Jev Service  │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │ Finding Normalizer │
                    └─────────┬──────────┘
                              │
               ┌──────────────┼───────────────┐
               ▼              ▼               ▼
             CLI            JSON/SARIF        MCP
               │                              │
              CI/CD                       AI Agents
                                              │
                                     ┌────────┴─────────┐
                                     ▼                  ▼
                                Scan/Explain      Issue Provider
                                                        │
                                     ┌──────────────────┼─────────────┐
                                     ▼                  ▼             ▼
                                   GitHub             GitLab        Gitea
```

---

# 12. File Discovery

Responsibilities:

* Recursively discover source files.
* Respect configured exclusions.
* Ignore generated/vendor/build directories where appropriate.
* Determine supported language.
* Support future incremental/diff scanning.

Initial languages:

* Go
* Python

Future languages may include:

* JavaScript/TypeScript
* Java
* Rust
* C/C++
* C#

---

# 13. Language Analyzer Architecture

Each language should implement a common abstraction.

Conceptual interface:

```go
type Analyzer interface {
    Language() string
    Supports(path string) bool
    Analyze(
        context.Context,
        source []byte,
        path string,
    ) ([]Evidence, error)
}
```

Adding a language should not require rewriting the scanner core.

---

# 14. Go AST Analyzer

Use:

* `go/parser`
* `go/ast`
* `go/token`
* `go/types`

Analyze:

* Functions
* Parameters
* Variables
* Assignments
* Calls
* Returns
* Imports
* Struct fields
* Method calls
* Control-flow constructs
* Type information

Initial scope should favor simple intra-procedural analysis.

---

# 15. Python AST Analyzer

Research and select a reliable Go-compatible Python parser.

Candidates to evaluate include:

* Go-native Python parsers
* Python subprocess parsing
* Embedded Python
* Language-server/parser implementations

The preferred approach should:

* Preserve source locations.
* Avoid requiring Python at runtime if practical.
* Work reliably in a standalone scanner.
* Support future semantic analysis.

---

# 16. Common Evidence Model

Normalize language-specific behavior into common security concepts.

## Sources

Examples:

```text
HTTP_PARAMETER
CLI_ARGUMENT
ENVIRONMENT_VARIABLE
FILE_INPUT
FUNCTION_PARAMETER
NETWORK_INPUT
```

## Sinks

Examples:

```text
SHELL_EXECUTION
SQL_EXECUTION
FILE_ACCESS
PATH_OPERATION
DESERIALIZATION
HTML_RENDERING
NETWORK_REQUEST
```

## Transformations

Examples:

```text
ASSIGNMENT
STRING_CONCATENATION
FORMAT_STRING
FUNCTION_CALL
TYPE_CONVERSION
ARGUMENT_PASSING
```

Example:

```text
HTTP_PARAMETER
      ↓
VARIABLE
      ↓
STRING_CONCATENATION
      ↓
SHELL_EXECUTION
```

---

# 17. Data-Flow Engine

The initial implementation should support:

```text
Source
  ↓
Assignment
  ↓
Transformation
  ↓
Sink
```

The primary question is:

> Does attacker-controlled input reach a dangerous operation?

Do not initially implement full interprocedural analysis.

Future capabilities:

* Control-flow graphs
* Interprocedural analysis
* Type propagation
* Taint propagation
* Alias analysis
* Function summaries
* Incremental analysis

---

# 18. Security Rule Engine

Rules operate on normalized evidence.

Conceptual interface:

```go
type Rule interface {
    ID() string
    Name() string
    Analyze(
        context.Context,
        []Evidence,
    ) ([]Candidate, error)
}
```

Initial vulnerability classes:

1. Command Injection
2. SQL Injection
3. Path Traversal
4. Hardcoded Secrets
5. Unsafe Deserialization

The first complete vertical slice should implement only **Command Injection**.

---

# 19. Command Injection Vertical Slice

Example:

```go
func runCommand(input string) error {
    cmd := exec.Command("sh", "-c", input)
    return cmd.Run()
}
```

Evidence:

```text
function parameter
       ↓
input
       ↓
exec.Command
       ↓
shell execution
```

Candidate:

```json
{
  "file": "commands.go",
  "line": 12,
  "sink": "os/exec.Command",
  "source": "function parameter",
  "flow": "parameter -> string argument -> shell execution"
}
```

Safe examples must also be supported.

---

# 20. Optional Classifier Pipeline

When disabled:

```text
Candidate
   ↓
Finding
```

When enabled:

```text
Candidate
   ↓
ClassificationInput
   ↓
Classifier API Client
   ↓
Kev/Jev
   ↓
ClassificationResult
   ↓
Finding
```

The scanner should not assume classification is always successful.

---

# 21. Focused Classification Input

Do not send entire repositories to the classifier.

Send focused evidence.

Example:

```json
{
  "language": "go",
  "question": "Does attacker-controlled input reach shell execution?",
  "evidence": {
    "source": "function parameter",
    "sink": "os/exec.Command",
    "flow": [
      "input",
      "exec.Command",
      "sh -c"
    ]
  }
}
```

The exact payload must conform to the selected Kev/Jev API.

---

# 22. Classification Output

Preserve raw probabilities where the external service provides them.

Example:

```json
{
  "provider": "kev",
  "model": "example-model",
  "label": "command_injection",
  "probabilities": {
    "command_injection": 0.94,
    "safe_command_execution": 0.03,
    "other_security_issue": 0.02,
    "uncertain": 0.01
  }
}
```

The scanner should preserve:

* Provider
* Model/version
* Label
* Probabilities
* Request/response metadata where useful

Do not convert model confidence directly into CVSS.

---

# 23. Finding Model

Conceptual model:

```go
type Finding struct {
    ID          string
    Fingerprint string

    File        string
    Line        int
    Column      int

    Category    string
    CWE         []string

    Severity    Severity
    Confidence  float64

    Evidence    []Evidence

    Description string
    Remediation string

    References  []Reference

    Classification *ClassificationResult
}
```

`Classification` should be optional.

A valid finding must be able to exist with:

```go
Classification == nil
```

---

# 24. Finding Confidence

Distinguish:

```text
SAST confidence
Classifier confidence
```

where appropriate.

Do not conflate:

```text
classifier probability
```

with:

```text
CVSS severity
```

A finding may therefore contain:

```text
Static analysis evidence
Classifier result
Confidence
Severity
```

as separate concepts.

---

# 25. CWE Integration

Source-code findings should primarily map to CWE.

Examples:

```text
Command Injection → CWE-78
SQL Injection → CWE-89
Path Traversal → CWE-22
```

Research an authoritative CWE source before implementation.

---

# 26. CVE / OSV / CVSS / CISA KEV

Keep dependency intelligence separate from SAST.

For dependency vulnerabilities:

```text
Manifest
   ↓
Package/version
   ↓
OSV
   ↓
CVE/advisory
   ↓
CVSS
   ↓
Affected/fixed versions
```

CISA KEV may provide an additional known-exploitation signal.

Do not assign CVEs to arbitrary SAST findings.

---

# 27. Remediation Engine

For SAST:

```text
CWE
 ↓
secure coding guidance
 ↓
remediation
```

For dependency findings:

```text
OSV/CVE
 ↓
affected version
 ↓
fixed version
 ↓
upgrade recommendation
```

The classifier must not be responsible for inventing authoritative remediation information.

---

# 28. Scanner Service

The CLI and MCP must both call the same scanner abstraction.

Conceptually:

```go
type Scanner interface {
    Scan(
        context.Context,
        ScanRequest,
    ) (*ScanResult, error)
}
```

Example:

```go
type ScanRequest struct {
    Paths       []string
    GitBase     string
    GitHead     string
    Languages   []string
    Confidence  float64
}
```

Example:

```go
type ScanResult struct {
    Findings []Finding
    Stats    ScanStats
}
```

---

# 29. Diff Scanning

Support:

```bash
scanner --diff HEAD~1
```

and eventually:

```bash
scanner --diff main...HEAD
```

Diff scanning should be a first-class capability because it is particularly useful for AI agents.

---

# 30. CLI

Examples:

```bash
scanner .
scanner ./src
scanner . --format json
scanner . --diff HEAD~1
scanner . --fail-on high
```

Classifier-enabled examples:

```bash
scanner . --classifier
scanner . --classifier-provider kev
scanner . --classifier-endpoint https://kev.example.com/api
```

The exact CLI options should be finalized after the API contract is researched.

Options should include:

```text
--format text|json|sarif
--severity low|medium|high|critical
--confidence 0.80
--fail-on high
--exclude path
--config path
--no-color
--verbose
--diff <git-range>
--classifier
--classifier-provider
--classifier-endpoint
--version
```

---

# 31. Exit Codes

```text
0 = no findings above threshold
1 = findings exceeded threshold
2 = configuration error
3 = source parsing error
4 = internal error
```

Classifier failure behavior should depend on classifier mode.

For example, optional mode may still return exit code `0/1` based on SAST results even if the classifier service is unavailable.

---

# 32. Output Formats

## Human-readable

Example:

```text
HIGH CWE-78 Command Injection

internal/handlers.go:42

User-controlled HTTP input reaches shell execution.

SAST evidence:
  r.URL.Query()
      ↓
  command
      ↓
  exec.Command("sh", "-c", command)

Classifier:
  Provider: Kev
  Confidence: 97%
```

If classification is disabled:

```text
Classifier: disabled
```

If unavailable in optional mode:

```text
Classifier: unavailable
```

The finding must still be reported.

## JSON

Include complete scanner and classifier metadata where available.

## SARIF

Add after the core finding model stabilizes.

---

# 33. MCP Server

MCP provides an agent-facing interface to the scanner.

It must use the same `Scanner` service as the CLI.

```text
AI Agent
   ↓
MCP
   ↓
Scanner
```

The MCP server must not contain duplicate AST, data-flow, rule, or classification logic.

---

# 34. MCP Tools

Initial tools:

### `scan`

Full project scan.

### `scan_diff`

Scan code modified between two Git references.

This should be the primary AI-agent workflow.

### `scan_file`

Scan an individual file.

### `explain_finding`

Explain:

* Source
* Sink
* Data flow
* Rule
* CWE
* Classifier result
* Source location

### `get_remediation`

Return remediation guidance.

### `get_security_status`

Return repository security status.

---

# 35. MCP Classifier Behavior

MCP must not directly interact with Kev/Jev.

The call chain remains:

```text
Agent
 ↓
MCP
 ↓
Scanner
 ↓
SAST
 ↓
Optional Classifier API
 ↓
Kev/Jev
```

This ensures CLI and MCP produce equivalent findings.

---

# 36. MCP Issue Creation

Issue creation must be a separate operation from scanning.

Primary workflow:

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

Scanning must not automatically create external issues unless an explicit policy is configured.

---

# 37. `prepare_issue`

Convert a finding into a proposed issue.

Example:

```text
prepare_issue(finding_id)
```

Returns:

```json
{
  "title": "Security: Command injection in handlers.go",
  "body": "...",
  "labels": [
    "security",
    "vulnerability",
    "CWE-78"
  ]
}
```

No external side effect should occur.

---

# 38. `create_issue`

Create an issue from a finding.

Conceptual interface:

```text
create_issue(
    finding_id,
    additional_context?
)
```

The generated issue should include:

* Vulnerability category
* CWE
* Severity
* Confidence
* Source location
* Evidence
* Data-flow path
* Remediation
* Scanner finding ID
* Stable fingerprint
* References
* Classifier information where appropriate

---

# 39. Issue Provider Abstraction

Do not hard-code GitHub into the scanner.

Conceptual interface:

```go
type IssueProvider interface {
    CreateIssue(
        context.Context,
        IssueRequest,
    ) (*Issue, error)

    UpdateIssue(
        context.Context,
        IssueID,
        IssueUpdate,
    ) error

    CloseIssue(
        context.Context,
        IssueID,
    ) error
}
```

Potential providers:

```text
GitHub
GitLab
Gitea
Forgejo
```

Implement one provider initially while preserving the abstraction.

---

# 40. Issue Deduplication

Use the stable finding fingerprint.

Workflow:

```text
Finding fingerprint
       ↓
Search existing issues
       ↓
Existing issue?
    /        \
  yes         no
   │           │
return       create
existing
issue
```

The issue should include:

```text
Scanner-Finding: SEC-001
Scanner-Fingerprint: a83c...91f
```

Repeated scans should not create duplicate issues.

---

# 41. Issue Lifecycle

Eventually support:

```text
Finding
   ↓
Issue created
   ↓
Code modified
   ↓
scan_diff
   ↓
Finding still exists?
   ├── yes → issue remains
   └── no  → optionally close/update issue
```

Automatic closing must be configurable.

Default behavior should be conservative.

---

# 42. MCP Security Model

Separate read and write tools.

### Read-only

```text
scan
scan_diff
scan_file
explain_finding
get_remediation
get_security_status
```

### Write

```text
create_issue
update_issue
close_issue
```

Write capabilities must require explicit authorization.

The scanner should follow least-privilege principles.

---

# 43. Agent Security Feedback Loop

The intended workflow:

```text
Agent receives task
       ↓
Agent modifies code
       ↓
MCP scan_diff()
       ↓
Scanner
       ↓
SAST
       ↓
Optional Kev/Jev API
       ↓
Finding
       ↓
┌──────────────────┐
│ Vulnerability?   │
└────────┬─────────┘
         │
     ┌───┴───┐
     │       │
    No      Yes
     │       │
     │       ▼
     │  explain_finding()
     │       │
     │       ▼
     │  prepare_issue()
     │       │
     │       ▼
     │  create_issue()
     │       │
     │       ▼
     │  Agent fixes code
     │       │
     └───────┤
             ▼
        scan_diff()
             │
             ▼
          resolved
```

This creates a security feedback loop for AI coding agents.

---

# 44. Repository Structure

Recommended:

```text
scanner/
├── cmd/
│   ├── scanner/
│   │   └── main.go
│   └── scanner-mcp/
│       └── main.go
│
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go
│   │   ├── go/
│   │   │   ├── parser.go
│   │   │   ├── sources.go
│   │   │   ├── sinks.go
│   │   │   └── analyzer.go
│   │   └── python/
│   │       ├── parser.go
│   │       ├── sources.go
│   │       ├── sinks.go
│   │       └── analyzer.go
│   │
│   ├── flow/
│   │   ├── graph.go
│   │   └── analyzer.go
│   │
│   ├── rules/
│   │   ├── rule.go
│   │   ├── command_injection.go
│   │   ├── sql_injection.go
│   │   └── path_traversal.go
│   │
│   ├── classifier/
│   │   ├── classifier.go
│   │   └── api/
│   │       └── client.go
│   │
│   ├── findings/
│   │   ├── finding.go
│   │   ├── fingerprint.go
│   │   └── normalize.go
│   │
│   ├── intelligence/
│   │   ├── cwe/
│   │   ├── osv/
│   │   ├── cve/
│   │   └── kev/
│   │
│   ├── scanner/
│   │   └── scanner.go
│   │
│   ├── issues/
│   │   ├── provider.go
│   │   ├── model.go
│   │   └── providers/
│   │       ├── github/
│   │       ├── gitlab/
│   │       └── gitea/
│   │
│   ├── mcp/
│   │   ├── server.go
│   │   ├── scan.go
│   │   ├── findings.go
│   │   └── issues.go
│   │
│   ├── config/
│   │   └── config.go
│   │
│   └── output/
│       ├── text.go
│       ├── json.go
│       └── sarif.go
│
├── testdata/
│   ├── go/
│   └── python/
│
├── examples/
│   ├── github-actions/
│   ├── woodpecker/
│   ├── gitlab/
│   └── mcp/
│
├── benchmarks/
├── docs/
├── go.mod
├── go.sum
└── README.md
```

---

# 45. Development Phases

## Phase 1 — Scanner Foundation

Implement:

* Go module
* CLI
* Configuration
* File discovery
* Language detection
* Scanner interface
* Basic result model

No classifier dependency.

---

## Phase 2 — Go AST

Implement:

* Go parsing
* AST traversal
* Source detection
* Sink detection
* Source locations
* Evidence normalization

---

## Phase 3 — Python AST

Research and implement Python parsing.

Ensure Go and Python produce compatible security evidence.

---

## Phase 4 — Data Flow

Implement basic intra-procedural data flow.

Success criterion:

```text
source
  ↓
variable
  ↓
transformation
  ↓
sink
```

---

## Phase 5 — First Security Rule

Implement command injection.

Create:

* Vulnerable fixtures
* Safe fixtures
* Unit tests
* Integration tests

At this point:

```bash
scanner .
```

must work **without any classifier service**.

---

# 46. Phase 6 — External Classifier API

Research and document:

* Kev API
* Jev API
* Authentication
* Request schema
* Response schema
* Timeouts
* Error behavior
* Model/version metadata
* Deployment requirements
* Licensing

Implement:

```text
Classifier interface
       ↓
HTTP API client
       ↓
configured external endpoint
```

Do not incorporate model inference into the scanner.

Success criteria:

```text
classifier disabled
    → scanner works

Kev configured
    → scanner calls Kev

Jev configured
    → scanner calls Jev

classifier unavailable + optional
    → scanner still produces SAST findings
```

---

# 47. Phase 7 — Finding Normalization

Implement:

* Finding IDs
* Stable fingerprints
* CWE
* Confidence
* Severity
* Evidence
* Remediation
* Classification metadata

---

# 48. Phase 8 — CLI / JSON / Diff

Implement:

* Human output
* JSON
* Exit codes
* Diff scanning
* Classifier configuration
* SARIF after the core model stabilizes

---

# 49. Phase 9 — MCP

Implement:

```text
scan
scan_diff
scan_file
explain_finding
get_remediation
get_security_status
```

All MCP operations must call the same scanner service.

Success criterion:

An AI coding agent can modify code and call `scan_diff`.

---

# 50. Phase 10 — Issue Integration

Implement:

```text
prepare_issue
create_issue
```

Then:

```text
update_issue
close_issue
```

Implement:

* IssueProvider
* One initial provider
* Authentication
* Stable finding fingerprints
* Duplicate detection
* Issue metadata
* Mock provider tests

---

# 51. Phase 11 — Additional SAST Rules

Add:

1. SQL Injection
2. Path Traversal
3. Hardcoded Secrets
4. Unsafe Deserialization

Each rule requires:

* Positive tests
* Negative tests
* CWE mapping
* Evidence generation
* Classifier evaluation
* Remediation guidance

---

# 52. Phase 12 — Dependency Intelligence

Add:

* Manifest detection
* Package/version extraction
* OSV
* CVE references
* CVSS
* CISA KEV
* Fixed-version guidance

Keep dependency scanning separate from SAST.

---

# 53. Testing Strategy

## Unit tests

Test:

* AST parsing
* Source detection
* Sink detection
* Data flow
* Rules
* Finding normalization
* Fingerprinting
* Classifier API client
* MCP handlers
* Issue providers

## Integration tests

Test:

```text
source
 ↓
AST
 ↓
data flow
 ↓
rule
 ↓
candidate
 ↓
optional classifier
 ↓
finding
 ↓
output
```

## Classifier tests

The scanner should support mocked classifier endpoints.

Test:

* Successful response
* Invalid response
* Timeout
* Connection failure
* Authentication failure
* HTTP 4xx
* HTTP 5xx
* Malformed model output
* Optional fallback
* Required failure

Do not make ordinary scanner tests dependent on a live Kev/Jev instance.

---

# 54. MCP Integration Tests

Test:

```text
MCP scan
MCP scan_diff
MCP scan_file
MCP explain_finding
MCP get_remediation
MCP prepare_issue
MCP create_issue
MCP update_issue
MCP close_issue
```

Use mock scanner and issue-provider implementations where appropriate.

---

# 55. Evaluation Metrics

### SAST detection

* Precision
* Recall
* F1
* False positives
* False negatives

### Classifier

* Classification accuracy
* Precision/recall by category
* Calibration where applicable
* Classification latency
* API failure rate

### Performance

* Files/second
* Lines/second
* Startup time
* Memory
* CPU
* AST time
* Data-flow time
* Classifier API latency
* Total scan time

### Agent workflow

* `scan_diff` latency
* MCP startup time
* Issue creation latency
* Duplicate issue prevention
* Number of scan/fix iterations

---

# 56. Caching

Consider caching after the first working implementation.

Potential cache key:

```text
file hash
+
AST version
+
rule version
+
classifier provider
+
classifier model/version
+
configuration
```

If the classifier is disabled, classifier information must not affect SAST cache validity.

If the classifier changes model/version, classification cache entries should be invalidated independently of AST analysis.

This allows:

```text
SAST result cache
+
classifier result cache
```

to be managed independently.

---

# 57. Parallelism

Eventually allow parallel file analysis.

Do not prematurely optimize before benchmarking.

The external classifier API may require its own concurrency/rate-limit controls.

The scanner should therefore have configurable classifier concurrency rather than blindly issuing one request per candidate simultaneously.

---

# 58. CI/CD Integration

The scanner remains CI/CD agnostic.

Example:

```bash
scanner . --format sarif --fail-on high
```

The classifier can optionally be enabled:

```bash
scanner . \
  --classifier \
  --classifier-provider kev \
  --fail-on high
```

CI environments should be able to run:

```text
SAST only
```

without requiring network access to Kev/Jev.

Alternatively, organizations can configure a private internal classifier service.

---

# 59. AI-Agent Example

An agent receives:

> Add a REST endpoint that executes a user-selected command.

The agent modifies:

```text
internal/api/handler.go
```

Then calls:

```text
scan_diff
```

The scanner performs:

```text
AST
 ↓
source/sink analysis
 ↓
data flow
 ↓
command injection rule
 ↓
candidate
 ↓
Kev API
 ↓
classification
 ↓
CWE-78
```

The MCP response contains:

```text
SEC-001
CWE-78
High
97% classifier confidence
```

The agent calls:

```text
explain_finding("SEC-001")
```

Then:

```text
prepare_issue("SEC-001")
```

The agent reviews the proposed issue.

Then:

```text
create_issue("SEC-001")
```

The issue provider creates the external security issue.

The agent fixes the code.

Finally:

```text
scan_diff
```

returns no corresponding finding.

---

# 60. Security Boundaries

The architecture should enforce four distinct trust boundaries:

```text
1. Source Code
       ↓
2. SAST Engine
       ↓
3. External Classifier
       ↓
4. External Issue Provider
```

The classifier is treated as an external dependency.

The issue provider is treated as an external side-effecting dependency.

Neither should be required for the scanner's fundamental SAST functionality.

---

# 61. Initial Scope Boundaries

Do not initially implement:

* Full interprocedural analysis
* Every CWE
* Every programming language
* Embedded ML models
* Local Kev inference
* Local Jev inference
* Complete CVE database
* Full dependency scanning
* Automatic issue closing
* Multiple issue providers
* Autonomous vulnerability remediation
* IDE integration
* Cloud-hosted scanner
* Distributed scanning
* Complex agent orchestration

The first vertical slice should be:

```text
Go/Python
   +
basic SAST
   +
one vulnerability class
   +
CLI
```

Then:

```text
optional external classifier
   +
Kev/Jev API
```

Then:

```text
MCP
   +
scan_diff
   +
issue creation
```

---

# 62. Research Tasks Before Implementation

The coding agent must research:

1. Current Kev project and API.
2. Current Jev project and API.
3. Kev/Jev authentication mechanisms.
4. Kev/Jev request schemas.
5. Kev/Jev response schemas.
6. Model/version identification.
7. API rate limits.
8. API timeout/retry recommendations.
9. Kev/Jev deployment requirements.
10. Kev/Jev licensing.
11. Best Go-compatible Python parser.
12. Authoritative CWE data source.
13. OSV API.
14. CVE/CVSS sources.
15. CISA KEV data.
16. Go MCP SDK options.
17. MCP transport options.
18. MCP authentication/security model.
19. GitHub issue API.
20. GitLab issue API.
21. Gitea issue API.
22. SARIF requirements.
23. CI runtime requirements.
24. Appropriate caching strategy.

Document research in:

```text
docs/architecture/
```

before permanently committing to implementation-specific decisions.

---

# 63. Recommended Implementation Order

```text
1. Repository/module setup
2. Core domain models
3. Scanner interface
4. File discovery
5. Go AST analyzer
6. Python AST analyzer
7. Evidence model
8. Basic data-flow engine
9. Command-injection rule
10. Finding model
11. CWE mapping
12. CLI output
13. JSON output
14. Diff scanning
15. Tests and benchmarks
16. Classifier interface
17. External classifier API client
18. Kev API integration
19. Jev API integration
20. Classifier configuration/fallback behavior
21. MCP server
22. scan / scan_diff tools
23. explain_finding
24. get_remediation
25. IssueProvider abstraction
26. prepare_issue
27. create_issue
28. Issue deduplication
29. Issue lifecycle operations
30. Additional SAST rules
31. OSV/dependency scanning
32. SARIF
33. CI/CD examples
```

---

# 64. Architectural End State

```text
                         ┌─────────────────────┐
                         │     AI Agent        │
                         └──────────┬──────────┘
                                    │
                                   MCP
                                    │
                 ┌──────────────────▼──────────────────┐
                 │             MCP Server               │
                 │                                      │
                 │ scan / scan_diff                     │
                 │ explain_finding                      │
                 │ get_remediation                      │
                 │ prepare_issue                        │
                 │ create_issue                         │
                 │ get_security_status                  │
                 └──────────────────┬───────────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Scanner Service   │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼────────────────────┐
              │                     │                    │
              ▼                     ▼                    ▼
        Go Analyzer          Python Analyzer       Future Analyzers
              │                     │
              └─────────────┬───────┘
                            ▼
                    ┌───────────────┐
                    │ Evidence/Data │
                    │ Flow Engine   │
                    └───────┬───────┘
                            ▼
                    ┌───────────────┐
                    │ Security Rules│
                    └───────┬───────┘
                            ▼
                    ┌───────────────┐
                    │ Candidate     │
                    │ Findings      │
                    └───────┬───────┘
                            │
                       Optional
                            │
                            ▼
                 ┌───────────────────────┐
                 │ Classifier API Client│
                 └───────────┬───────────┘
                             │
                       HTTP/API
                             │
                    ┌────────┴─────────┐
                    ▼                  ▼
                Kev Service        Jev Service
                    │                  │
                    └────────┬─────────┘
                             ▼
                    ┌────────────────┐
                    │ Classification │
                    │ Result         │
                    └───────┬────────┘
                            ▼
                    ┌───────────────┐
                    │ Finding       │
                    │ Normalizer    │
                    └───────┬───────┘
                            │
              ┌─────────────┼────────────────┐
              ▼             ▼                ▼
            CLI          JSON/SARIF      IssueProvider
                                             │
                                  ┌──────────┼──────────┐
                                  ▼          ▼          ▼
                               GitHub      GitLab     Gitea
```

---

# 65. Core Design Philosophy

The system should ultimately maintain this separation:

```text
SAST
"What is the code doing?"

       ↓

Security Rules
"Does this behavior match a known dangerous pattern?"

       ↓

Optional Kev/Jev
"What does this security evidence represent?"

       ↓

Security Intelligence
"What CWE/advisory/remediation information applies?"

       ↓

CLI / CI
"Should this scan/build pass?"

       ↓

MCP
"How can an AI agent interact with the scanner?"

       ↓

Issue Provider
"How should discovered vulnerabilities become tracked work?"
```

The critical architectural property is that **the bottom layers remain independently useful**.

A developer can use:

```text
scanner .
```

without any classifier.

A CI pipeline can use:

```text
scanner . --fail-on high
```

without any external ML service.

An organization can optionally deploy:

```text
Kev service
```

or:

```text
Jev service
```

and configure the scanner to use it.

An AI agent can then access the exact same scanner through:

```text
MCP
```

and, when authorized, turn findings into tracked issues.

The resulting system is therefore a **standalone language-aware SAST engine with optional external ML classification and an agent-native security feedback loop**, rather than a scanner whose operation depends on an embedded AI model.
