Below is a design plan written so an OpenCode/coding agent can use it as an implementation specification. It assumes the existing scanner, adaptive analysis, caching, MCP, and finding models remain the source of truth.

# Dynamic Interactive Terminal UI

## Design & Implementation Plan

## 1. Objective

Upgrade the scanner's existing CLI output into an optional, dynamic terminal user interface (TUI) that allows users to observe the security analysis as it happens.

The TUI should communicate:

* Overall scan progress.
* Current analysis phase.
* Files and functions discovered.
* Candidates identified.
* Adaptive analysis decisions.
* Current analysis target.
* Data-flow paths being investigated.
* Cached versus newly analyzed work.
* Skipped/dead/unreachable code.
* Vulnerabilities as they are discovered.
* Finding details and evidence.
* Final scan statistics.

The TUI must remain an **observational layer**.

It must never control or alter the security-analysis logic.

The scanner must remain fully functional without the TUI for:

* CI/CD.
* JSON output.
* SARIF output.
* MCP.
* Non-TTY environments.
* Automated testing.

---

# 2. Core Design Principle

The scanner should expose its internal progress through a structured event/state system.

Architecture:

```text
                         Scanner Engine
                              │
                    ┌─────────┴─────────┐
                    │                   │
               Scan State          Scan Events
                    │                   │
                    └─────────┬─────────┘
                              │
                       Presentation Layer
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
             TUI             JSON             MCP
              │
              ▼
      Terminal Renderer
```

Do not implement the TUI by inserting terminal rendering calls throughout the analyzer.

Instead, analysis components emit structured events and update shared scan state.

---

# 3. TUI Activation

The TUI should be optional.

Normal command:

```bash
scanner scan .
```

should preserve the existing non-interactive output behavior unless the project decides that interactive TTY mode should become the default.

Explicit TUI:

```bash
scanner scan . --visual
```

or:

```bash
scanner scan . --tui
```

Choose the flag consistent with the existing CLI conventions.

Recommended initial behavior:

```text
TTY + no explicit output format
    → interactive TUI

non-TTY
    → standard CLI output

--format json
    → JSON output

--format sarif
    → SARIF output

--no-tui
    → standard CLI output
```

The TUI must automatically disable itself when stdout is not a terminal.

This prevents CI logs from being filled with ANSI cursor-control sequences.

---

# 4. TUI Architecture

Create a dedicated presentation package.

Suggested structure:

```text
internal/
├── tui/
│   ├── app.go
│   ├── model.go
│   ├── state.go
│   ├── events.go
│   ├── renderer.go
│   ├── layout.go
│   ├── graph.go
│   ├── header.go
│   ├── footer.go
│   ├── details.go
│   ├── findings.go
│   ├── styles.go
│   ├── input.go
│   └── tui_test.go
│
├── analysis/
├── ast/
├── cache/
├── findings/
└── ...
```

The exact structure may be adapted to the existing repository.

The TUI package must not contain security-analysis logic.

---

# 5. Analysis Event System

Introduce a structured analysis-event system.

Example:

```go
type AnalysisEvent struct {
    Type      EventType
    Timestamp time.Time

    NodeID    string
    File      string
    Function  string

    Status    NodeStatus

    Finding   *Finding

    Progress  ProgressState

    Metadata  map[string]any
}
```

Possible event types:

```text
scan.started
scan.completed

phase.started
phase.completed

file.discovered
file.indexed

function.discovered

candidate.discovered
candidate.prioritized

analysis.started
analysis.progress
analysis.completed

flow.started
flow.step
flow.completed

node.cached
node.skipped
node.unreachable

finding.discovered

classification.started
classification.completed

cache.hit
cache.miss
```

Events should be immutable once emitted.

---

# 6. Scan State

Maintain a central state object representing the current scan.

Example:

```go
type ScanState struct {
    Phase       Phase
    Progress    float64

    Files       FileStats
    Functions   FunctionStats
    Candidates  CandidateStats
    Analysis    AnalysisStats
    Cache       CacheStats
    Findings    FindingStats

    CurrentNode *GraphNode
    CurrentPath []GraphNode

    FindingsList []Finding
}
```

The TUI renders this state.

The analyzer should not depend on the TUI.

---

# 7. Scan Phases

Represent scanning as explicit phases.

Recommended phases:

```text
DISCOVERY
INDEXING
CANDIDATE_DETECTION
ADAPTIVE_PLANNING
DEEP_ANALYSIS
CLASSIFICATION
FINALIZATION
COMPLETE
```

The header should display the current phase.

Example:

```text
Phase: Deep Analysis
```

Transitions should generate events:

```text
phase.started
phase.completed
```

---

# 8. Persistent Header

The header should remain visible while the graph changes.

Example:

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ Scanner • Adaptive Security Analysis                         73%  00:12  │
│                                                                          │
│ Files       37 / 84       Functions   421 / 910       Candidates      23 │
│ Analyzed    31            Deep          7             Findings         1 │
│ Cached      29                                                             │
│                                                                          │
│ ████████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░  73%   │
└──────────────────────────────────────────────────────────────────────────┘
```

The header should update without causing terminal scrolling.

---

# 9. Progress Calculation

Do not calculate progress solely from files scanned.

The scanner performs multiple forms of work.

Use a weighted phase model.

Initial weights:

```text
Discovery           10%
Indexing            10%
Candidate Detection 15%
Adaptive Planning   15%
Deep Analysis       35%
Classification      10%
Finalization         5%
```

These values should be configurable internally and refined through benchmarking.

Within each phase, calculate progress using the work units available to that phase.

The UI should show both:

```text
overall progress
```

and:

```text
current phase
```

Example:

```text
Phase: Deep Analysis

██████████████████████████████░░░░░░░░░░  78%
```

---

# 10. Security-Relevant Graph

The graph should not attempt to render the complete AST.

A large repository may contain thousands of functions and millions of AST nodes.

Instead, expose a security-oriented graph containing:

* Entry points.
* Sources.
* Sinks.
* Security-sensitive functions.
* Functions participating in candidate flows.
* Important transformations.
* Reachability relationships.
* Findings.
* Current analysis path.

Example:

```text
HTTP Request
      │
      ▼
Run()
      │
      ▼
r.URL.Query().Get()
      │
      ▼
c
      │
      ▼
exec.Command()
      │
      ▼
Shell Execution
```

The internal analyzer may maintain a much larger graph.

The TUI should render a projection of the graph.

---

# 11. Graph Node States

Nodes should have explicit states.

Recommended:

```text
○ discovered
◉ analyzing
✓ clear
! finding
◆ cached
· skipped
× unreachable
```

Possible state transitions:

```text
discovered
    ↓
queued
    ↓
analyzing
    ↓
clear
```

or:

```text
analyzing
    ↓
finding
```

or:

```text
discovered
    ↓
cached
```

or:

```text
discovered
    ↓
unreachable
```

---

# 12. Color Usage

Use color as an enhancement, not the only indication of state.

Suggested semantics:

```text
neutral     discovered
blue        queued
yellow      analyzing
green       clear
red         finding
dim         skipped/unreachable
cyan        cached
```

Every state must also have a symbol/text representation so the TUI remains usable in terminals with limited color support.

Example:

```text
✓ clear
◆ cached
! finding
· skipped
```

---

# 13. Current Analysis Panel

The bottom/details region should show what the scanner is currently doing.

Example:

```text
Current: internal/handlers/command.go

Strategy: adaptive
Priority: 85
Depth: 6

Reason:
  HTTP input → shell execution

Following:

  r.URL.Query().Get()
          ↓
        c
          ↓
  exec.Command("sh", "-c", c)
```

This is particularly important because it exposes the adaptive-analysis architecture.

---

# 14. Adaptive Analysis Visualization

When the planner prioritizes a candidate, display the decision.

Example:

```text
Candidate: command.go:6

Priority: 85
Depth: 6
Strategy: adaptive

Reason:
  Source reaches shell execution sink
```

For lower-priority candidates:

```text
Candidate: health.go:22

Priority: 14
Action: shallow analysis

Reason:
  No security-sensitive sink detected
```

For skipped candidates:

```text
Candidate: legacy.go:91

Priority: 8
Action: skipped

Reason:
  Unreachable code
```

The TUI should make it obvious that the scanner is **allocating analysis effort**, rather than blindly scanning every path equally.

---

# 15. Candidate View

Provide a candidate-oriented view.

Example:

```text
CANDIDATES

✓ HTTP input                    priority 72
✓ Database query                priority 64
◉ Shell execution               priority 95
· File operation                priority 21
· Template rendering            priority 18
```

Possible interactions:

```text
↑/↓     select candidate
Enter   inspect candidate
```

The selected candidate should update the details panel.

---

# 16. Data-Flow View

When analyzing a security candidate, show the active path.

Example:

```text
DATA FLOW

HTTP Input
    │
    ▼
r.URL.Query().Get
    │
    ▼
variable: c
    │
    ▼
exec.Command
    │
    ▼
sh -c
    │
    ▼
Shell Execution
```

The current node should be highlighted.

As the analysis progresses, the active path should grow.

---

# 17. Finding Discovery

When a finding is discovered, add it to the graph and findings list.

Example:

```text
! HIGH  OS Command Injection
    CWE-78
    internal/handlers/command.go:6
```

The graph should retain the finding after the discovery animation completes.

The scanner should not erase findings when moving to another candidate.

---

# 18. Finding Details

Selecting a finding should show:

```text
FINDING

HIGH
OS Command Injection

File:
  internal/handlers/command.go

Line:
  6

CWE:
  CWE-78

Confidence:
  100%

Strategy:
  adaptive

Priority:
  85

Depth:
  6
```

Then:

```text
Evidence Flow:

r.URL.Query().Get
        ↓
       c
        ↓
exec.Command("sh", "-c", c)
```

Then:

```text
Recommendation:

Avoid invoking a shell with untrusted input.
Prefer direct process execution with explicit arguments.
```

The existing `Finding` model should be reused.

Do not duplicate finding data specifically for the TUI.

---

# 19. Finding Focus Mode

When a finding is selected, allow the user to focus the graph on that vulnerability.

Example:

```text
HTTP Request
      │
      ▼
Query Parameter
      │
      ▼
Run()
      │
      ▼
exec.Command()
      │
      ▼
! CWE-78
```

This should hide unrelated graph nodes while preserving the ability to return to the full graph.

Suggested controls:

```text
Enter  Focus
Esc    Return
```

---

# 20. Cache Visualization

Cached analysis should be visible.

Example:

```text
◆ auth.go
◆ users.go
◉ command.go
```

Header:

```text
Cached: 29
```

Optional details:

```text
Cache

AST          31 hits
SAST          8 hits
Planner       7 hits
Classifier    4 hits
```

Do not make cache information dominate the UI.

It should communicate why work was skipped/reused without overwhelming the user.

---

# 21. Dead-Code / Unreachable Visualization

When reachability analysis determines code is not relevant:

```text
debug.go       · unreachable
legacy.go      · unreachable
health.go      ✓ clear
command.go     ◉ analyzing
```

Selecting the node should show:

```text
Status: Unreachable

Reason:
  No reachable callers from application entry points.
```

The TUI must distinguish:

```text
not analyzed
```

from:

```text
analyzed and determined irrelevant
```

and:

```text
cached
```

These are different states.

---

# 22. Findings Panel

Provide a dedicated findings view.

Example:

```text
FINDINGS

! HIGH     OS Command Injection        CWE-78
! MEDIUM   SQL Injection               CWE-89
```

Selecting a finding opens its details.

The header should continuously display the total finding count.

---

# 23. Keyboard Interaction

Provide a minimal keyboard interface.

Recommended:

```text
↑ / ↓       Navigate
Enter       Select / focus
Esc         Return
Tab         Change panel
g           Graph
f           Findings
c           Candidates
d           Details
p           Pause / resume
r           Resume/reset view
?           Help
q           Quit
```

The exact key bindings can be adapted to the selected TUI framework.

Avoid excessive controls.

The primary purpose is observation.

---

# 24. Pause / Resume

Allow the user to pause the visualization.

Important:

**Pause should pause rendering, not necessarily analysis.**

Two modes can be considered:

```text
visualization paused
```

versus:

```text
scanner paused
```

For the initial implementation, only pause the UI update/rendering.

Do not add scanner execution pausing unless there is a compelling requirement.

---

# 25. Terminal Resizing

The TUI must react to terminal resize events.

Minimum behavior:

* Recalculate layout.
* Re-render graph.
* Reflow text.
* Prevent clipping.
* Preserve current selected node.

For narrow terminals, degrade gracefully.

Example:

```text
Wide terminal:
    graph + details

Medium terminal:
    graph
    details below

Narrow terminal:
    summary + current operation
```

Never allow the TUI to corrupt the terminal.

---

# 26. Non-TTY Behavior

The TUI must never activate when output is redirected.

For example:

```bash
scanner scan . > scan.log
```

must produce ordinary output.

Likewise:

```bash
scanner scan . --format json
```

must never emit TUI control sequences.

GitHub Actions, Woodpecker, GitLab CI, and other CI environments should remain compatible.

---

# 27. TUI Lifecycle

Recommended lifecycle:

```text
Initialize terminal
        ↓
Create ScanState
        ↓
Start event consumer
        ↓
Start scanner
        ↓
Render initial UI
        ↓
Receive events
        ↓
Update state
        ↓
Render
        ↓
Scanner completes
        ↓
Render final state
        ↓
Wait for exit
        ↓
Restore terminal
        ↓
Return exit code
```

If the scanner fails:

```text
scanner error
    ↓
render error state
    ↓
restore terminal
    ↓
return original error code
```

The terminal must always be restored even when analysis fails or the user exits.

---

# 28. Rendering Frequency

Do not redraw for every internal event if event volume becomes excessive.

Use a render loop.

Example target:

```text
30–60 FPS maximum
```

For a CLI scanner, approximately:

```text
10–30 FPS
```

is likely sufficient.

Events should update state immediately, but rendering should be throttled/coalesced.

This prevents the TUI from consuming significant CPU while the scanner is working.

---

# 29. Event Batching

If a large repository generates thousands of events quickly, batch them.

For example:

```text
100 function.discovered events
```

should not necessarily cause:

```text
100 terminal redraws
```

Instead:

```text
events
  ↓
state updates
  ↓
single render
```

This is particularly important during:

* AST indexing.
* Candidate discovery.
* Repository traversal.

---

# 30. TUI Performance Requirements

The TUI must not materially slow down scanning.

Target:

```text
TUI overhead < 5% of total scan time
```

where practical.

Benchmark:

```text
headless scan
versus
TUI scan
```

on representative repositories.

The scanner's analysis performance remains the priority.

---

# 31. Terminal Graph Rendering

Initially implement a simple graph renderer.

Do not attempt sophisticated automatic graph layout immediately.

Start with:

```text
tree / directed-path representation
```

for active security paths.

Example:

```text
server.go
  │
  └── handler()
       │
       └── Query.Get()
            │
            └── exec.Command()
```

Later, implement a more general graph layout if needed.

The initial implementation should prioritize readability over mathematical graph-layout sophistication.

---

# 32. Graph View Modes

Eventually support:

```text
g → Graph
```

with possible modes:

```text
Security Path
Call Graph
Source → Sink
Candidate Graph
Finding Graph
```

Do not implement all modes in the first iteration.

Recommended first version:

```text
Security Path
```

because it directly supports the scanner's core security-analysis purpose.

---

# 33. Final Scan Screen

When scanning completes, preserve the TUI instead of immediately returning to a blank shell.

Example:

```text
Scanner • Scan Complete

Files       84
Functions   910
Candidates  37
Deep        14
Cached      42
Findings     2

HIGH       1
MEDIUM     1

Scan time: 16.482s
```

Then show the findings.

Possible controls:

```text
f  findings
g  graph
q  exit
```

---

# 34. Exit Behavior

On completion:

```text
successful scan with no findings
```

should exit with the scanner's existing success code.

If vulnerabilities meet the configured failure threshold:

```text
findings detected
```

the TUI should display them before returning the existing non-zero exit code.

The TUI must not alter the scanner's existing exit-code semantics.

---

# 35. Accessibility / Degraded Terminal Mode

The UI should work without color.

Provide a mode such as:

```text
--no-color
```

if the existing CLI supports it.

Symbols should communicate state:

```text
◉ analyzing
✓ clear
! finding
◆ cached
· skipped
× unreachable
```

Avoid relying solely on red/green.

---

# 36. Configuration

Potential configuration:

```yaml
tui:
  enabled: true
  refresh_rate: 20
  show_graph: true
  show_details: true
  show_cache: false
  color: true
```

Do not expose every possible rendering option initially.

Start with:

```text
--tui
--no-tui
```

and perhaps:

```text
--no-color
```

Expand configuration only when real use cases appear.

---

# 37. Testing Strategy

## Unit tests

Test:

* Event processing.
* State transitions.
* Progress calculation.
* Node status transitions.
* Finding insertion.
* Cache state transitions.
* Phase transitions.
* Selection logic.

Example:

```text
analysis.started
    ↓
node = ANALYZING
```

Then:

```text
analysis.completed
    ↓
node = CLEAR
```

And:

```text
finding.discovered
    ↓
node = FINDING
```

---

# 38. Integration Tests

Run a real scan with a mocked/event-observable analyzer.

Verify:

```text
scan.started
phase.started
file.discovered
candidate.discovered
analysis.started
analysis.completed
finding.discovered
scan.completed
```

Ensure the TUI state at the end matches the scanner's actual result.

---

# 39. Golden / Snapshot Tests

Where supported by the chosen TUI framework, create snapshot tests for important layouts.

Test:

```text
empty scan
normal scan
analysis in progress
finding discovered
multiple findings
narrow terminal
wide terminal
no-color terminal
final scan
```

Do not make snapshots overly dependent on exact timing.

---

# 40. Framework Selection

Before implementation, evaluate established Go TUI frameworks.

Candidates may include:

* Bubble Tea.
* tview.
* termui or similar maintained alternatives.

Select one based on:

* active maintenance,
* terminal rendering quality,
* input handling,
* resize support,
* testability,
* compatibility with the project's Go version,
* ease of graph rendering.

Do not implement a complete terminal UI framework from scratch.

---

# 41. MCP Compatibility

The event system should not be TUI-specific.

Long term:

```text
                    Analysis Events
                          │
            ┌─────────────┼─────────────┐
            ▼             ▼             ▼
           TUI           MCP        Event Log
```

MCP can eventually expose progress information such as:

```text
Phase: deep_analysis
Progress: 0.73
Current file: command.go
Current priority: 85
Findings: 1
```

Do not couple MCP implementation to the terminal renderer.

---

# 42. Logging Compatibility

The TUI should not interfere with normal application logging.

Separate:

```text
application logs
```

from:

```text
interactive rendering
```

Errors/debug logs should either:

* be buffered,
* be displayed in a dedicated log panel,
* or be disabled from the main screen unless explicitly requested.

Never allow ordinary log output to corrupt the TUI.

---

# 43. Security Considerations

The TUI displays source-code information.

Be careful when rendering:

* source snippets,
* filenames,
* user-controlled strings,
* AI-generated explanations,
* finding descriptions.

Never interpret source content as terminal control sequences.

Escape/sanitize terminal output appropriately.

A malicious string in source code must not be able to inject arbitrary ANSI terminal commands.

This is particularly important because the scanner analyzes potentially untrusted repositories.

---

# 44. Implementation Milestones

## Milestone 1 — Event Infrastructure

Implement:

* `AnalysisEvent`.
* Event types.
* `ScanState`.
* Event dispatcher/consumer.
* Phase tracking.

No sophisticated TUI yet.

Acceptance:

```text
scanner can execute while emitting structured analysis events.
```

---

## Milestone 2 — Basic TUI

Implement:

* Header.
* Progress bar.
* Phase.
* Counters.
* Footer.
* TTY detection.

Example:

```text
Scanner • Adaptive Analysis

Files 37/84
Functions 421/910
Candidates 23
Findings 1

██████████████████░░░░ 73%

Phase: Deep Analysis
```

---

## Milestone 3 — Dynamic Graph

Implement:

* Security graph.
* Node states.
* Active analysis path.
* Graph updates.

Acceptance:

The graph visibly changes as the scanner analyzes the repository.

---

## Milestone 4 — Adaptive Analysis Details

Display:

* Priority.
* Depth.
* Strategy.
* Analysis reason.
* Current candidate.

Example:

```text
Priority: 85
Depth: 6
Strategy: adaptive
Reason: HTTP input → shell execution
```

---

## Milestone 5 — Findings

Implement:

* Finding nodes.
* Finding list.
* Finding details.
* Evidence flow.
* Focus mode.

---

## Milestone 6 — Cache Visualization

Display:

* Cache hits.
* Cache misses where useful.
* Cached nodes.
* Cache statistics.

---

## Milestone 7 — Interaction

Add:

```text
navigation
selection
focus
graph/finding switching
help
```

---

## Milestone 8 — Production Hardening

Implement:

* Resize support.
* No-color mode.
* Non-TTY fallback.
* Event batching.
* Render throttling.
* Terminal restoration.
* Error handling.
* Snapshot tests.
* Performance benchmarks.

---

# 45. Example Target Experience

A scan should feel approximately like:

```text
Scanner • Adaptive Security Analysis

Phase: Candidate Detection

Files       62 / 84
Functions   712 / 910
Candidates  31
Deep         0
Findings     0

████████████████████████████░░░░░░░░░░  67%

──────────────────────────────────────────────────────────────────────

                    SECURITY GRAPH

server.go
   │
   ├── health.go                 ✓ clear
   │
   ├── auth.go                   ✓ clear
   │
   └── handlers/
        │
        ├── users.go             · low priority
        │
        └── command.go           ◉ analyzing
              │
              └── Query.Get()    ◉ source

──────────────────────────────────────────────────────────────────────

◉ analyzing  ✓ clear  ! finding  ◆ cached  · skipped  × unreachable

Current: handlers/command.go
Strategy: adaptive
Priority: 85
Depth: 6

Reason:
  HTTP input reaches shell execution sink
```

Then:

```text
Finding discovered
```

updates the same screen:

```text
command.go
    │
    ▼
Query.Get()
    │
    ▼
exec.Command()
    │
    ▼
! HIGH  CWE-78
```

The header changes:

```text
Findings 1
```

and the bottom panel changes:

```text
HIGH  OS Command Injection

handlers/command.go:6

Confidence: 100%

Evidence:
  Query.Get()
      ↓
      c
      ↓
  exec.Command("sh", "-c", c)
```

Finally:

```text
Scan Complete

Files       84
Functions   910
Candidates  37
Deep        14
Cached      42
Findings     1

Scan time: 16.482s
```

---

# 46. Non-TUI Output Must Remain Equivalent

The TUI is not a replacement for machine-readable output.

These must continue to work:

```bash
scanner scan .
scanner scan . --format json
scanner scan . --format sarif
scanner scan . --no-tui
```

The underlying `ScanResult` must be identical regardless of presentation mode.

Architecture:

```text
                  Scan Engine
                      │
                 ScanResult
                      │
          ┌───────────┼────────────┐
          ▼           ▼            ▼
         TUI         JSON         SARIF
```

Never:

```text
                  Scan Engine
                      │
                      ▼
                     TUI
                      │
                      ▼
                  ScanResult
```

The latter would make the TUI part of the scanner's core execution path.

---

# 47. Definition of Done

The TUI implementation is complete when:

* [ ] Scanner events are represented by structured types.
* [ ] Scan state is independent of presentation.
* [ ] TUI automatically detects interactive terminals.
* [ ] TUI can be explicitly enabled/disabled.
* [ ] Header displays live scan statistics.
* [ ] Progress updates dynamically.
* [ ] Scan phases are visible.
* [ ] Security-relevant graph updates during analysis.
* [ ] Nodes have visible analysis states.
* [ ] Current analysis target is displayed.
* [ ] Adaptive priority/depth are displayed.
* [ ] Data-flow paths can be visualized.
* [ ] Findings appear dynamically.
* [ ] Finding details can be inspected.
* [ ] Findings can be focused.
* [ ] Cached analysis is distinguishable.
* [ ] Dead/unreachable code is distinguishable.
* [ ] Keyboard navigation works.
* [ ] Terminal resizing works.
* [ ] Non-TTY output remains clean.
* [ ] JSON/SARIF output remains unaffected.
* [ ] Terminal is restored after errors.
* [ ] Untrusted source content cannot inject terminal control sequences.
* [ ] TUI performance overhead is measured.
* [ ] Unit/integration/snapshot tests exist.
* [ ] MCP remains independent of the TUI.
* [ ] Final scan results are identical with or without the TUI.

---

# 48. Long-Term Architecture

The final architecture should evolve toward:

```text
                           Scanner
                              │
                ┌─────────────┴─────────────┐
                │                           │
          Analysis State              Event Stream
                │                           │
                │                ┌──────────┼──────────┐
                │                │          │          │
                │                ▼          ▼          ▼
                │               TUI        MCP      Logging
                │
                ▼
        Security Analysis Graph
                │
        ┌───────┼────────┬──────────┐
        ▼       ▼        ▼          ▼
       AST    SAST     Adaptive    Cache
                       Planner
        │                │
        └────────┬───────┘
                 ▼
             Findings
                 │
        ┌────────┼────────┐
        ▼        ▼        ▼
       CLI      JSON     SARIF
```

The critical architectural principle is:

> **The scanner produces analysis state and events; presentation layers consume them.**

This allows the terminal UI to become increasingly sophisticated without making the underlying scanner dependent on terminal rendering.

The initial TUI should therefore focus on **observability and clarity**, not visual complexity. The most valuable experience is being able to watch the scanner move from repository discovery → candidate discovery → adaptive prioritization → deep data-flow analysis → vulnerability discovery, while understanding *why* it chose each path and which work came from cache.
