# Agent Security Feedback Loop Architecture

Per `DESIGN_PLAN.md` Section 43 & Section 59, the scanner establishes an agent-native security feedback loop.

## The Workflow

```text
Agent receives task
       ↓
Agent modifies code
       ↓
MCP scan_diff()
       ↓
Scanner (SAST + Optional Classifier)
       ↓
Finding Detected?
 ├── No  → Code clean! Task complete.
 └── Yes → explain_finding(id)
            ↓
          prepare_issue(id)
            ↓
          create_issue(id) [Deduplicated]
            ↓
          get_remediation(id)
            ↓
          Agent refactors code with safe pattern
            ↓
          scan_diff()
            ↓
          Clean! Issue resolved.
```

## Why `scan_diff` is Primary

AI agents work iteratively on small diffs within larger existing codebases. Scanning the entire repository for every file edit introduces latency and risks blocking on pre-existing legacy issues outside the agent's task scope.

`scan_diff` runs full AST and data-flow analysis on touched files, but isolates reported findings to lines created or modified within the pending Git diff (`HEAD`, commit ranges, or branches).

## Safety Boundary Between Read and Write

1. `scan`, `scan_diff`, `scan_code`, and `explain_finding` produce zero side-effects.
2. `prepare_issue` generates an issue draft without external network requests.
3. `create_issue` performs external side-effects (creating GitHub/tracker issues) and strictly requires explicit agent operator authorization via `--allow-write`.
