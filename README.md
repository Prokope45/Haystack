# Haystack

**Adaptive AI-Assisted Static Security Scanner**

Haystack is a standalone, high-performance static application security testing (SAST) scanner written in **Go** that inspects source code for security-sensitive behavior and vulnerabilities.

Supporting **Go** and **Python**, Haystack implements a **neuro-symbolic / hybrid SAST architecture**—combining deterministic AST parsing, program indexing, and taint analysis with optional **Jev / System-One** AI planning and evidence classification. Findings are normalized into standardized CWE classifications with actionable remediation guidance.

Haystack can run offline in CI/CD pipelines, execute directly on files and in-memory snippets, or serve as an **agentic tool via Model Context Protocol (MCP)** so that AI coding agents can verify code safety and prevent vulnerabilities before committing changes.

---

## Architecture Overview

Haystack follows a staged neuro-symbolic pipeline where deterministic static analysis remains the authoritative security foundation, and optional AI services assist in analysis planning and evidence classification:

```text
Source Code (or in-memory code snippet)
    │
    ▼
AST / Parsing (Go & Python)
    │
    ▼
Program Index (internal/index)
    ├── Tracks files, functions, imports, calls, sources, and sinks
    └── Cheap structural queries without expensive data-flow analysis
    │
    ▼
Lightweight Candidate Discovery (internal/candidates)
    ├── Identifies candidate source-to-sink pairings
    └── Estimates analysis cost and complexity from proximity and sink type
    │
    ▼
Analysis Planning (internal/planning)
    ├── Deterministic Planner : Offline heuristic triage (default)
    └── Jev AI Planner        : OpenRouter /api/alpha/decisions (~typesafe/jev-latest)
    │
    ▼
Analysis Plan (Allocates budgets into shallow, medium, and deep modes)
    │
    ▼
Adaptive SAST Engine (internal/flow & internal/analyzer)
    ├── Shallow : Intra-statement and immediate invocation verification
    ├── Medium  : Local function-level taint propagation with bounded hops
    └── Deep    : Full intra-procedural and inter-procedural taint flow tracking
    │
    ▼
Deterministic Security Rules (internal/rules)
    └── CWE-78, CWE-89, CWE-22, CWE-798, CWE-502
    │
    ▼
Security Evidence
    │
    ▼
Optional AI Validation (internal/classifier)
    └── Jev decisions API validation + LLM contextual explanation
    │
    ▼
Normalized Findings + Analysis Metadata (internal/findings)
    │
    ▼
Reporting & Integrations
    ├── Terminal UI (ANSI colored flow arrows, snippets, and telemetry)
    ├── JSON Output (with top-level "analysis" telemetry block)
    ├── SARIF 2.1.0 (GitHub / GitLab / CI code scanning)
    └── Model Context Protocol (MCP stdio server for AI agents)
```

For the design specifications, refer to [Adaptive AI Design Plan](agents/Adaptive-ai-design-plan.md) and [POC Design Plan](agents/DESIGN_PLAN.md).

---

## Adaptive Analysis & Planning

Haystack scales analysis computational cost through explicit analysis strategies and modes:

### Analysis Strategies

- **`adaptive` (default)**: Discovers candidate flows through the program index, formulates an analysis plan (using the deterministic heuristic planner or optional Jev AI planner), and executes static analysis scaled to candidate complexity.
- **`full`**: Analyzes every candidate with exhaustive deep data-flow analysis.

### Analysis Modes

- **`shallow`**: Fast AST check for direct source-to-sink invocations without multi-hop propagation.
- **`medium`**: Bounded local function data-flow analysis (up to 4 propagation hops).
- **`deep`**: Unconstrained taint flow analysis tracking full variable assignments, string formatting, and argument passing.

### AI Dependency Modes (`--ai-mode`)

- **`optional` (default)**: Uses AI services when available. If the external AI service times out or fails, Haystack gracefully falls back to the deterministic planner without failing the scan.
- **`required`**: Fails the scan with an error if external AI services are unreachable.
- **`disabled`**: Strictly offline operation; no outbound network calls are made.

---

## Configuration & Environment Variables

All settings can be configured via CLI flags or `.env` file (see [`.env.example`](.env.example)):

### Core & Adaptive Analysis Options

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `--analysis` | `ANALYSIS_STRATEGY` | `adaptive` | Analysis strategy: `adaptive` or `full` |
| `--ai-planner` | `AI_PLANNER` | `false` | Enable external AI planner (Jev) for candidate triage |
| `--ai-classifier` | `AI_CLASSIFIER` | `false` | Enable external AI finding classifier |
| `--ai-mode` | `AI_MODE` | `optional` | AI failure handling: `optional`, `required`, or `disabled` |
| `--verbose-analysis` | | `false` | Display detailed candidate planning telemetry in terminal |
| `--diff` | | `""` | Scan only code modified in Git diff range (e.g. `HEAD~1`, `main...HEAD`) |
| `--max-depth` | | `8` | Maximum data flow search depth |
| `--max-candidates` | | `1000` | Maximum candidate flows to analyze |
| `--max-deep-candidates` | | `100` | Maximum candidates receiving deep analysis |

### AI Provider & Classifier Options

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `--classifier-provider` | `CLASSIFIER_PROVIDER` | `heuristic` | Provider: `heuristic`, `jev`, `kev`, `rlcd`, `openrouter` |
| `--classifier-endpoint` | `RLCD_API_URL` or `KEV_API_URL` | `""` | Remote classifier endpoint URL |
| `--classifier-model` | `RLCD_MODEL` or `KEV_MODEL` | `heuristic` | Model identifier |
| `--classifier-api-key` | `RLCD_API_KEY` or `KEV_API_KEY` | `""` | API key / Bearer token |
| `--classifier-timeout` | | `5s` | Classifier request timeout in seconds |
| `--openrouter-api-key` | `OPENROUTER_API_KEY` | `""` | OpenRouter API Key for Jev / System-One |
| `--system-one-model` | `SYSTEM_ONE_MODEL` | `~typesafe/jev-latest` | Jev decision model for decisions API |
| `--openrouter-model` | `OPENROUTER_MODEL` | `openrouter/free` | LLM model for vulnerability explanations |
| `--openrouter-base-url` | `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | OpenRouter API base URL |

---

## Agentic Tool Support (MCP & CLI)

Haystack provides first-class support for AI coding agents (such as Claude, OpenCode, Cursor, and Windsurf) through MCP and CLI interfaces.

### 1. Model Context Protocol (MCP) Server

Start Haystack as a standard MCP server communicating over `stdio`:

```bash
scanner mcp
```

#### MCP Client Configuration Example

Add Haystack to your `mcpServers` configuration (e.g., `claude_desktop_config.json` or `.opencode/opencode.json`):

```json
{
  "mcpServers": {
    "haystack": {
      "command": "/path/to/bin/scanner",
      "args": ["mcp"]
    }
  }
}
```

#### Available MCP Tools

| Tool | Type | Description |
|------|------|-------------|
| **`scan`** | Read | Full project security scan across Go and Python source files with adaptive triage. |
| **`scan_diff`** | Read | Scan only code modified between Git references or unstaged working tree changes. |
| **`get_analysis_plan`** | Read | Inspect candidate triage and the adaptive plan without executing full static analysis. |
| **`scan_code`** | Read | Scan in-memory Go or Python code strings directly with instant safety verdict (`is_safe`). |
| **`scan_file`** | Read | Scan an individual Go or Python file on disk. |
| **`explain_finding`** | Read | Retrieve a structured, in-depth explanation and risk assessment for a finding ID. |
| **`get_remediation`** | Read | Get remediation steps, code examples, and mitigation guidance for a finding. |
| **`get_security_status`**| Read | Overview of scanned files, active findings, severity counts, and safe verdict. |
| **`prepare_issue`** | Read | Draft a tracked security issue from a finding without performing side effects. |
| **`create_issue`** | Write | Create a tracked issue on GitHub with automated fingerprint deduplication. |
| **`update_issue`** | Write | Add comments or update status on an existing tracked issue. |
| **`close_issue`** | Write | Close a tracked issue after remediation has been verified. |

### 2. Direct CLI Code Snippet Scanning (`scan-code`)

Agents executing commands in terminal sessions can invoke `scan-code`:

```bash
# Scan a Go code snippet directly
scanner scan-code --lang go --code '
package main
import ("net/http"; "os/exec")
func Run(w http.ResponseWriter, r *http.Request) {
    c := r.URL.Query().Get("cmd")
    exec.Command("sh", "-c", c).Run()
}'

# Scan Python code piped from stdin
cat << 'EOF' | scanner scan-code --lang python --format json
import subprocess
from flask import request
def exec_user():
    cmd = request.args.get("cmd")
    subprocess.run("ping " + cmd, shell=True)
EOF
```

- **Exit code `0`**: Code is safe (no vulnerabilities found above threshold).
- **Exit code `1`**: Security findings detected.
- **Exit code `3`**: Source syntax / parsing error.

---

## Standard CLI Usage

```bash
# Scan workspace directory using default adaptive analysis
scanner .

# Scan with verbose analysis telemetry
scanner . --verbose-analysis

# Scan only code changed in git diff
scanner . --diff HEAD~1

# Run with external AI planner (Jev)
scanner . --ai-planner

# Scan with JSON output format
scanner . --format json

# Fail CI pipeline on high-severity findings
scanner . --fail-on high --confidence 0.80

# Generate SARIF 2.1.0 report for GitHub code scanning
scanner . --format sarif > results.sarif
```

### Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| `0` | Scan completed with no findings exceeding threshold |
| `1` | Security findings exceeded configured threshold |
| `2` | Configuration error |
| `3` | Source parsing / syntax error |
| `4` | Internal scanner error |

---

## Local Development & Testing

```bash
# Build binary
go build -o bin/scanner ./cmd/scanner

# Run all unit, integration, and MCP tests
go test -v ./...

# Run evaluation suite (100% precision, 100% recall on reference fixtures)
go test -v ./benchmarks

# Run linter
golangci-lint run ./...
```

---

## Repository Structure

```text
.
├── cmd/
│   ├── scanner/               # CLI entrypoint with mcp, scan-code, and dir scanning
│   └── scanner-mcp/           # Dedicated MCP server binary entrypoint
├── internal/
│   ├── index/                 # Program index constructed from ASTs
│   ├── candidates/            # Candidate discovery & cost estimation
│   ├── planning/              # Deterministic planner, candidate plans & budgets
│   ├── ai/                    # Jev AI planner client & OpenRouter decisions integration
│   ├── analyzer/              # AST parsers & language analyzers (Go, Python)
│   ├── flow/                  # Bounded intra-procedural data-flow tracking
│   ├── rules/                 # Deterministic security rules (CWE-78, 89, 22, 798, 502)
│   ├── classifier/            # Post-analysis classifier models (Jev, Kev, RLCD)
│   ├── findings/              # Finding models, analysis metadata & normalization
│   ├── issues/                # Issue provider abstraction & GitHub provider
│   ├── mcp/                   # Model Context Protocol JSON-RPC 2.0 stdio server
│   ├── output/                # Terminal UI, JSON (with telemetry), and SARIF 2.1.0 formatters
│   ├── config/                # Configuration flags and .env loading
│   └── scanner/               # Scan orchestrator, diff scanner, and discovery
├── testdata/                  # Vulnerable & safe test fixtures (Go, Python)
├── benchmarks/                # Precision, recall, and evaluation benchmarks
├── agents/                    # Architecture and design plan specifications
└── README.md
```
