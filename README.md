# Haystack

**AI-Assisted Static Security Scanner**

Haystack is a standalone, high-performance static security scanner written in **Go** that inspects source code for security-sensitive behavior and potential vulnerabilities.

Initially supporting **Go** and **Python**, Haystack bridges deterministic static analysis (AST parsing and source-to-sink data-flow tracking) with calibrated decision models (RLCD / Jev / Kev), normalizing findings into standardized CWE classifications and actionable remediation guidance.

Haystack can be run as a CLI tool in CI/CD pipelines, executed directly on files and code snippets, or served as an **agentic tool via Model Context Protocol (MCP)** so that AI coding agents can verify code safety and prevent vulnerabilities before writing or committing code.

---

## Architecture Overview

Haystack separates deterministic evidence generation from vulnerability decision classification:

```text
Source Code (or in-memory code snippet)
    │
    ▼
AST / Static Analysis
    │
    ├── Source Detection   (e.g., HTTP params, CLI args, env vars)
    ├── Sink Detection     (e.g., exec.Command, SQL queries, eval, open)
    └── Data-Flow Engine   (Intra-procedural taint flow tracking)
    │
    ▼
Candidate Security Evidence
    │
    ▼
Calibrated Decision Model (RLCD / Jev / Kev API or Local Heuristic)
    │
    ├── Model Selection: Jev, Kev, RLCD, or local calibrated heuristic
    ├── Security relevance & confidence scoring
    └── Complete preservation of raw probability distributions
    │
    ▼
Finding Normalization
    │
    ├── CWE Weakness Mapping (e.g., CWE-78, CWE-89, CWE-22, CWE-798, CWE-502)
    └── Actionable Remediation Guidance
    │
    ▼
Reporting & Integrations
    ├── Terminal UI (ANSI colored flow arrows & snippets)
    ├── JSON Output (machine-readable)
    ├── SARIF 2.1.0 (GitHub / GitLab / CI code scanning)
    └── Model Context Protocol (MCP stdio server for AI agents)
```

For the full architectural specification and roadmap, refer to [PROJECT_PLAN.MD](./PROJECT_PLAN.MD).

---

## Calibrated Decision Models (RLCD / Jev / Kev)

Teams can choose which calibrated decision model they want to use:

- **`heuristic`** (default offline): Built-in deterministic, structural probability model requiring no external network access.
- **`jev`**: Just-in-time Exploit / Vulnerability decision model optimized for rapid triage.
- **`kev`**: Known Exploited Vulnerability model focused on active exploit patterns.
- **`rlcd`**: Reinforcement Learning from Canonical Decisions / Compiler critic models.
- **Custom Models**: Any fine-tuned decision model endpoint.

### Configuration Flags & Environment Variables

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `--classifier-endpoint`, `--classifier-url` | `RLCD_API_URL` or `KEV_API_URL` | `""` | Inference API URL for the remote decision service |
| `--classifier-model`, `-model` | `RLCD_MODEL` or `KEV_MODEL` | `heuristic` | Model identifier (`jev`, `kev`, `rlcd`, `heuristic`, or custom) |
| `--classifier-api-key` | `RLCD_API_KEY` or `KEV_API_KEY` | `""` | Bearer token / API key for remote model service |
| `--classifier-timeout` | | `5s` | HTTP request timeout in seconds |

If a remote model API is configured but temporarily unavailable, Haystack gracefully falls back to the calibrated local heuristic classifier.

---

## Agentic Tool Support (MCP & CLI)

Haystack can be used by AI coding agents (such as Claude, OpenCode, Cursor, and Windsurf) to scan generated code before saving, committing, or executing it.

### 1. Model Context Protocol (MCP) Server

Start Haystack as a standard MCP server communicating over stdio:

```bash
scanner mcp
# Or with remote RLCD decision model:
scanner mcp --classifier-endpoint https://rlcd.internal/v1/classify --classifier-model jev
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

1. **`scan_code`**: Scans an in-memory string of Go or Python code directly.
   - Arguments: `code` (string, required), `language` ("go" or "python", required), `filename` (optional), `min_severity` (optional), `min_confidence` (optional).
   - Returns: Instant verdict (`is_safe: true/false`), findings count, structured taint flow steps, and remediation advice.
2. **`scan_file`**: Scans an individual Go or Python file on disk.
   - Arguments: `path` (string, required), `min_severity` (optional).
3. **`scan_directory`**: Scans an entire project or workspace directory.
   - Arguments: `path` (string, optional), `min_severity` (optional).

### 2. Direct CLI Code Snippet Scanning (`scan-code`)

Agents executing commands via bash / terminal tool calls can invoke `scan-code`:

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
- **Exit code `1`**: Vulnerabilities found.
- **Exit code `3`**: Source syntax error.

---

## Standard CLI Usage

```bash
# Scan a directory
scanner ./path/to/project

# Scan an individual file directly
scanner ./src/api/handler.go

# Scan with JSON output format
scanner . --format json

# Fail CI pipeline on high-severity findings
scanner . --fail-on high --confidence 0.80

# Generate SARIF report for GitHub code scanning
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
│   └── scanner/               # CLI entrypoint with mcp, scan-code, and file/dir scanning
├── internal/
│   ├── analyzer/              # AST parsers & language analyzers (Go, Python)
│   ├── classifier/            # Classifier interface & implementations
│   │   ├── kev/               # Calibrated heuristic baseline & Kev HTTP adapter
│   │   └── rlcd/              # Generalized RLCD/Jev/Kev multi-model client
│   ├── config/                # CLI & scanner configuration with env var support
│   ├── findings/              # Finding models and normalization
│   ├── flow/                  # Intra-procedural data-flow analysis
│   ├── intelligence/          # Authoritative CWE catalog & remediations
│   ├── mcp/                   # Model Context Protocol JSON-RPC 2.0 stdio server
│   ├── output/                # Terminal, JSON, and SARIF 2.1.0 formatters
│   ├── rules/                 # Deterministic security rules (CWE-78, 89, 22, 798, 502)
│   └── scanner/               # Scan orchestrator, discovery, and in-memory analyzer
├── testdata/                  # Intentionally vulnerable & safe test fixtures (Go, Python)
├── benchmarks/                # Precision, recall, and performance benchmarks
├── examples/                  # CI/CD pipeline examples (GitHub Actions, etc.)
└── README.md
```
