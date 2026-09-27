# AI Agent Secure Coding with Haystack MCP

This directory contains integration configuration and workflows for connecting AI coding agents (OpenCode, Claude Desktop, Cursor) to the **Haystack Security Scanner MCP Server**.

## 1. Overview

The Haystack MCP server enables AI agents to verify security posture throughout the development lifecycle:

1. **In-Memory Verification (`scan_code`)**: Scan generated snippets before saving to disk.
2. **Pending Changes Verification (`scan_diff`)**: Scan only git-modified lines after editing code.
3. **Finding Explanation (`explain_finding`)**: Understand untrusted sources, dangerous sinks, and taint paths.
4. **Authoritative Remediation (`get_remediation`)**: Retrieve secure coding patterns and CWE fixes.
5. **Issue Creation (`prepare_issue` & `create_issue`)**: Review and create tracked security issues deduplicated by stable finding fingerprints.

## 2. Configuration

Add the following to your agent's MCP configuration (e.g. `opencode.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "haystack-scanner": {
      "command": "/path/to/scanner-mcp",
      "args": [
        "--allow-write",
        "--issue-provider=github",
        "--github-repo=owner/repo"
      ],
      "env": {
        "GITHUB_TOKEN": "ghp_your_token_here"
      }
    }
  }
}
```

## 3. Tool Permissions

Per `DESIGN_PLAN.md` Section 42, tools adhere to least-privilege security boundaries:

* **Read-Only Tools** (Enabled by default):
  * `scan`
  * `scan_diff`
  * `scan_file`
  * `scan_code`
  * `explain_finding`
  * `get_remediation`
  * `get_security_status`
  * `prepare_issue`
* **Write Tools** (Requires `--allow-write` or `--enable-issues` flag):
  * `create_issue`
  * `update_issue`
  * `close_issue`
