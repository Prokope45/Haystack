# Issue Deduplication & Stable Fingerprints

Per `DESIGN_PLAN.md` Section 40, repeated scans must not create duplicate issues in issue trackers.

## Stable Fingerprint Derivation

Vulnerability line numbers frequently drift as unrelated code is added or deleted elsewhere in a file. Fingerprinting must remain stable across line shifts while uniquely identifying distinct vulnerabilities.

### Algorithm

The fingerprint is computed as a SHA-256 hash of normalized vulnerability traits:

```text
raw = "rule:" + RuleID +
      "|file:" + NormalizedRelativePath +
      "|sink_type:" + SinkType +
      "|sink_name:" + SinkName +
      "|source_type:" + SourceType +
      "|source_name:" + SourceName +
      "|flow:" + NormalizedFlowSteps

Fingerprint = SHA256(raw)
```

## Issue Provider Tracking

When filing an issue, the provider embeds standard metadata comments into the issue body:

```markdown
<!--
Scanner-Finding: RULE-CMD-001-handlers-api.go-42-1
Scanner-Fingerprint: a83c91f000deadbeef83492...
-->
```

## Deduplication Workflow

```text
Finding Fingerprint
       ↓
Search Open Issues (GitHub Search API: `repo:{repo} is:issue is:open {fingerprint}`)
       ↓
Existing Open Issue Found?
 ├── Yes → Return existing issue with `IsDuplicate: true` (no new issue created)
 └── No  → POST new issue to GitHub API
```
