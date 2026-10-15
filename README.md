# RepoLens

RepoLens is a small, local-first repository health scanner. It accepts a public GitHub repository URL or a ZIP archive and produces a severity-ranked report with codebase metrics and suggested next steps.

## Run it

Requires Python 3.10+ and Git (Git is only needed for GitHub URL scans). The bundled React interface is served from the committed build; Node.js is only needed when rebuilding the UI.

```powershell
cd repo-audit
python server.py
```

Open <http://localhost:4173>. ZIP uploads are limited to 25 MB. The server binds to localhost and deletes each temporary checkout after generating the report.

To work on the React interface, install Node.js 20+, then run `npm ci` and `npm run build`. The Python server serves the generated `dist/` app when it exists. `npm run dev` starts Vite for frontend work; run the Python API server separately while using the dev server.

### Optional scanner CLIs

Install any tools you want from their official sources. RepoLens detects local tools in `.tools` automatically, or uses commands on `PATH`. Missing CLIs are skipped and shown as not installed; RepoLens never installs target-project dependencies. Source analysis runs on the local machine, but OSV-Scanner sends package coordinates to the OSV vulnerability service and Semgrep may download its selected rule pack. CodeQL CLI is free for public repositories; private-repository use requires the applicable GitHub Code Security license. Only run it on repositories eligible under GitHub's CodeQL terms.

| Tool | CLI name | Scope |
| --- | --- | --- |
| [Gitleaks](https://github.com/gitleaks/gitleaks/releases) | `gitleaks` | Secrets; redacted results. GitHub scans are shallow clones, ZIP scans inspect archive files only. |
| [OSV-Scanner](https://github.com/google/osv-scanner/releases) | `osv-scanner` | Known vulnerabilities from manifests and lockfiles. |
| [Semgrep](https://semgrep.dev/docs/getting-started/) | `semgrep` | Security rules using `p/default`; the rule pack may need network access. |
| [Bandit](https://bandit.readthedocs.io/) | `bandit` | Python security checks. |
| [ESLint](https://eslint.org/docs/latest/use/getting-started) | `eslint` | JavaScript checks with a small built-in ruleset; project configs and plugins are not loaded. TypeScript is reported as unsupported until a safe parser integration is added. |
| [Radon](https://radon.readthedocs.io/) | `radon` | Python cyclomatic complexity; reports functions with complexity 10 or higher. |
| [CodeQL CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli) | `codeql` | Optional deeper analysis for Python or JavaScript/TypeScript; currently chooses one detected language per scan. |

## What it scans

- High-confidence pattern checks for credential-like values, private keys, SQL string construction, permissive CORS, debug settings, unfinished markers, and possible queries inside loops.
- Optional Gitleaks, OSV-Scanner, Semgrep, Bandit, ESLint, Radon, and CodeQL integrations. Secret values from Gitleaks are redacted in RepoLens findings.
- Basic source inventory: file count, line count, function count, branch-signal count, language mix, and oversized files.
- Conservative hints for repeated lines and imports missing from recognized dependency manifests.
- A score that prioritizes the number and severity of findings. It is a navigation aid, not a formal security certification.

These built-in checks are heuristics. They can miss issues and can flag code that is safe in context; review the file and line before acting. RepoLens avoids quoting source lines in its findings to reduce the chance of exposing a secret through unrelated evidence. Dependency-manifest checks are intentionally a hint and do not prove that a package is nonexistent or unsafe.

## Finding format and exports

Each finding is normalized through the `Finding` schema: rule ID, severity, confidence, file, line, tool, title, evidence, category, fix hint, and exploitability. JSON reports are versioned with `schemaVersion` and retain RepoLens-specific context, category scores, scanner status, and a SARIF representation. Use **Export SARIF** after a scan to download SARIF 2.1.0 for GitHub code scanning or compatible editors.

## Suppressions and configuration

Place `.repolens.yml` at the root of a scanned repository. RepoLens supports a conservative YAML subset and does not execute or load YAML tags. Copy [.repolens.example.yml](.repolens.example.yml) to see supported keys:

```yaml
ignore_paths:
  - generated/**
disabled_rules:
  - todo
severity_overrides:
  loop-query: High
rules:
  debug: false
```

Inline comments suppress matching rule IDs on their own line or the immediately following source line: `# repolens-ignore: rule-id` (also accepts `//` comment syntax). Multiple IDs can be comma-separated; `*` suppresses all RepoLens findings at the annotated line. External IDs may be specified in full (for example `bandit:B602`) or by their rule suffix. Suppressed findings do not affect scores or SARIF.

## Scoring

The score starts at 100 and subtracts the sum of each finding's severity weight multiplied by confidence and exploitability. Severity weights are Critical 25, High 12, Medium 5, and Low 2. Confidence multipliers are high 1.0, medium 0.75, and low 0.5; exploitability multipliers are high 1.2, medium 1.0, and low 0.7. Each penalty is rounded only when the final score is calculated; the final score is clamped to 0–100. Built-in heuristics default to medium confidence and medium exploitability. External scanner findings default to high confidence, with high exploitability for Critical/High and medium otherwise. These defaults are triage hints, not calibrated probabilities.

Category scores use the same formula on findings in that category and are reported for security, maintainability, dependencies, docs/tests (currently includes completeness checks), and scaling. A category with no findings scores 100. The overall score combines all findings directly, so it is not the average of category scores. The score is a navigation aid, not a certification or a comparison across unlike repositories.

## Development and CI

Run tests with `python -m pytest -q`. CI runs Ruff, Mypy, and the tests for Python 3.10 through 3.13. Scanner CLIs are mocked in report tests, so CI does not install or invoke third-party scanners.

## Analysis engines

The report marks built-in rules as active and each optional scanner as active, missing, not applicable, or failed based on the local CLI. The engine panel calls this out rather than presenting missing tools as passing. The LLM review layer is not configured; no code is sent to an AI service.

## Current scope

This is a runnable MVP for local exploration. It supports public GitHub clone URLs and ZIP uploads; private GitHub App installation, patch generation, persistent scan history, and TypeScript-aware ESLint parsing are not included yet. Do not expose the local server to an untrusted network: it is designed for a single developer's local machine.
