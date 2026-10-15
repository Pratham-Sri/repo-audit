# RepoLens

RepoLens is a small, local-first repository health scanner. It accepts a public GitHub repository URL or a ZIP archive and produces a severity-ranked report with codebase metrics and suggested next steps.

## Run it

Requires Python 3.10+ and Git (Git is only needed for GitHub URL scans). No Python packages are required.

```powershell
cd repo-audit
python server.py
```

Open <http://localhost:4173>. ZIP uploads are limited to 25 MB. The server binds to localhost and deletes each temporary checkout after generating the report.

### Optional scanner CLIs

Install any tools you want from their official sources, and make sure each CLI is on `PATH` before starting RepoLens. Missing CLIs are skipped and shown as not installed; RepoLens never downloads tools or installs target-project dependencies for you. Source analysis runs on the local machine, but OSV-Scanner sends package coordinates to the OSV vulnerability service and Semgrep may download its selected rule pack.

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

These built-in checks are heuristics. They can miss issues and can flag code that is safe in context; review evidence before acting. Dependency-manifest checks are intentionally a hint and do not prove that a package is nonexistent or unsafe.

## Analysis engines

The report marks built-in rules as active and each optional scanner as active, missing, not applicable, or failed based on the local CLI. The engine panel calls this out rather than presenting missing tools as passing. The LLM review layer is not configured; no code is sent to an AI service.

## Current scope

This is a runnable MVP for local exploration. It supports public GitHub clone URLs and ZIP uploads; private GitHub App installation, patch generation, persistent scan history, and TypeScript-aware ESLint parsing are not included yet. Do not expose the local server to an untrusted network: it is designed for a single developer's local machine.
