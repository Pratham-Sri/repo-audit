# RepoLens

RepoLens is a local-first repository health scanner. Give it a public GitHub repository URL or a ZIP archive, click **Run all checks**, and get one severity-ranked report with codebase metrics, scanner-by-scanner results, and suggested next steps.

The interface is built with React and uses a cool blue and cream theme. Repository files are analyzed locally; each scan is temporary and removed when the report is ready.

## Features

- One-click full scan across RepoLens rules and seven optional third-party scanners.
- A coverage and results card for every engine. Cards show whether a check completed, failed, is missing, or does not apply, plus its finding count. Select a card to filter the report to that scanner's findings.
- Severity-ranked findings with file and line, confidence, evidence, exploitability, scanner attribution, and a suggested next step.
- Overall and category scores, language inventory, file/line/function counts, and branch-signal metrics.
- Search and filters for severity, category, and scanner; export results as SARIF 2.1.0.
- GitHub URL and ZIP archive inputs.

## Run RepoLens

Requires Python 3.10 or newer. Git is needed to scan a public GitHub URL. The committed React production build is served by the Python server, so Node.js is only needed when developing or rebuilding the UI.

```powershell
cd repo-audit
python server.py
```

Open <http://localhost:4173>. ZIP uploads are limited to 25 MB and unpacked archives to 120 MB. The server binds to localhost; it is intended for one developer on their own machine and should not be exposed to an untrusted network.

### Develop the React UI

Install Node.js 20+, then run:

```powershell
npm ci
npm run dev
```

Run the Python API server separately while using Vite. To update the production interface served by `server.py`, run:

```powershell
npm run build
```

The generated `dist/` interface is committed with the source.

## Scanner coverage

RepoLens always runs its built-in deterministic checks. It then runs each installed third-party scanner that applies to the detected repository languages. These checks run from the single **Run all checks** action. Tool-specific results are combined into one report; scanner cards let you filter to an individual tool.

| Scanner | CLI | What it checks | Applicability and notes |
| --- | --- | --- | --- |
| RepoLens rules | Built in | Credential-like values, private keys, SQL string construction, permissive CORS, debug settings, unfinished markers, likely queries in loops, oversized files, repeated lines, and dependency-manifest hints. | Always runs. Heuristics can miss issues or flag safe code; review findings in context. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | `gitleaks` | Exposed secrets. | Secret values are redacted in findings. GitHub URL scans use a shallow clone; ZIP scans cannot inspect Git history. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | `osv-scanner` | Known dependency vulnerabilities from supported manifests and lockfiles. | Sends package coordinates to the OSV vulnerability service; network access is required. |
| [Semgrep](https://semgrep.dev/docs/) | `semgrep` | Security patterns using the `p/default` ruleset. | May need network access to retrieve its rules. |
| [Bandit](https://bandit.readthedocs.io/) | `bandit` | Common Python security issues. | Runs when Python files are detected. |
| [ESLint](https://eslint.org/) | `eslint` | Unused variables, unreachable code, constant conditions, and parser errors in JavaScript files. | Runs on JavaScript-family files. TypeScript files are skipped. Repo-specific ESLint configs and plugins are not loaded. |
| [Radon](https://radon.readthedocs.io/) | `radon` | Python cyclomatic complexity. | Runs when Python files are detected; reports functions with complexity 10 or higher. |
| [CodeQL CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli) | `codeql` | Deeper code analysis for Python or JavaScript/TypeScript. | Runs for one supported language per scan, preferring Python when present. CodeQL is free for public GitHub repositories; use on private repositories requires the applicable GitHub Code Security license. Only use it on repositories eligible under [GitHub's CodeQL terms](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli). |

### Install scanner CLIs

Scanner CLIs are optional and are not committed to the repository. Install them from their official sources and make them available on `PATH`, or put local installations in the corresponding `.tools` folders. RepoLens automatically checks these local Windows paths:

```text
.tools/bin/                 Gitleaks and OSV-Scanner
.tools/python/Scripts/      Semgrep, Bandit, and Radon
.tools/npm/node_modules/.bin/ ESLint
.tools/codeql/              CodeQL CLI
```

The `.tools/` directory is ignored by Git, so scanner binaries do not get pushed with the source. Restart the server after installing a CLI. Missing and failed tools are reported as such; they are never shown as passing. RepoLens does not install dependencies from the repository being scanned.

## Reports and scoring

Findings include a rule ID, severity, confidence, file, line, scanner, evidence, category, suggested fix, and exploitability. Duplicate findings are consolidated with their scanner sources. RepoLens avoids quoting source lines in findings to reduce the chance of exposing secrets through unrelated evidence. Use **Export SARIF** to download SARIF 2.1.0 for GitHub code scanning or compatible tools.

The score starts at 100 and subtracts each finding's severity weight multiplied by confidence and exploitability. Severity weights are Critical 25, High 12, Medium 5, and Low 2. Confidence multipliers are high 1.0, medium 0.75, and low 0.5; exploitability multipliers are high 1.2, medium 1.0, and low 0.7. Penalties are rounded when the final score is calculated, and the score is clamped to 0–100. Category scores use the same formula for findings in that category; a category with no findings scores 100. The overall score is not the average of category scores. Scores are triage aids, not calibrated probabilities, certifications, or comparisons across unlike repositories.

## Configuration and suppressions

Place `.repolens.yml` at the root of the repository being scanned. RepoLens supports a conservative YAML subset and does not execute YAML tags. See [.repolens.example.yml](.repolens.example.yml):

```yaml
ignore_paths:
  - generated/**
  - vendor/**

disabled_rules:
  - todo

severity_overrides:
  loop-query: High

rules:
  debug: false
```

Inline comments suppress matching rule IDs on their line or the immediately following line. Both `#` and `//` comments are accepted:

```python
# repolens-ignore: todo, bandit:B602
```

Use `*` to suppress all RepoLens findings on the annotated line. External scanner IDs can be specified in full or by their rule suffix. Suppressed findings do not affect scores or SARIF.

## Development and CI

Run the Python quality checks with:

```powershell
python -m pytest -q
```

GitHub Actions runs Ruff, Mypy, and pytest against Python 3.10–3.13, and builds the React UI with `npm ci` and `npm run build`. Scanner CLIs are mocked in report tests, so CI does not install or invoke third-party scanners.

## Current scope

RepoLens supports public GitHub clone URLs and ZIP uploads. It does not include GitHub App installation, private-repository authentication, persistent scan history, patch generation, an LLM review layer, or TypeScript-aware ESLint parsing. OSV-Scanner and Semgrep may contact their respective services to retrieve vulnerability data or rules. No code is sent to an AI service.
