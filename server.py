from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import urllib.parse
import zipfile
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
MAX_UPLOAD = 25 * 1024 * 1024
MAX_UNPACKED = 120 * 1024 * 1024
MAX_FILES = 5000
EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".go", ".rb", ".php", ".cs", ".sql", ".html", ".yml", ".yaml", ".json", ".toml", ".env", ".sh"}
SKIP = {".git", "node_modules", "vendor", "dist", "build", ".next", "coverage", "__pycache__", ".venv"}

RULES = [
    ("secret", "Critical", "Exposed credential", re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{12,}['\"]"), "Move this value into a server-side environment variable, rotate the exposed credential, and add the secret file to .gitignore.", "Security"),
    ("private-key", "Critical", "Private key in source", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Remove the private key from the repository and rotate it. Load credentials from a secret manager at runtime.", "Security"),
    ("sql", "High", "SQL built from a string", re.compile(r"(?i)(?:execute|query|raw)\s*\(\s*(?:f['\"]|['\"][^'\"]*%s|['\"][^'\"]*\+\s*(?:request|user|params|input))"), "Use a parameterized query or your ORM's bound parameters. Validate and allowlist identifiers that cannot be bound.", "Security"),
    ("cors", "High", "Permissive CORS policy", re.compile(r"(?i)(?:origin\s*[:=]\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]|cors\s*\(\s*\))"), "Restrict cross-origin requests to the exact production origins that need access.", "Security"),
    ("debug", "High", "Debug mode may be enabled", re.compile(r"(?i)(?:debug\s*=\s*True|DEBUG\s*=\s*true|app\.run\([^\n]*debug\s*=\s*True)"), "Disable debug mode in production and read the setting from a deployment environment variable.", "Security"),
    ("todo", "Low", "Unfinished code marker", re.compile(r"(?i)\b(?:TODO|FIXME|HACK|XXX)\b"), "Confirm this work is intentionally deferred; implement it or remove the placeholder before release.", "Completeness"),
    ("empty-handler", "Medium", "Empty or placeholder implementation", re.compile(r"(?m)^\s*(?:pass\s*(?:#.*)?$|throw new Error\(['\"](?:not implemented|todo)|return null\s*//\s*(?:todo|placeholder))", re.I), "Replace the placeholder with an implementation or return an explicit, documented unsupported response.", "Completeness"),
    ("loop-query", "Medium", "Potential query inside a loop", re.compile(r"(?is)(?:for|while)\s*\([^)]*\)\s*\{[^{}]{0,600}(?:\.find(?:One|Many)?\(|\.query\(|\.execute\(|SELECT\s+)[^{}]*\}|(?:for|while)\s+[^:\n]+:\s*\n(?:[^\n]*\n){0,8}\s*[^\n]*(?:\.filter\(|\.get\(|\.execute\(|SELECT\s+)"), "Fetch related records in one query, use eager loading, or batch the operation to avoid N+1 database calls.", "Scaling"),
]

def analyze(path: Path, label: str, scan_workspace: Path) -> dict:
    findings = []
    files = []
    languages = Counter()
    source_lines = 0
    duplicate_lines = Counter()
    function_count = 0
    complexity = 0
    manifest_deps = set()
    package_names = set()
    for current, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP and not d.startswith(".")]
        for name in names:
            p = Path(current) / name
            rel = p.relative_to(path).as_posix()
            ext = p.suffix.lower()
            if name.lower() in {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "pom.xml", "composer.json"}:
                try:
                    raw = p.read_text("utf-8", errors="ignore")[:2_000_000]
                    if name == "package.json":
                        data = json.loads(raw); package_names |= set(data.get("dependencies", {})) | set(data.get("devDependencies", {}))
                    elif name == "requirements.txt":
                        package_names |= {x.split(";")[0].split("[")[0].split("=")[0].split(">")[0].split("<")[0].strip().lower().replace("_", "-") for x in raw.splitlines() if x.strip() and not x.lstrip().startswith("#")}
                except Exception: pass
            if ext not in EXTENSIONS: continue
            try: content = p.read_text("utf-8", errors="ignore")
            except OSError: continue
            lines = content.splitlines(); count = len(lines); source_lines += count
            files.append({"path": rel, "lines": count, "extension": ext})
            languages[ext or "other"] += 1
            if count >= 1000:
                findings.append(finding("large-file", "Medium", "Very large source file", rel, 1, f"This file has {count:,} lines. Split it into focused modules to make changes safer.", "Maintainability"))
            if ext in {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs"}:
                defs = sum(1 for x in lines if re.match(r"\s*(?:async\s+)?(?:def\s+|function\s+|(?:export\s+)?(?:const|let)\s+\w+\s*=\s*(?:async\s*)?\(|func\s+\w+|(?:public|private|protected)\s+.*\s+\w+\s*\()", x))
                function_count += defs
                complexity += sum(len(re.findall(r"\b(?:if|elif|for|while|case|catch|except|&&|\|\|)\b|\?", x)) for x in lines)
            for n, line in enumerate(lines, 1):
                for rid, severity, title, regex, fix, category in RULES:
                    if regex.search(line):
                        evidence = "Credential-like value detected; the value is redacted." if rid == "secret" else "Private key marker detected; key contents are redacted." if rid == "private-key" else "Rule matched at this location; source text is hidden to avoid exposing sensitive values."
                        findings.append(finding(rid, severity, title, rel, n, evidence, category, fix))
                stripped = line.strip()
                if len(stripped) > 35 and not stripped.startswith(("#", "//", "*")):
                    duplicate_lines[(rel, stripped)] += 1
    if len(files) > MAX_FILES:
        files = files[:MAX_FILES]
    # Flag repeated lines across distinct files as a conservative duplication signal.
    seen = {}
    for (rel, line), _ in duplicate_lines.items():
        if line in seen and seen[line] != rel:
            findings.append(finding("duplicate", "Low", "Repeated code line", rel, 1, "A substantial line also appears in " + seen[line] + ". Review for copy-pasted logic.", "Maintainability", "Extract shared behavior into a helper or module if these copies need to stay in sync."))
        else: seen[line] = rel
    # Likely hallucinated dependencies are reported only for package names referenced as direct imports.
    if package_names:
        for p in path.rglob("*"):
            if p.suffix.lower() not in {".py", ".js", ".jsx", ".ts", ".tsx"} or any(x in SKIP for x in p.parts): continue
            try: src = p.read_text("utf-8", errors="ignore")[:500_000]
            except OSError: continue
            if p.suffix == ".py": imports = set(re.findall(r"(?m)^\s*(?:from|import)\s+([A-Za-z0-9_.-]+)", src))
            else: imports = set(re.findall(r"(?:from|require\()\s*['\"]([^./][^'\"]*)['\"]", src))
            for imp in imports:
                root = imp.split(".")[0].split("/")[0].lower().replace("_", "-")
                if root not in package_names and root not in {"os", "sys", "re", "json", "path", "fs", "http", "https", "crypto", "util", "url", "events", "stream", "zlib", "child_process", "pytest", "unittest", "typing", "collections", "datetime", "logging", "math", "time", "asyncio", "subprocess", "pathlib", "flask", "django", "fastapi", "numpy", "pandas", "react", "react-dom", "vite", "next", "typescript"}:
                    findings.append(finding("undeclared-package", "Medium", "Import missing from dependency manifest", p.relative_to(path).as_posix(), 1, f"'{imp}' is imported in source but was not found in a recognized dependency manifest. This can make installs fail on a clean machine.", "Dependencies", "Add the verified package to the project manifest, or remove the unused import. Confirm the package name on its official registry first."))
                    break
    scanner_results = [run_gitleaks(path, scan_workspace)]
    has_python = any(f["extension"] == ".py" for f in files)
    has_javascript = any(f["extension"] in {".js", ".jsx", ".mjs", ".cjs"} for f in files)
    has_typescript = any(f["extension"] in {".ts", ".tsx"} for f in files)
    scanner_results.extend([
        run_osv(path, scan_workspace),
        run_semgrep(path, scan_workspace),
        run_bandit(path, scan_workspace) if has_python else ("not-applicable", "No Python files detected", []),
        run_eslint(path, scan_workspace, has_typescript) if has_javascript else ("not-supported" if has_typescript else "not-applicable", "TypeScript files detected; this MVP does not load third-party ESLint parsers" if has_typescript else "No JavaScript files detected", []),
        run_radon(path, scan_workspace) if has_python else ("not-applicable", "No Python files detected", []),
        run_codeql(path, scan_workspace, "python" if has_python else "javascript-typescript" if has_javascript or has_typescript else None),
    ])
    for _, _, scan_findings in scanner_results:
        findings.extend(scan_findings)
    # Gitleaks is authoritative for secret detection; hide duplicate heuristic alerts at the same location.
    gitleaks_locations = {(f["file"], f["line"]) for f in scanner_results[0][2]}
    findings = [f for f in findings if not (f["id"] in {"secret", "private-key"} and (f["file"], f["line"]) in gitleaks_locations)]
    findings = dedupe(findings)
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: (rank.get(f["severity"], 4), f["file"], f["line"]))
    score = max(0, min(100, 100 - sum({"Critical": 25, "High": 12, "Medium": 5, "Low": 2}[f["severity"]] for f in findings)))
    engines = [{"name": "RepoLens rules", "status": "complete", "detail": "Built-in deterministic checks"}]
    engines.extend({"name": name, "status": result[0], "detail": result[1]} for name, result in zip(("Gitleaks", "OSV-Scanner", "Semgrep", "Bandit", "ESLint", "Radon", "CodeQL"), scanner_results))
    return {"repository": label, "score": score, "grade": "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F", "summary": {"files": len(files), "lines": source_lines, "functions": function_count, "complexity": complexity, "findings": len(findings), "critical": sum(f["severity"] == "Critical" for f in findings), "high": sum(f["severity"] == "High" for f in findings), "medium": sum(f["severity"] == "Medium" for f in findings), "low": sum(f["severity"] == "Low" for f in findings)}, "languages": [{"name": k, "files": v} for k, v in languages.most_common(6)], "findings": findings, "engines": engines}

def run_gitleaks(path: Path, scan_workspace: Path) -> tuple[str, str, list[dict]]:
    executable = shutil.which("gitleaks")
    if not executable:
        return "not-installed", "Install Gitleaks to scan for secrets", []
    report_path = scan_workspace / "gitleaks-report.json"
    try:
        command = [executable, "git" if (path / ".git").exists() else "dir", "--no-banner", "--redact", "--report-format", "json", "--report-path", str(report_path), "--exit-code", "0", "--timeout", "120", str(path)]
        proc = subprocess.run(command, cwd=scan_workspace, capture_output=True, text=True, timeout=135, check=False)
        if proc.returncode != 0:
            return "failed", "Gitleaks exited with an error; its findings were not included", []
        if not report_path.exists():
            return "failed", "Gitleaks did not produce a report", []
        data = json.loads(report_path.read_text("utf-8", errors="replace"))
        if not isinstance(data, list):
            return "failed", "Gitleaks returned an unsupported report format", []
        results = []
        for item in data:
            rule = str(item.get("RuleID") or "secret-detection")
            raw_path = str(item.get("File") or "")
            try:
                fp = Path(raw_path)
                relative = fp.resolve().relative_to(path.resolve()).as_posix() if fp.is_absolute() else fp.as_posix().lstrip("./")
            except (OSError, ValueError):
                relative = Path(raw_path).name or "unknown"
            try: line = max(1, int(item.get("StartLine") or 1))
            except (TypeError, ValueError): line = 1
            critical = any(token in rule.lower() for token in ("private-key", "private_key", "aws-root"))
            results.append({"id": f"gitleaks:{rule}", "severity": "Critical" if critical else "High", "title": "Exposed credential detected", "file": relative, "line": line, "evidence": f"Gitleaks rule '{rule}' matched. Secret value redacted.", "category": "Security", "fix": "Revoke and rotate this credential, remove it from the repository and its history where appropriate, then load the replacement from a secret manager.", "engine": "Gitleaks", "confidence": "high", "fingerprint": item.get("Fingerprint")})
        return "complete", f"Scanned {'shallow Git history and working tree' if (path / '.git').exists() else 'repository files'} · {len(results)} secret finding(s)", results
    except subprocess.TimeoutExpired:
        return "failed", "Gitleaks exceeded its 135 second time limit", []
    except (OSError, json.JSONDecodeError):
        return "failed", "Could not read the Gitleaks report", []
    finally:
        try: report_path.unlink(missing_ok=True)
        except OSError: pass

def normalize_path(root: Path, raw_path: str) -> str:
    try:
        candidate = Path(raw_path)
        if candidate.is_absolute(): return candidate.resolve().relative_to(root.resolve()).as_posix()
        return candidate.as_posix().lstrip("./") or "unknown"
    except (OSError, ValueError):
        return Path(raw_path).name or "unknown"

def external_finding(engine: str, rule: str, severity: str, title: str, file: str, line: int, evidence: str, category: str, fix: str, confidence="high") -> dict:
    return {"id": f"{engine.lower()}:{rule}", "severity": severity, "title": title, "file": file, "line": max(1, line), "evidence": evidence[:500], "category": category, "fix": fix, "engine": engine, "confidence": confidence}

def run_osv(path: Path, scan_workspace: Path) -> tuple[str, str, list[dict]]:
    executable = shutil.which("osv-scanner")
    if not executable: return "not-installed", "Install OSV-Scanner to check lockfiles against OSV advisories", []
    try:
        proc = subprocess.run([executable, "scan", "source", "--recursive", "--format", "json", str(path)], cwd=scan_workspace, capture_output=True, text=True, timeout=180, check=False)
        data = json.loads(proc.stdout)
        if proc.returncode not in (0, 1) or data.get("errors"):
            return "failed", "OSV-Scanner reported an error; dependency results may be incomplete", []
        results = []
        for source in data.get("results", []):
            manifest = normalize_path(path, str(source.get("source", {}).get("path", "unknown")))
            for package_group in source.get("packages", []):
                package = package_group.get("package", {})
                name = str(package.get("name", "dependency")); version = str(package.get("version", "unknown"))
                for vuln in package_group.get("vulnerabilities", []):
                    vuln_id = str(vuln.get("id", "OSV advisory")); aliases = vuln.get("aliases", [])
                    refs = ", ".join(str(x) for x in aliases[:2])
                    summary = str(vuln.get("summary") or vuln.get("details") or "Known vulnerability reported by OSV")
                    results.append(external_finding("OSV-Scanner", vuln_id, "High", f"Vulnerable dependency: {name}", manifest, 1, f"{vuln_id}{' · '+refs if refs else ''} · {name}@{version} · {summary}", "Dependencies", "Upgrade this dependency to a patched version listed in the OSV advisory, then regenerate and commit the lockfile."))
        return "complete", f"Checked dependency manifests · {len(results)} vulnerability finding(s)", results
    except subprocess.TimeoutExpired: return "failed", "OSV-Scanner exceeded its 180 second time limit", []
    except (OSError, json.JSONDecodeError, AttributeError, TypeError): return "failed", "Could not parse OSV-Scanner output", []

def run_semgrep(path: Path, scan_workspace: Path) -> tuple[str, str, list[dict]]:
    executable = shutil.which("semgrep")
    if not executable: return "not-installed", "Install Semgrep CLI to run the security rule pack", []
    try:
        proc = subprocess.run([executable, "scan", "--config", "p/default", "--json", "--quiet", "--metrics=off", str(path)], cwd=scan_workspace, capture_output=True, text=True, timeout=240, check=False)
        data = json.loads(proc.stdout)
        if not isinstance(data, dict) or data.get("errors") or proc.returncode not in (0, 1):
            return "failed", "Semgrep reported an error; security results may be incomplete", []
        results = []
        for item in data.get("results", []):
            extra = item.get("extra", {}); metadata = extra.get("metadata", {})
            raw_severity = str(extra.get("severity") or "WARNING").upper()
            severity = "Critical" if raw_severity == "CRITICAL" else "High" if raw_severity in {"ERROR", "HIGH"} else "Low" if raw_severity == "INFO" else "Medium"
            line = int(item.get("start", {}).get("line") or 1)
            rule = str(item.get("check_id") or "semgrep-rule")
            msg = str(extra.get("message") or item.get("message") or "Semgrep reported a match")
            fix = str(extra.get("fix") or metadata.get("remediation") or "Review the rule guidance and validate whether this pattern is exploitable in context.")
            results.append(external_finding("Semgrep", rule, severity, str(metadata.get("shortDescription") or msg.split("\n")[0])[:160], normalize_path(path, str(item.get("path", "unknown"))), line, msg, "Security", fix))
        return "complete", f"Ran p/default rules · {len(results)} finding(s)", results
    except subprocess.TimeoutExpired: return "failed", "Semgrep exceeded its 240 second time limit", []
    except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError): return "failed", "Could not parse Semgrep output", []

def run_bandit(path: Path, scan_workspace: Path) -> tuple[str, str, list[dict]]:
    executable = shutil.which("bandit")
    if not executable: return "not-installed", "Install Bandit to scan Python code", []
    try:
        proc = subprocess.run([executable, "-r", str(path), "-f", "json", "--exit-zero", "-q"], cwd=scan_workspace, capture_output=True, text=True, timeout=120, check=False)
        data = json.loads(proc.stdout); results = []
        for item in data.get("results", []):
            sev_raw = str(item.get("issue_severity") or "LOW").upper()
            severity = "Critical" if sev_raw == "CRITICAL" else "High" if sev_raw == "HIGH" else "Medium" if sev_raw == "MEDIUM" else "Low"
            issue = str(item.get("issue_text") or "Bandit reported a security issue")
            results.append(external_finding("Bandit", str(item.get("test_id") or "security-check"), severity, issue[:160], normalize_path(path, str(item.get("filename", "unknown"))), int(item.get("line_number") or 1), issue, "Security", "Review the Bandit test guidance and change the code or document why this use is safe."))
        return "complete", f"Scanned Python files · {len(results)} finding(s)", results
    except subprocess.TimeoutExpired: return "failed", "Bandit exceeded its 120 second time limit", []
    except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError): return "failed", "Could not parse Bandit output", []

def run_eslint(path: Path, scan_workspace: Path, has_typescript=False) -> tuple[str, str, list[dict]]:
    executable = shutil.which("eslint")
    if not executable: return "not-installed", "Install ESLint CLI to check JavaScript syntax and common defects", []
    try:
        # Disable repository config discovery so scanning a repo cannot execute its config or plugins.
        proc = subprocess.run([executable, "--no-config-lookup", "--format", "json", "--rule", "no-unused-vars:warn", "--rule", "no-unreachable:error", "--rule", "no-constant-condition:warn", "--ext", ".js,.jsx,.mjs,.cjs", str(path)], cwd=scan_workspace, capture_output=True, text=True, timeout=120, check=False)
        data = json.loads(proc.stdout); results = []
        for file_result in data:
            filename = normalize_path(path, str(file_result.get("filePath", "unknown")))
            for item in file_result.get("messages", []):
                rule = str(item.get("ruleId") or "parse-error")
                severity = "High" if int(item.get("severity") or 1) == 2 else "Low"
                msg = str(item.get("message") or "ESLint reported an issue")
                results.append(external_finding("ESLint", rule, severity, msg[:160], filename, int(item.get("line") or 1), msg, "Maintainability", "Fix the reported lint issue and add project-specific rules after reviewing the repository's lint configuration."))
        if not isinstance(data, list): return "failed", "ESLint returned an unsupported report format", []
        return "complete", f"Scanned JavaScript files{' · TypeScript skipped' if has_typescript else ''} · {len(results)} finding(s)", results
    except subprocess.TimeoutExpired: return "failed", "ESLint exceeded its 120 second time limit", []
    except (OSError, json.JSONDecodeError, TypeError, ValueError): return "failed", "Could not parse ESLint output (a recent ESLint CLI is required)", []

def run_radon(path: Path, scan_workspace: Path) -> tuple[str, str, list[dict]]:
    executable = shutil.which("radon")
    if not executable: return "not-installed", "Install Radon to measure Python function complexity", []
    try:
        proc = subprocess.run([executable, "cc", "--json", str(path)], cwd=scan_workspace, capture_output=True, text=True, timeout=90, check=False)
        data = json.loads(proc.stdout); results = []
        for filename, blocks in data.items():
            for block in blocks:
                complexity = int(block.get("complexity") or 0)
                if complexity < 10: continue
                name = str(block.get("name") or "function")
                rank = str(block.get("rank") or "?")
                results.append(external_finding("Radon", f"complexity-{rank}", "Medium" if complexity < 20 else "High", f"Complex function: {name}", normalize_path(path, filename), int(block.get("lineno") or 1), f"Cyclomatic complexity {complexity} (rank {rank}).", "Maintainability", "Split this function into smaller units and add tests around its branches."))
        return "complete", f"Measured Python cyclomatic complexity · {len(results)} function(s) at or above 10", results
    except subprocess.TimeoutExpired: return "failed", "Radon exceeded its 90 second time limit", []
    except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError): return "failed", "Could not parse Radon output", []

def run_codeql(path: Path, scan_workspace: Path, language: str | None) -> tuple[str, str, list[dict]]:
    if not language: return "not-applicable", "No supported CodeQL language detected", []
    executable = shutil.which("codeql")
    if not executable: return "not-installed", "Install CodeQL CLI for deeper data-flow analysis", []
    db_path = scan_workspace / "codeql-db"
    report_path = scan_workspace / "codeql.sarif"
    try:
        create = subprocess.run([executable, "database", "create", str(db_path), f"--language={language}", f"--source-root={path}", "--build-mode=none", "--quiet"], cwd=scan_workspace, capture_output=True, text=True, timeout=300, check=False)
        if create.returncode != 0: return "failed", "CodeQL could not create a database for this source tree", []
        analyze = subprocess.run([executable, "database", "analyze", str(db_path), "--format=sarifv2.1.0", f"--output={report_path}", "--quiet"], cwd=scan_workspace, capture_output=True, text=True, timeout=300, check=False)
        if analyze.returncode != 0 or not report_path.exists(): return "failed", "CodeQL analysis did not produce a SARIF report", []
        sarif = json.loads(report_path.read_text("utf-8", errors="replace")); results = []
        for run in sarif.get("runs", []):
            rule_map = {str(rule.get("id")): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for item in run.get("results", []):
                rule_id = str(item.get("ruleId") or "codeql-query")
                rule_props = rule_map.get(rule_id, {}).get("properties", {})
                try: cvss = float(rule_props.get("security-severity", 0))
                except (TypeError, ValueError): cvss = 0
                level = str(item.get("level", "warning")).lower()
                severity = "Critical" if cvss >= 9 else "High" if cvss >= 7 or level == "error" else "Medium" if cvss >= 4 else "Low"
                msg = str(item.get("message", {}).get("text") or item.get("message", {}).get("markdown") or rule_id)
                locations = item.get("locations", [])
                physical = locations[0].get("physicalLocation", {}) if locations else {}
                uri = str(physical.get("artifactLocation", {}).get("uri", "unknown"))
                line = int(physical.get("region", {}).get("startLine") or 1)
                description = str(rule_map.get(rule_id, {}).get("shortDescription", {}).get("text") or msg.split("\n")[0])
                results.append(external_finding("CodeQL", rule_id, severity, description[:160], normalize_path(path, uri), line, msg, "Security", "Trace the CodeQL data-flow path, validate reachability, and fix the unsafe source-to-sink flow."))
        return "complete", f"Analyzed {language} with CodeQL · {len(results)} finding(s)", results
    except subprocess.TimeoutExpired: return "failed", "CodeQL exceeded its 300 second time limit", []
    except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError): return "failed", "Could not parse CodeQL SARIF output", []
    finally:
        shutil.rmtree(db_path, ignore_errors=True)
        try: report_path.unlink(missing_ok=True)
        except OSError: pass

def finding(rule, severity, title, file, line, evidence, category, fix=None):
    defaults = {r[0]: r[4] for r in RULES}
    return {"id": rule, "severity": severity, "title": title, "file": file, "line": line, "evidence": evidence, "category": category, "fix": fix or defaults.get(rule, "Review this code and consider extracting repeated behavior into a shared helper."), "engine": "RepoLens rules", "confidence": "medium"}

def dedupe(items):
    got = set(); out = []
    for f in items:
        key = (f["id"], f["file"], f["line"])
        if key not in got: got.add(key); out.append(f)
    return out

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def send(self, status, data, kind="application/json; charset=utf-8"):
        raw = data if isinstance(data, bytes) else (json.dumps(data).encode() if kind.startswith("application/json") else data.encode())
        self.send_response(status); self.send_header("Content-Type", kind); self.send_header("Content-Length", str(len(raw))); self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers(); self.wfile.write(raw)
    def do_OPTIONS(self): self.send(204, b"")
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        target = ROOT / ("index.html" if path == "/" else path.lstrip("/"))
        try:
            if ROOT not in target.resolve().parents and target.resolve() != ROOT.resolve(): raise ValueError()
            mime = {".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml"}.get(target.suffix, "text/plain")
            self.send(200, target.read_bytes(), mime + "; charset=utf-8")
        except Exception: self.send(404, "Not found", "text/plain")
    def do_POST(self):
        if self.path != "/api/scan": return self.send(404, {"error": "Unknown endpoint"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_UPLOAD * 2: return self.send(413, {"error": "Upload must be smaller than 25 MB."})
            body = json.loads(self.rfile.read(length)); work = Path(tempfile.mkdtemp(prefix="repolens-"))
            try:
                if body.get("zip"):
                    payload = base64.b64decode(body["zip"], validate=True)
                    if len(payload) > MAX_UPLOAD: return self.send(413, {"error": "Upload must be smaller than 25 MB."})
                    archive = work / "upload.zip"; archive.write_bytes(payload)
                    with zipfile.ZipFile(archive) as z:
                        entries = z.infolist()
                        if sum(m.file_size for m in entries) > MAX_UNPACKED: return self.send(413, {"error": "Unpacked archive contents must be smaller than 120 MB."})
                        safe = [m for m in entries if not Path(m.filename).is_absolute() and ".." not in Path(m.filename).parts and not m.is_dir()]
                        if len(safe) > MAX_FILES * 3: return self.send(413, {"error": "Archive contains too many files."})
                        for m in safe:
                            dest = (work / "source" / m.filename).resolve()
                            if (work / "source").resolve() not in dest.parents: continue
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            with z.open(m) as src, dest.open("wb") as out: shutil.copyfileobj(src, out)
                    root = work / "source"; label = body.get("name") or "Uploaded repository"
                elif body.get("url"):
                    url = body["url"].strip()
                    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?(?:\.git)?", url): return self.send(400, {"error": "Enter a public GitHub repository URL (https://github.com/owner/repo)."})
                    proc = subprocess.run(["git", "clone", "--depth", "1", url, str(work / "source")], capture_output=True, text=True, timeout=120)
                    if proc.returncode: return self.send(400, {"error": "Could not clone this repository. Check that it is public and the URL is correct."})
                    root = work / "source"; label = url.rstrip("/").split("/")[-1].removesuffix(".git")
                else: return self.send(400, {"error": "Choose a ZIP file or enter a GitHub URL."})
                return self.send(200, analyze(root, label, work))
            finally: shutil.rmtree(work, ignore_errors=True)
        except subprocess.TimeoutExpired: self.send(408, {"error": "Repository clone timed out. Try a smaller repository."})
        except zipfile.BadZipFile: self.send(400, {"error": "That file is not a valid ZIP archive."})
        except Exception: self.send(500, {"error": "Scan failed. Check the repository contents and try again."})

if __name__ == "__main__":
    print("RepoLens running at http://localhost:4173")
    ThreadingHTTPServer(("127.0.0.1", 4173), Handler).serve_forever()
