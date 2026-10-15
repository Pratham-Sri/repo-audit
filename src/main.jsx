import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const glyph = {
  shield: 'M12 3 20 6v5c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6zM8.5 12l2.2 2.2 4.8-5',
  scan: 'M4 8V5a1 1 0 0 1 1-1h3m8 0h3a1 1 0 0 1 1 1v3M4 16v3a1 1 0 0 0 1 1h3m8 0h3a1 1 0 0 0 1-1v-3M8 12h8',
  search: 'm20 20-4.5-4.5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0z',
  file: 'M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10zM13 3v7h7M8 14h8M8 18h6',
  upload: 'M12 16V4m-5 5 5-5 5 5M5 15v4a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-4',
  external: 'M14 4h6v6m0-6-9 9M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5',
  bolt: 'M13 2 4 14h7l-1 8 10-13h-7z',
  grid: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
};
const SCANNER_NAMES = ['RepoLens rules', 'Gitleaks', 'OSV-Scanner', 'Semgrep', 'Bandit', 'ESLint', 'Radon', 'CodeQL'];
function Icon({ name, size = 18 }) { return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={glyph[name] || glyph.grid} /></svg>; }

function App() {
  const [source, setSource] = useState('github');
  const [url, setUrl] = useState('');
  const [archive, setArchive] = useState(null);
  const [report, setReport] = useState(null);
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [severity, setSeverity] = useState('all');
  const [category, setCategory] = useState('all');
  const [tool, setTool] = useState('all');
  const [query, setQuery] = useState('');
  const findings = report?.findings || [];
  const categories = useMemo(() => [...new Set(findings.map((item) => item.category))].sort(), [findings]);
  const tools = useMemo(() => [...new Set(findings.flatMap((item) => [item.engine || item.tool || 'RepoLens rules', ...(item.sources || [])]))].sort(), [findings]);
  const filtered = useMemo(() => findings.filter((item) => {
    const sourceTool = item.engine || item.tool || 'RepoLens rules';
    const text = [item.title, item.file, item.evidence, item.id].join(' ').toLowerCase();
    return (severity === 'all' || item.severity === severity) && (category === 'all' || item.category === category)
      && (tool === 'all' || sourceTool === tool || (item.sources || []).includes(tool)) && (!query || text.includes(query.toLowerCase()));
  }), [findings, severity, category, tool, query]);

  async function scan(event) {
    event?.preventDefault();
    setBusy(true); setStatus({ text: 'Running all checks in one scan. CodeQL may take a few minutes…', kind: 'loading' }); setReport(null);
    setSeverity('all'); setCategory('all'); setTool('all'); setQuery('');
    try {
      const payload = source === 'github' ? { url: url.trim() } : { zip: await fileToBase64(archive), name: (archive?.name || 'Uploaded repository').replace(/\.zip$/i, '') };
      const response = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'The scan could not be completed.');
      setReport(data); setStatus({ text: 'Scan complete. Your report is ready.', kind: 'success' });
      window.setTimeout(() => document.getElementById('report')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 40);
    } catch (error) { setStatus({ text: error.message || 'The scan failed. Please try again.', kind: 'error' }); }
    finally { setBusy(false); }
  }
  function exportSarif() {
    if (!report?.sarif) return;
    const objectUrl = URL.createObjectURL(new Blob([JSON.stringify(report.sarif, null, 2)], { type: 'application/sarif+json' }));
    const anchor = document.createElement('a'); anchor.href = objectUrl; anchor.download = 'repolens-results.sarif'; anchor.click(); URL.revokeObjectURL(objectUrl);
  }
  const scoreTone = (value) => value < 55 ? 'red' : value < 78 ? 'amber' : 'blue';
  const summary = report?.summary;

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#top"><span className="brand-mark"><i /><i /><i /></span><span>repo<span className="brand-accent">lens</span></span></a>
      <div className="workspace-label">WORKSPACE</div>
      <nav className="side-nav" aria-label="Main navigation">
        <a className="side-link selected" href="#top"><Icon name="grid" />Overview</a>
        <a className="side-link" href="#findings"><Icon name="file" />Findings<span className="nav-count">{summary?.findings ?? '—'}</span></a>
        <a className="side-link" href="#engines"><Icon name="shield" />Scanners</a>
      </nav>
      <div className="sidebar-bottom"><div className="privacy-card"><span className="privacy-icon"><Icon name="shield" size={17} /></span><div><strong>Private by default</strong><p>Source stays on this machine. No account required.</p></div></div><div className="sidebar-user"><span className="user-avatar">RL</span><span><strong>Local workspace</strong><small>Personal project</small></span><i className="online-dot" /></div></div>
    </aside>

    <main className="main-content" id="top">
      <header className="topbar"><div className="breadcrumbs">Workspace <span>/</span> <strong>Repository health</strong></div><div className="topbar-right"><span className="local-pill"><i /> LOCAL SCAN</span><span className="topbar-label">CODE QUALITY · SECURITY · SCALE</span></div></header>
      <section className="hero"><div className="hero-copy"><div className="eyebrow"><i /> CODEBASE INTELLIGENCE</div><h1>Make your next<br /><em>ship a confident one.</em></h1><p>RepoLens finds the risks between the lines, then gives you a clear place to start.</p><div className="hero-proof"><span>✓ Seven scanner integrations</span><span>✓ Source stays local</span></div></div><div className="hero-visual" aria-hidden="true"><div className="orbit orbit-a" /><div className="orbit orbit-b" /><div className="visual-core"><span>R</span><small>REPO<br />SIGNALS</small></div><span className="float-chip chip-security"><i /> SECURITY</span><span className="float-chip chip-quality"><i /> QUALITY</span></div></section>

      <section className="scan-panel" aria-labelledby="scan-title">
        <div className="panel-heading"><div><div className="section-kicker"><span>01</span> START HERE</div><h2 id="scan-title">Bring your repository in</h2><p>Run a focused, local-first health check in a few moments.</p></div><div className="scan-counter"><span className="counter-icon"><Icon name="scan" /></span><span><b>01</b><small>NEW SCAN</small></span></div></div>
        <div className="source-tabs" role="tablist"><button className={source === 'github' ? 'source-tab active' : 'source-tab'} onClick={() => setSource('github')} role="tab" aria-selected={source === 'github'}><Icon name="external" size={16} /> GitHub repository</button><button className={source === 'zip' ? 'source-tab active' : 'source-tab'} onClick={() => setSource('zip')} role="tab" aria-selected={source === 'zip'}><Icon name="upload" size={16} /> ZIP archive</button></div>
        {source === 'github' ? <form className="scan-form" onSubmit={scan}><label className="sr-only" htmlFor="repo-url">Public GitHub repository URL</label><span className="url-prefix">github.com /</span><input id="repo-url" type="url" required placeholder="owner/repository" value={url} onChange={(event) => setUrl(event.target.value)} /><button className="primary-button" type="submit" disabled={busy || !url.trim()}><Icon name="scan" size={15} />{busy ? 'Running all checks…' : 'Run all checks'} <Icon name="external" size={15} /></button></form> : <div className="upload-area"><label className="dropzone"><input type="file" accept=".zip,application/zip" onChange={(event) => setArchive(event.target.files?.[0] || null)} /><span className="upload-symbol"><Icon name={archive ? 'grid' : 'upload'} /></span><span><strong>{archive ? archive.name : 'Choose a ZIP archive'}</strong><small>{archive ? (archive.size / 1048576).toFixed(1) + ' MB · ready to scan' : 'Drop a file here or browse your computer'}</small></span><b className="browse-link">Browse files</b></label><button className="primary-button upload-button" onClick={scan} disabled={busy || !archive}><Icon name="scan" size={15} />{busy ? 'Running all checks…' : 'Run all checks'} <Icon name="external" size={15} /></button></div>}
        <div className="scan-plan"><div className="scan-plan-heading"><span><Icon name="bolt" size={15} /> ONE CLICK · FULL COVERAGE</span><small>Built-in rules + 7 scanner integrations</small></div><div className="scan-plan-list">{SCANNER_NAMES.map((name) => <span className="scan-plan-chip" key={name}><i />{name}</span>)}</div></div>
        {status && <div className={'scan-status ' + status.kind} role="status">{status.kind === 'loading' && <i className="spinner" />}{status.text}</div>}
        <div className="scan-panel-footer"><span><Icon name="shield" size={14} /> Local processing · no repository is stored</span><span className="footer-languages">PYTHON <i /> JAVASCRIPT <i /> MULTI-LANGUAGE</span></div>
      </section>

      {report ? <section className="report-section" id="report">
        <div className="report-heading"><div><div className="section-kicker"><span>02</span> YOUR REPORT</div><h2>{report.repository}</h2><p>{summary.files.toLocaleString()} source files · {summary.lines.toLocaleString()} lines examined</p></div><div className="report-actions"><button className="outline-button" onClick={exportSarif}>Export SARIF <Icon name="external" size={15} /></button><button className="ghost-button" onClick={() => { setReport(null); setStatus(null); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>New scan ＋</button></div></div>
        <div className="report-overview">
          <article className="score-panel"><div className="card-topline"><div><div className="section-kicker">REPOSITORY HEALTH</div><h3>Overall score</h3></div><span className="grade-tag">GRADE {report.grade}</span></div><div className="score-content"><div className={'score-dial ' + scoreTone(report.score)} style={{ '--score': report.score + '%' }}><div><strong>{report.score}</strong><small>/ 100</small></div></div><div className="score-copy"><strong>{report.score >= 85 ? 'A strong foundation.' : report.score >= 65 ? 'Good bones. Room to grow.' : 'A few risks need attention.'}</strong><p>{summary.critical + summary.high} higher-priority finding{summary.critical + summary.high === 1 ? '' : 's'} to review. A triage guide, not a certification.</p></div></div><div className="category-heading"><span>HEALTH BY CATEGORY</span><span>0–100</span></div><div className="category-grid">{Object.entries(report.categoryScores || {}).map(([name, value]) => <CategoryScore key={name} name={name} value={value} tone={scoreTone(value)} />)}</div></article>
          <article className="metrics-panel"><div className="card-topline"><div><div className="section-kicker">AT A GLANCE</div><h3>Codebase snapshot</h3></div><span className="snapshot-icon"><Icon name="file" /></span></div><div className="metrics-grid"><Metric label="Files scanned" value={summary.files} /><Metric label="Lines of code" value={summary.lines} /><Metric label="Functions" value={summary.functions} /><Metric label="Branch signals" value={summary.complexity} /></div><div className="language-block"><span className="category-heading">DETECTED LANGUAGES</span><div className="language-list">{report.languages.map((item) => <span className="language-pill" key={item.name}>{languageName(item.name)}<b>{item.files}</b></span>)}</div></div><div className="severity-summary"><span><i className="dot-critical" />{summary.critical} critical</span><span><i className="dot-high" />{summary.high} high</span><span><i className="dot-medium" />{summary.medium} medium</span><span><i className="dot-low" />{summary.low} low</span></div></article>
        </div>
        <section className="findings-section" id="findings"><div className="findings-title"><div><div className="section-kicker"><span>03</span> PRIORITIZED SIGNALS</div><h2>Findings <span className="total-badge">{summary.findings}</span></h2><p>Review the source, confidence, and next step for each signal.</p></div><div className="showing-count"><b>{filtered.length}</b><span>SHOWING</span></div></div>
          <div className="filter-bar"><label className="search-field"><Icon name="search" size={16} /><input aria-label="Search findings" placeholder="Search findings or files" value={query} onChange={(event) => setQuery(event.target.value)} /></label><select aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option>{['Critical', 'High', 'Medium', 'Low'].map((item) => <option key={item}>{item}</option>)}</select><select aria-label="Filter by category" value={category} onChange={(event) => setCategory(event.target.value)}><option value="all">All categories</option>{categories.map((item) => <option key={item}>{item}</option>)}</select><select aria-label="Filter by scanner" value={tool} onChange={(event) => setTool(event.target.value)}><option value="all">All scanners</option>{tools.map((item) => <option key={item}>{item}</option>)}</select></div>
          <div className="finding-list">{filtered.length ? filtered.map((item, index) => <FindingCard finding={item} index={index} key={item.id + item.file + item.line} />) : <div className="empty-findings"><span><Icon name="shield" size={20} /></span><strong>{findings.length ? 'No findings match these filters.' : 'No findings surfaced in this scan.'}</strong><p>{findings.length ? 'Try clearing a filter or changing your search.' : 'Check scanner coverage below; tools marked not installed did not contribute results.'}</p></div>}</div>
        </section>
        <section className="scanner-section" id="engines"><div className="scanner-heading"><div><div className="section-kicker"><span>04</span> SCANNER RESULTS</div><h2>Every tool, one report</h2><p>Select a tool to filter the findings it reported. Completed tools with zero matches are shown clearly.</p></div><span className="scanner-count">{report.engines.filter((item) => item.status === 'complete').length} / {report.engines.length} complete</span></div><div className="scanner-grid">{report.engines.map((item) => <ScannerCard engine={item} findings={findings} selected={tool === item.name} onSelect={() => { setTool(tool === item.name ? 'all' : item.name); document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }} key={item.name} />)}</div></section>
      </section> : <section className="empty-state"><span><Icon name="bolt" size={17} /></span><strong>YOUR REPORT WILL APPEAR HERE</strong><p>Start a scan to see category scores, prioritized findings, and scanner coverage.</p></section>}
      <footer className="page-footer"><span>RepoLens <i>·</i> A clearer view of your code</span><span>Local-first by design</span></footer>
    </main>
  </div>;
}

function CategoryScore({ name, value, tone }) {
  const label = name === 'docs_tests' ? 'Docs & tests' : name.replaceAll('_', ' & ');
  return <div className="category-score"><div><span>{label}</span><strong>{value}</strong></div><div className="category-track"><i className={tone} style={{ width: value + '%' }} /></div></div>;
}
function Metric({ label, value }) { return <div className="metric-card"><span>{label}</span><strong>{Number(value || 0).toLocaleString()}</strong></div>; }
function FindingCard({ finding, index }) {
  const sources = finding.sources?.length ? finding.sources : [finding.engine || 'RepoLens rules'];
  return <details className="finding-card" open={index === 0 && finding.severity === 'Critical'}><summary><span className={'severity-tag severity-' + finding.severity.toLowerCase()}>{finding.severity}</span><span className="finding-title"><strong>{finding.title}</strong><small>{finding.file}<i>:</i>{finding.line}</small></span><span className="finding-category">{finding.category}</span><span className="finding-signal"><small>CONFIDENCE</small><b className={'confidence confidence-' + (finding.confidence || 'medium')}>{finding.confidence || 'medium'}</b></span><span className="finding-chevron">⌄</span></summary><div className="finding-body"><div><span className="detail-label">WHY IT MATTERS</span><p>{finding.evidence}</p></div><div className="fix-callout"><span className="fix-icon"><Icon name="bolt" size={15} /></span><div><span className="detail-label">SUGGESTED NEXT STEP</span><p>{finding.fix_hint || finding.fix || 'Review this finding in context and decide whether remediation is needed.'}</p></div></div><div className="finding-meta"><span>Exploitability <b>{finding.exploitability || 'medium'}</b></span><span className="source-list">Detected by {sources.map((item) => <b className="source-tag" key={item}>{item}</b>)}</span><code>{finding.rule_id || finding.id}</code></div></div></details>;
}
function ScannerCard({ engine, findings, selected, onSelect }) {
  const active = engine.status === 'complete';
  const failed = engine.status === 'failed';
  const label = active ? 'COMPLETE' : failed ? 'ERROR' : engine.status === 'not-installed' ? 'NOT INSTALLED' : engine.status === 'not-applicable' ? 'NOT APPLICABLE' : engine.status === 'not-supported' ? 'NOT SUPPORTED' : 'UNAVAILABLE';
  const matches = findings.filter((finding) => [finding.engine, finding.tool, ...(finding.sources || [])].includes(engine.name)).length;
  return <button type="button" className={'scanner-card ' + (active ? 'is-active' : '') + (failed ? ' is-failed' : '') + (selected ? ' is-selected' : '')} onClick={onSelect} aria-pressed={selected} title={`Show ${engine.name} findings`}><span className="scanner-card-top"><span className="scanner-icon"><Icon name={engine.name === 'Gitleaks' ? 'shield' : engine.name === 'OSV-Scanner' ? 'file' : 'scan'} size={17} /></span><span className={'scanner-status ' + (active ? 'active' : failed ? 'failed' : '')}><i />{label}</span></span><strong>{engine.name}</strong><span className="scanner-card-detail">{engine.detail}</span><span className="scanner-card-result">{active ? <><b>{matches}</b> {matches === 1 ? 'finding' : 'findings'}</> : 'No scan results'}</span></button>;
}
function languageName(extension) { return ({ '.py': 'Python', '.js': 'JavaScript', '.jsx': 'React JSX', '.ts': 'TypeScript', '.tsx': 'React TSX', '.go': 'Go', '.rb': 'Ruby', '.php': 'PHP', '.java': 'Java', '.cs': 'C#', '.sql': 'SQL', '.html': 'HTML', '.yml': 'YAML', '.yaml': 'YAML', '.json': 'JSON', '.toml': 'TOML', '.sh': 'Shell' })[extension] || extension.replace('.', '').toUpperCase(); }
function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    if (!file) return reject(new Error('Choose a ZIP archive before scanning.'));
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(',')[1]);
    reader.onerror = () => reject(new Error('The selected ZIP could not be read.'));
    reader.readAsDataURL(file);
  });
}

createRoot(document.getElementById('root')).render(<React.StrictMode><App /></React.StrictMode>);
