"""HTML reporter - flagship AEGIS report with hacker/cybersecurity aesthetic."""

from datetime import datetime, timezone

from jinja2 import Environment

from aegis.core.findings import OWASPCategory, Severity, ScanResult
from aegis.reporters import BaseReporter
from aegis.reporters.compliance import ComplianceMapper


# Severity colours used across badges and charts
_SEV_COLORS = {
    "critical": "#ff2a6d",
    "high": "#ff6a00",
    "medium": "#ffd600",
    "low": "#00d4ff",
    "info": "#7a7d85",
}


_env = Environment(autoescape=True)
_HTML_TEMPLATE = _env.from_string(r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS Security Report - {{ target }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ═══════════════════════════════════════════════════════════════
   AEGIS - Cybersecurity Report Theme
   ═══════════════════════════════════════════════════════════════ */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg-primary:   #0a0b10;
  --bg-secondary: #101520;
  --bg-card:      #141925;
  --bg-hover:     #1a2035;
  --border:       #1e2740;
  --border-glow:  #00d4ff22;
  --text-primary: #e0e4ec;
  --text-muted:   #7a7d85;
  --accent:       #00d4ff;
  --accent-dim:   #00d4ff44;
  --neon-glow:    0 0 12px #00d4ff55, 0 0 30px #00d4ff22;
  --critical:     #ff2a6d;
  --high:         #ff6a00;
  --medium:       #ffd600;
  --low:          #00d4ff;
  --info:         #7a7d85;
  --font-mono:    'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
}

html { scroll-behavior: smooth; }

body {
  font-family: var(--font-mono);
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
  min-height: 100vh;
}

/* Subtle scanline overlay */
body::before {
  content: '';
  position: fixed; inset: 0; z-index: 9999; pointer-events: none;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,0.03) 2px,
    rgba(0,0,0,0.03) 4px
  );
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.container { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }

/* ── Header ────────────────────────────────────────────────── */
.header {
  text-align: center;
  padding: 3rem 1rem 2rem;
  border-bottom: 1px solid var(--border);
  position: relative;
}
.header::after {
  content: '';
  position: absolute; bottom: -1px; left: 50%; transform: translateX(-50%);
  width: 200px; height: 1px;
  background: var(--accent);
  box-shadow: var(--neon-glow);
}
.logo {
  font-size: 2.8rem;
  font-weight: 700;
  letter-spacing: 0.35em;
  color: var(--accent);
  text-shadow: var(--neon-glow);
  margin-bottom: 0.5rem;
}
.logo-sub {
  font-size: 0.85rem;
  color: var(--text-muted);
  letter-spacing: 0.15em;
  text-transform: uppercase;
}
.header-meta {
  margin-top: 1.2rem;
  display: flex;
  justify-content: center;
  gap: 2rem;
  flex-wrap: wrap;
  font-size: 0.8rem;
  color: var(--text-muted);
}
.header-meta span { display: inline-flex; align-items: center; gap: 0.35rem; }
.header-meta .val { color: var(--accent); }

/* ── Section Titles ────────────────────────────────────────── */
.section-title {
  font-size: 1.1rem;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--accent);
  margin: 2.5rem 0 1.2rem;
  padding-bottom: 0.4rem;
  border-bottom: 1px solid var(--border);
  position: relative;
}
.section-title::after {
  content: '';
  position: absolute; bottom: -1px; left: 0;
  width: 60px; height: 2px;
  background: var(--accent);
  box-shadow: 0 0 8px var(--accent);
}

/* ── Executive Summary Cards ───────────────────────────────── */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1rem;
}
.summary-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1.2rem;
  text-align: center;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.summary-card:hover {
  border-color: var(--accent);
  box-shadow: 0 0 20px var(--accent-dim);
}
.summary-card .label {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-muted);
  margin-bottom: 0.5rem;
}
.summary-card .value {
  font-size: 1.8rem;
  font-weight: 700;
  color: var(--text-primary);
}
.summary-card .value.accent { color: var(--accent); }
.summary-card .value.critical { color: var(--critical); }
.summary-card .value.high { color: var(--high); }
.summary-card .value.medium { color: var(--medium); }
.summary-card .value.low { color: var(--low); }

/* ── Severity badges ───────────────────────────────────────── */
.badge {
  display: inline-block;
  padding: 0.15em 0.6em;
  border-radius: 3px;
  font-size: 0.72rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  border: 1px solid;
}
.badge-critical { color: var(--critical); border-color: var(--critical); background: #ff2a6d18; }
.badge-high     { color: var(--high);     border-color: var(--high);     background: #ff6a0018; }
.badge-medium   { color: var(--medium);   border-color: var(--medium);   background: #ffd60018; }
.badge-low      { color: var(--low);      border-color: var(--low);      background: #00d4ff18; }
.badge-info     { color: var(--info);     border-color: var(--info);     background: #7a7d8518; }

/* ── Severity Chart (pure CSS horizontal bars) ─────────────── */
.chart { margin-bottom: 1.5rem; }
.chart-row {
  display: flex;
  align-items: center;
  margin-bottom: 0.55rem;
  gap: 0.8rem;
}
.chart-label {
  width: 80px;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
  text-align: right;
  flex-shrink: 0;
}
.chart-bar-container {
  flex: 1;
  height: 22px;
  background: var(--bg-secondary);
  border-radius: 3px;
  overflow: hidden;
  position: relative;
}
.chart-bar {
  height: 100%;
  border-radius: 3px;
  transition: width 0.6s ease;
  position: relative;
}
.chart-bar::after {
  content: '';
  position: absolute; inset: 0;
  background: linear-gradient(90deg, transparent 60%, rgba(255,255,255,0.08));
}
.chart-count {
  width: 32px;
  font-size: 0.8rem;
  font-weight: 600;
  text-align: left;
  flex-shrink: 0;
}

/* ── Findings Table ────────────────────────────────────────── */
.findings-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8rem;
}
.findings-table thead th {
  text-align: left;
  padding: 0.7rem 0.8rem;
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  background: var(--bg-secondary);
  position: sticky;
  top: 0;
  z-index: 2;
}
.findings-table tbody tr {
  border-bottom: 1px solid var(--border);
  transition: background 0.15s;
}
.findings-table tbody tr:hover { background: var(--bg-hover); }
.findings-table td {
  padding: 0.65rem 0.8rem;
  vertical-align: middle;
}
.findings-table td:first-child { width: 90px; }
.findings-table .cat-code {
  font-size: 0.7rem;
  color: var(--text-muted);
  letter-spacing: 0.04em;
}

/* ── Finding Detail Cards ──────────────────────────────────── */
.finding-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  margin-bottom: 1rem;
  overflow: hidden;
  transition: border-color 0.2s;
}
.finding-card:hover { border-color: var(--accent-dim); }
.finding-card summary {
  cursor: pointer;
  padding: 1rem 1.2rem;
  display: flex;
  align-items: center;
  gap: 0.8rem;
  list-style: none;
  user-select: none;
}
.finding-card summary::-webkit-details-marker { display: none; }
.finding-card summary::before {
  content: '\25B6'; /* right triangle */
  font-size: 0.6rem;
  color: var(--accent);
  transition: transform 0.2s;
  flex-shrink: 0;
}
.finding-card[open] summary::before { transform: rotate(90deg); }
.finding-card .finding-title {
  font-weight: 600;
  font-size: 0.9rem;
  flex: 1;
}
.finding-card .finding-id {
  font-size: 0.7rem;
  color: var(--text-muted);
}
.finding-body {
  padding: 0 1.2rem 1.2rem;
  display: grid;
  gap: 1rem;
}
.finding-body .field-label {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--accent);
  margin-bottom: 0.25rem;
}
.finding-body .field-value {
  font-size: 0.82rem;
  color: var(--text-primary);
  line-height: 1.5;
}
.finding-body pre {
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.8rem 1rem;
  font-size: 0.78rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--accent);
  max-height: 300px;
  overflow-y: auto;
}
.compliance-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}
.compliance-tag {
  display: inline-block;
  padding: 0.15em 0.55em;
  border-radius: 3px;
  font-size: 0.68rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  color: var(--text-muted);
}

/* ── Compliance Summary Table ──────────────────────────────── */
.compliance-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8rem;
}
.compliance-table th,
.compliance-table td {
  text-align: left;
  padding: 0.6rem 0.8rem;
  border-bottom: 1px solid var(--border);
}
.compliance-table thead th {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  background: var(--bg-secondary);
}
.compliance-table .count-cell {
  text-align: center;
  font-weight: 600;
}
.compliance-table .has-findings { color: var(--critical); }
.compliance-table .no-findings { color: var(--text-muted); }

/* ── Footer ────────────────────────────────────────────────── */
.footer {
  margin-top: 3rem;
  padding: 1.5rem;
  text-align: center;
  font-size: 0.72rem;
  color: var(--text-muted);
  border-top: 1px solid var(--border);
}
.footer .brand {
  color: var(--accent);
  font-weight: 600;
}

/* ── Responsive ────────────────────────────────────────────── */
@media (max-width: 768px) {
  .summary-grid { grid-template-columns: repeat(2, 1fr); }
  .header-meta { flex-direction: column; align-items: center; gap: 0.5rem; }
  .logo { font-size: 2rem; }
  .findings-table { font-size: 0.72rem; }
}
@media (max-width: 480px) {
  .summary-grid { grid-template-columns: 1fr; }
  .container { padding: 1rem; }
}
</style>
</head>
<body>

<div class="container">

  <!-- ═══════════ HEADER ═══════════ -->
  <header class="header">
    <div class="logo">AEGIS</div>
    <div class="logo-sub">LLM Security Scanner &mdash; Vulnerability Report</div>
    <div class="header-meta">
      <span>Target: <span class="val">{{ target }}</span></span>
      <span>Profile: <span class="val">{{ profile }}</span></span>
      <span>Date: <span class="val">{{ scan_date }}</span></span>
    </div>
  </header>

  <!-- ═══════════ EXECUTIVE SUMMARY ═══════════ -->
  <h2 class="section-title">Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-card">
      <div class="label">Total Findings</div>
      <div class="value accent">{{ total_findings }}</div>
    </div>
    <div class="summary-card">
      <div class="label">Critical</div>
      <div class="value critical">{{ sev_counts.critical }}</div>
    </div>
    <div class="summary-card">
      <div class="label">High</div>
      <div class="value high">{{ sev_counts.high }}</div>
    </div>
    <div class="summary-card">
      <div class="label">Medium</div>
      <div class="value medium">{{ sev_counts.medium }}</div>
    </div>
    <div class="summary-card">
      <div class="label">Low</div>
      <div class="value low">{{ sev_counts.low }}</div>
    </div>
    <div class="summary-card">
      <div class="label">Info</div>
      <div class="value" style="color:var(--info)">{{ sev_counts.info }}</div>
    </div>
    <div class="summary-card">
      <div class="label">Duration</div>
      <div class="value accent">{{ duration }}s</div>
    </div>
    <div class="summary-card">
      <div class="label">Cost (USD)</div>
      <div class="value accent">${{ cost }}</div>
    </div>
    <div class="summary-card">
      <div class="label">Scanners Run</div>
      <div class="value accent">{{ scanners_run | length }}</div>
    </div>
  </div>

  {% if scanners_run %}
  <div style="margin-top:0.8rem; font-size:0.75rem; color:var(--text-muted);">
    Scanners: {{ scanners_run | join(', ') }}
  </div>
  {% endif %}

  <!-- ═══════════ SEVERITY CHART ═══════════ -->
  <h2 class="section-title">Severity Distribution</h2>
  <div class="chart">
    {% for sev_name in ['critical', 'high', 'medium', 'low', 'info'] %}
    {% set count = sev_counts[sev_name] %}
    {% set pct = ((count / max_count * 100) | round(1)) if max_count > 0 else 0 %}
    <div class="chart-row">
      <div class="chart-label">{{ sev_name }}</div>
      <div class="chart-bar-container">
        <div class="chart-bar" style="width:{{ pct }}%; background:{{ sev_colors[sev_name] }};"></div>
      </div>
      <div class="chart-count" style="color:{{ sev_colors[sev_name] }};">{{ count }}</div>
    </div>
    {% endfor %}
  </div>

  <!-- ═══════════ FINDINGS TABLE ═══════════ -->
  {% if findings %}
  <h2 class="section-title">Findings Overview</h2>
  <table class="findings-table">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Category</th>
        <th>Title</th>
        <th>Technique</th>
      </tr>
    </thead>
    <tbody>
      {% for f in findings %}
      <tr>
        <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
        <td><span class="cat-code">{{ f.category_code }}</span></td>
        <td><a href="#finding-{{ f.id }}">{{ f.title }}</a></td>
        <td style="color:var(--text-muted);">{{ f.technique }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <!-- ═══════════ FINDING DETAILS ═══════════ -->
  {% if findings %}
  <h2 class="section-title">Finding Details</h2>
  {% for f in findings %}
  <details class="finding-card" id="finding-{{ f.id }}">
    <summary>
      <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
      <span class="finding-title">{{ f.title }}</span>
      <span class="finding-id">#{{ f.id }}</span>
    </summary>
    <div class="finding-body">

      <div>
        <div class="field-label">OWASP Category</div>
        <div class="field-value">{{ f.category }}</div>
      </div>

      <div>
        <div class="field-label">Description</div>
        <div class="field-value">{{ f.description }}</div>
      </div>

      <div>
        <div class="field-label">Technique</div>
        <div class="field-value">{{ f.technique }}</div>
      </div>

      {% if f.payload %}
      <div>
        <div class="field-label">Payload</div>
        <pre>{{ f.payload }}</pre>
      </div>
      {% endif %}

      {% if f.response %}
      <div>
        <div class="field-label">Response Excerpt</div>
        <pre>{{ f.response }}</pre>
      </div>
      {% endif %}

      {% if f.evidence %}
      <div>
        <div class="field-label">Evidence</div>
        <div class="field-value">{{ f.evidence }}</div>
      </div>
      {% endif %}

      {% if f.compliance %}
      <div>
        <div class="field-label">Compliance Mapping</div>
        <div class="compliance-tags">
          {% for tag in f.compliance.owasp_tags %}
          <span class="compliance-tag" style="border-color:var(--accent);color:var(--accent);">{{ tag }}</span>
          {% endfor %}
          {% for tag in f.compliance.eu_tags %}
          <span class="compliance-tag" style="border-color:#a78bfa;color:#a78bfa;">{{ tag }}</span>
          {% endfor %}
          {% for tag in f.compliance.nist_tags %}
          <span class="compliance-tag" style="border-color:#34d399;color:#34d399;">{{ tag }}</span>
          {% endfor %}
        </div>
      </div>
      {% endif %}

      {% if f.remediation %}
      <div>
        <div class="field-label">Remediation</div>
        <div class="field-value">{{ f.remediation }}</div>
      </div>
      {% endif %}

    </div>
  </details>
  {% endfor %}
  {% endif %}

  <!-- ═══════════ COMPLIANCE SUMMARY ═══════════ -->
  <h2 class="section-title">OWASP LLM Top 10 Compliance</h2>
  <table class="compliance-table">
    <thead>
      <tr>
        <th>Category</th>
        <th style="text-align:center;">Findings</th>
        <th>EU AI Act</th>
        <th>NIST AI RMF</th>
      </tr>
    </thead>
    <tbody>
      {% for row in compliance_rows %}
      <tr>
        <td>{{ row.category }}</td>
        <td class="count-cell {{ 'has-findings' if row.count > 0 else 'no-findings' }}">{{ row.count }}</td>
        <td style="font-size:0.72rem;color:var(--text-muted);">{{ row.eu_ai_act }}</td>
        <td style="font-size:0.72rem;color:var(--text-muted);">{{ row.nist }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <!-- ═══════════ FOOTER ═══════════ -->
  <footer class="footer">
    Generated by <span class="brand">AEGIS v0.1.0</span> - LLM Security Scanner<br>
    {{ generated_at }}
  </footer>

</div>
</body>
</html>
''')


class HTMLReporter(BaseReporter):
    # TODO: dark mode for the HTML report

    def generate(self, result: ScanResult, output_path: str) -> str:
        # Pre-compute template context
        sev_counts = {
            "critical": sum(1 for f in result.findings if f.severity == Severity.CRITICAL),
            "high":     sum(1 for f in result.findings if f.severity == Severity.HIGH),
            "medium":   sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
            "low":      sum(1 for f in result.findings if f.severity == Severity.LOW),
            "info":     sum(1 for f in result.findings if f.severity == Severity.INFO),
        }
        max_count = max(sev_counts.values()) if sev_counts else 1

        fctx = []
        for f in result.findings:
            mapping = ComplianceMapper.get_mapping(f.category)
            code = f.category.value.split(":")[0].strip()
            comp = {
                "owasp_tags": [f.category.value],
                "eu_tags": mapping.eu_ai_act,
                "nist_tags": mapping.nist_ai_rmf,
            }
            fctx.append({
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category.value,
                "category_code": code,
                "technique": f.technique,
                "payload": f.payload,
                "response": f.response[:500] if f.response else "",
                "evidence": f.evidence,
                "remediation": f.remediation,
                "compliance": comp,
            })

        # Build compliance summary rows (all 10 categories)
        owasp_counts: dict[str, int] = {}
        for f in result.findings:
            owasp_counts[f.category.value] = owasp_counts.get(f.category.value, 0) + 1

        compliance_rows = []
        for cat in OWASPCategory:
            mapping = ComplianceMapper.get_mapping(cat)
            compliance_rows.append({
                "category": cat.value,
                "count": owasp_counts.get(cat.value, 0),
                "eu_ai_act": "; ".join(mapping.eu_ai_act),
                "nist": "; ".join(mapping.nist_ai_rmf),
            })

        now = datetime.now(timezone.utc)
        scan_dt = datetime.fromtimestamp(result.start_time, tz=timezone.utc)

        html = _HTML_TEMPLATE.render(
            target=result.target,
            profile=result.profile,
            scan_date=scan_dt.strftime("%Y-%m-%d %H:%M UTC"),
            total_findings=len(result.findings),
            sev_counts=sev_counts,
            max_count=max_count,
            sev_colors=_SEV_COLORS,
            duration=round(result.duration_seconds, 1),
            cost=round(result.total_cost_usd, 4),
            scanners_run=result.scanners_run,
            findings=fctx,
            compliance_rows=compliance_rows,
            generated_at=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        return output_path
