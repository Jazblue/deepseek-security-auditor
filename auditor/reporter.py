"""
Security Auditor - Report Generator Module
"""
import logging
import html
from datetime import datetime
from pathlib import Path
from typing import List

from .config import Finding, Severity, mask_line_content

logger = logging.getLogger("security_auditor.report")

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#16a34a",
    Severity.INFO: "#2563eb",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "🔵",
}


def generate_report(findings: List[Finding], output_path: str, target_dir: str) -> str:
    """Generate a professional HTML security report."""
    total = len(findings)
    by_severity = {s: 0 for s in Severity}
    by_category = {}
    for f in findings:
        by_severity[f.severity] += 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    rows = "".join(_finding_row(f) for f in sorted(findings, key=lambda x: (list(Severity).index(x.severity), x.category)))

    severity_summary = "".join(
        f'<div class="severity-badge" style="background:{SEVERITY_COLORS[s]}">{s.value.upper()}: {by_severity[s]}</div>'
        for s in Severity
    )

    category_summary = "".join(
        f'<div class="category-tag">{html.escape(cat)}: {count}</div>'
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1])
    )

    findings_section = (
        f'<table><thead><tr><th>Severity</th><th>Category</th><th>Message</th><th>Location</th><th>Code</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table>'
        if total > 0 else '<div class="no-findings"><div class="icon">✅</div>No security issues detected.</div>'
    )

    report_html = _TEMPLATE.format(
        title="Security Audit Report",
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=html.escape(target_dir),
        total=total,
        critical=by_severity[Severity.CRITICAL],
        high=by_severity[Severity.HIGH],
        medium=by_severity[Severity.MEDIUM],
        low=by_severity[Severity.LOW],
        info=by_severity[Severity.INFO],
        severity_summary=severity_summary,
        category_summary=category_summary,
        findings_section=findings_section,
        findings_rows=rows,
        has_findings=total > 0,
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report_html, encoding="utf-8")
    logger.info("Report written to %s", output_path)
    return str(out.absolute())


def _finding_row(f: Finding) -> str:
    color = SEVERITY_COLORS[f.severity]
    icon = SEVERITY_ICONS[f.severity]
    # Final masking pass: even if a scanner shipped an unmasked value, the
    # report never renders a plaintext secret.
    message = mask_line_content(f.message)
    snippet = mask_line_content(f.code_snippet or "")
    return f"""
    <tr class="finding-row">
        <td><span class="severity-pill" style="background:{color}">{icon} {f.severity.value.upper()}</span></td>
        <td>{html.escape(f.category)}</td>
        <td>{html.escape(message)}</td>
        <td><code>{html.escape(f.file_path)}</code>{f'<br><small>Line {f.line_number}</small>' if f.line_number else ''}</td>
        <td><pre class="code-snippet">{html.escape(snippet)}</pre></td>
        <td class="remediation">{html.escape(f.remediation)}</td>
    </tr>"""


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface2: #334155;
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --border: #475569;
            --accent: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{ font-size: 2rem; color: var(--accent); }}
        .meta {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: var(--surface);
            border-radius: 8px;
            padding: 1.25rem;
            text-align: center;
            border: 1px solid var(--border);
        }}
        .summary-card .number {{ font-size: 2.5rem; font-weight: 700; }}
        .summary-card .label {{ color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .summary-card.critical .number {{ color: #dc2626; }}
        .summary-card.high .number {{ color: #ea580c; }}
        .summary-card.medium .number {{ color: #ca8a04; }}
        .summary-card.low .number {{ color: #16a34a; }}
        .summary-card.info .number {{ color: #2563eb; }}
        .section-title {{ font-size: 1.25rem; margin: 2rem 0 1rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }}
        th {{ background: var(--surface2); padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; }}
        td {{ padding: 0.75rem 1rem; vertical-align: top; border-top: 1px solid var(--border); }}
        .finding-row:hover {{ background: var(--surface2); }}
        .severity-pill {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
            text-transform: uppercase;
        }}
        code {{ background: var(--surface2); padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }}
        pre.code-snippet {{
            background: #0f172a;
            padding: 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 120px;
        }}
        .remediation {{ font-size: 0.85rem; color: var(--text-muted); }}
        .no-findings {{ text-align: center; padding: 3rem; color: var(--text-muted); }}
        .no-findings .icon {{ font-size: 3rem; margin-bottom: 1rem; }}
        footer {{ margin-top: 2rem; color: var(--text-muted); font-size: 0.8rem; text-align: center; }}
        .badge-row {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 1rem 0; }}
        .severity-badge {{ padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.8rem; color: white; font-weight: 600; }}
        .category-tag {{ background: var(--surface2); padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.8rem; color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Audit Report</h1>
            <div class="meta">
                Generated: {generated} &nbsp;|&nbsp; Target: <code>{target}</code>
            </div>
        </header>

        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="number">{critical}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{high}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{medium}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{low}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="number">{info}</div>
                <div class="label">Info</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color:var(--accent)">{total}</div>
                <div class="label">Total Findings</div>
            </div>
        </div>

        <div class="badge-row">
            {category_summary}
        </div>

        <h2 class="section-title">Findings ({total})</h2>

        {findings_section}

        <footer>
            <p>Generated by Security Auditor &mdash; Automated static analysis tool</p>
        </footer>
    </div>
</body>
</html>"""
