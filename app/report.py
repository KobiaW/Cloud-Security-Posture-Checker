"""
report.py — Generates HTML report sections from findings.
Returns three HTML blocks: summary, details, remediation.
"""

from app.checks import Finding

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "INFO":     "#3b82f6",
}

SEVERITY_BG = {
    "CRITICAL": "#2d1515",
    "HIGH":     "#2d1a0e",
    "MEDIUM":   "#2a2200",
    "LOW":      "#0f2a14",
    "INFO":     "#0d1f3c",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}


def _badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#64748b")
    icon = SEVERITY_ICONS.get(severity, "⚪")
    return (
        f'<span style="background:{color}22; color:{color}; border:1px solid {color}66; '
        f'padding:2px 10px; border-radius:999px; font-size:0.72rem; '
        f'font-family:\'JetBrains Mono\',monospace; font-weight:600; letter-spacing:0.05em;">'
        f'{icon} {severity}</span>'
    )


def generate_report(findings: list[Finding]):
    failed = [f for f in findings if not f.passed]
    passed = [f for f in findings if f.passed]

    counts = {}
    for f in failed:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    # ── RISK SCORE ──
    weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    raw_score = sum(weights.get(sev, 0) * cnt for sev, cnt in counts.items())
    risk_score = min(100, raw_score)
    risk_label = (
        "CRITICAL RISK" if risk_score >= 60
        else "HIGH RISK" if risk_score >= 40
        else "MEDIUM RISK" if risk_score >= 20
        else "LOW RISK" if risk_score > 0
        else "SECURE"
    )
    score_color = (
        "#ef4444" if risk_score >= 60
        else "#f97316" if risk_score >= 40
        else "#eab308" if risk_score >= 20
        else "#22c55e"
    )

    # ────────────────────────────────
    # SUMMARY TAB
    # ────────────────────────────────
    sev_rows = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        sev_rows += f"""
        <tr>
            <td style="padding:8px 12px;">{_badge(sev)}</td>
            <td style="padding:8px 12px; text-align:center; font-family:'JetBrains Mono',monospace;
                       font-size:1.1rem; font-weight:700; color:{color if cnt > 0 else '#64748b'};">
                {cnt}
            </td>
        </tr>"""

    failed_list = ""
    for f in failed:
        failed_list += f"""
        <li style="margin:6px 0; font-size:0.88rem;">
            {_badge(f.severity)} &nbsp;
            <span style="color:#e2e8f0;">{f.id}</span>
            <span style="color:#94a3b8;"> — {f.title}</span>
        </li>"""

    passed_list = ""
    for f in passed:
        passed_list += f'<li style="margin:4px 0; font-size:0.85rem; color:#22c55e;">✅ {f.id} — {f.title}</li>'

    summary_html = f"""
    <div style="font-family:'Syne',sans-serif; color:#e2e8f0; padding:1rem 0;">

        <!-- Risk Score Card -->
        <div style="background:#111827; border:1px solid {score_color}44; border-radius:12px;
                    padding:1.5rem 2rem; margin-bottom:1.5rem; display:flex;
                    align-items:center; gap:2rem;">
            <div style="text-align:center;">
                <div style="font-size:3rem; font-weight:800; color:{score_color};
                            font-family:'JetBrains Mono',monospace; line-height:1;">
                    {risk_score}
                </div>
                <div style="font-size:0.7rem; color:#64748b; letter-spacing:0.15em; margin-top:4px;">
                    RISK SCORE
                </div>
            </div>
            <div>
                <div style="font-size:1.3rem; font-weight:700; color:{score_color};">{risk_label}</div>
                <div style="color:#94a3b8; font-size:0.88rem; margin-top:4px;">
                    {len(failed)} issue{'s' if len(failed) != 1 else ''} detected &nbsp;·&nbsp;
                    {len(passed)} check{'s' if len(passed) != 1 else ''} passed
                </div>
            </div>
        </div>

        <!-- Severity Breakdown -->
        <div style="background:#111827; border:1px solid #1e2d45; border-radius:12px;
                    padding:1rem 1.5rem; margin-bottom:1.5rem;">
            <div style="font-family:'JetBrains Mono',monospace; color:#00d4ff;
                        font-size:0.7rem; letter-spacing:0.15em; margin-bottom:0.75rem;">
                SEVERITY BREAKDOWN
            </div>
            <table style="width:100%; border-collapse:collapse;">
                {sev_rows}
            </table>
        </div>

        <!-- Failed Checks -->
        {"" if not failed else f'''
        <div style="background:#111827; border:1px solid #1e2d45; border-radius:12px;
                    padding:1rem 1.5rem; margin-bottom:1.5rem;">
            <div style="font-family:\'JetBrains Mono\',monospace; color:#ff6b35;
                        font-size:0.7rem; letter-spacing:0.15em; margin-bottom:0.75rem;">
                FAILED CHECKS
            </div>
            <ul style="margin:0; padding-left:0.5rem; list-style:none;">{failed_list}</ul>
        </div>
        '''}

        <!-- Passed Checks -->
        {"" if not passed else f'''
        <div style="background:#111827; border:1px solid #1e2d45; border-radius:12px;
                    padding:1rem 1.5rem;">
            <div style="font-family:\'JetBrains Mono\',monospace; color:#22c55e;
                        font-size:0.7rem; letter-spacing:0.15em; margin-bottom:0.75rem;">
                PASSED CHECKS
            </div>
            <ul style="margin:0; padding-left:0.5rem; list-style:none;">{passed_list}</ul>
        </div>
        '''}
    </div>
    """

    # ────────────────────────────────
    # DETAILS TAB
    # ────────────────────────────────
    detail_cards = ""
    for f in findings:
        status_icon = "✅" if f.passed else "❌"
        bg = "#0f2a14" if f.passed else SEVERITY_BG.get(f.severity, "#1a1a2e")
        border_color = "#22c55e44" if f.passed else SEVERITY_COLORS.get(f.severity, "#64748b") + "44"

        affected_html = ""
        if f.affected:
            items = "".join(
                f'<li style="font-family:\'JetBrains Mono\',monospace; font-size:0.78rem; '
                f'color:#94a3b8; margin:3px 0; background:#0a0e1a; padding:4px 8px; '
                f'border-radius:4px; word-break:break-all;">{item}</li>'
                for item in f.affected
            )
            affected_html = f"""
            <div style="margin-top:0.75rem;">
                <div style="font-size:0.72rem; color:#64748b; letter-spacing:0.1em;
                            margin-bottom:4px; font-family:'JetBrains Mono',monospace;">
                    AFFECTED
                </div>
                <ul style="margin:0; padding-left:0.5rem; list-style:none;">{items}</ul>
            </div>"""

        detail_cards += f"""
        <div style="background:{bg}; border:1px solid {border_color}; border-radius:10px;
                    padding:1rem 1.25rem; margin-bottom:1rem;">
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:0.5rem;">
                <span style="font-family:'JetBrains Mono',monospace; color:#64748b;
                             font-size:0.75rem;">{f.id}</span>
                {_badge(f.severity)}
                <span style="margin-left:auto; font-size:1rem;">{status_icon}</span>
            </div>
            <div style="font-weight:700; font-size:0.98rem; color:#e2e8f0; margin-bottom:0.5rem;">
                {f.title}
            </div>
            <div style="color:#94a3b8; font-size:0.87rem; line-height:1.6;">
                {f.description}
            </div>
            {affected_html}
        </div>"""

    details_html = f"""
    <div style="font-family:'Syne',sans-serif; color:#e2e8f0; padding:1rem 0;">
        {detail_cards if detail_cards else '<p style="color:#64748b;">No findings to display.</p>'}
    </div>"""

    # ────────────────────────────────
    # REMEDIATION TAB
    # ────────────────────────────────
    rem_cards = ""
    failed_findings = [f for f in findings if not f.passed]
    if not failed_findings:
        rem_cards = """
        <div style="text-align:center; padding:3rem; color:#22c55e;">
            <div style="font-size:3rem; margin-bottom:1rem;">✅</div>
            <div style="font-size:1.1rem; font-weight:700;">No remediations needed.</div>
            <div style="color:#64748b; margin-top:0.5rem;">All checks passed.</div>
        </div>"""
    else:
        for i, f in enumerate(failed_findings, 1):
            color = SEVERITY_COLORS.get(f.severity, "#64748b")
            ref_link = (
                f'<a href="{f.reference}" target="_blank" '
                f'style="color:#00d4ff; font-size:0.8rem; font-family:\'JetBrains Mono\',monospace;">'
                f'AWS Docs →</a>'
            ) if f.reference else ""

            rem_cards += f"""
            <div style="background:#111827; border-left:3px solid {color};
                        border-radius:0 10px 10px 0; padding:1rem 1.25rem; margin-bottom:1rem;">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:0.5rem;">
                    <span style="font-family:'JetBrains Mono',monospace; color:#64748b;
                                 font-size:0.72rem;">#{i} · {f.id}</span>
                    {_badge(f.severity)}
                </div>
                <div style="font-weight:700; color:#e2e8f0; margin-bottom:0.5rem;">{f.title}</div>
                <div style="color:#94a3b8; font-size:0.87rem; line-height:1.6;
                            background:#0a0e1a; padding:10px 14px; border-radius:6px;
                            font-family:'JetBrains Mono',monospace; white-space:pre-wrap;">
                    {f.remediation}
                </div>
                {"" if not ref_link else f'<div style="margin-top:0.6rem;">{ref_link}</div>'}
            </div>"""

    remediation_html = f"""
    <div style="font-family:'Syne',sans-serif; color:#e2e8f0; padding:1rem 0;">
        {rem_cards}
    </div>"""

    return summary_html, details_html, remediation_html
