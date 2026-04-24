from __future__ import annotations

from pathlib import Path

from osint_agent.models import Finding, Observable, ReportData


EVIDENCE_TYPES = {
    "social_profile",
    "email_usage",
    "breach_count",
    "breach_artifact",
    "email",
    "ip",
    "domain",
    "phone_country",
    "phone_carrier",
    "phone_line_type",
    "phone_e164",
    "phone_international",
    "phone_number",
}
DERIVED_TYPES = {
    "candidate_username",
    "raw_artifact",
}
PIVOT_TYPES = {
    "search_url",
    "registry_search_url",
    "resource_hub",
}


def _is_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def _format_value(observable: Observable) -> str:
    if _is_url(observable.value):
        return f"[open]({observable.value})"
    return f"`{observable.value}`"


def _split_observables(observables: list[Observable]) -> tuple[list[Observable], list[Observable], list[Observable], list[Observable]]:
    evidence: list[Observable] = []
    derived: list[Observable] = []
    pivots: list[Observable] = []
    other: list[Observable] = []

    for observable in observables:
        if observable.type in EVIDENCE_TYPES:
            evidence.append(observable)
        elif observable.type in DERIVED_TYPES:
            derived.append(observable)
        elif observable.type in PIVOT_TYPES:
            pivots.append(observable)
        else:
            other.append(observable)

    return evidence, derived, pivots, other


def _build_analyst_highlights(report: ReportData, evidence: list[Observable], derived: list[Observable], pivots: list[Observable]) -> list[str]:
    highlights: list[str] = []

    breach_counts = [observable.value for observable in evidence if observable.type == "breach_count"]
    if breach_counts:
        highlights.append(f"Breach-related enrichment returned count values: {', '.join(breach_counts)}.")

    social_hits = [observable for observable in evidence if observable.type in {"social_profile", "email_usage"}]
    if social_hits:
        highlights.append(f"Direct social or account-usage signals collected: {len(social_hits)}.")

    candidate_usernames = [observable.value for observable in derived if observable.type == "candidate_username"]
    if candidate_usernames:
        highlights.append(f"Derived candidate usernames: {', '.join(candidate_usernames[:5])}.")

    if not evidence:
        if pivots or derived:
            highlights.append("No direct evidence was collected for the target; the current output is mostly derived pivots and suggested next searches.")
        else:
            highlights.append("No direct evidence or useful pivots were collected for the target.")

    if not highlights:
        highlights.append("Collected evidence exists, but it should still be manually validated before any conclusion is drawn.")

    return highlights


def _render_finding_lines(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Severity: {finding.severity}",
                    f"- Source: {finding.source}",
                    f"- Confidence: {finding.confidence}",
                    f"- Description: {finding.description}",
                    "",
                ]
            )
    else:
        lines.extend(["No workflow findings were recorded.", ""])
    return lines


def _render_observable_table(title: str, observables: list[Observable]) -> list[str]:
    lines: list[str] = [title, ""]
    if not observables:
        lines.extend(["No entries recorded.", ""])
        return lines

    lines.extend(["| Type | Value | Source |", "|---|---|---|"])
    for observable in observables:
        lines.append(f"| `{observable.type}` | {_format_value(observable)} | `{observable.source}` |")
    lines.append("")
    return lines


def render_markdown_report(report: ReportData, template_dir: Path, output_path: Path) -> Path:
    _ = template_dir
    evidence, derived, pivots, other = _split_observables(report.observables)
    highlights = _build_analyst_highlights(report, evidence, derived, pivots)

    lines: list[str] = [
        "# OSINT Report",
        "",
        "## Executive Summary",
        "",
        f"- Target: {report.target}",
        f"- Profile: {report.profile}",
        f"- Generated at: {report.generated_at.isoformat()}",
        f"- Mode: {report.mode}",
        f"- Workflow findings: {len(report.findings)}",
        f"- Direct evidence items: {len(evidence)}",
        f"- Derived clues: {len(derived)}",
        f"- Suggested pivots: {len(pivots)}",
        "",
        "## Analyst Highlights",
        "",
    ]

    for highlight in highlights:
        lines.append(f"- {highlight}")
    lines.append("")

    lines.extend(["## Workflow Findings", ""])
    lines.extend(_render_finding_lines(report.findings))

    lines.extend(_render_observable_table("## Direct Evidence", evidence))
    lines.extend(_render_observable_table("## Derived Clues", derived))
    lines.extend(_render_observable_table("## Suggested Pivots", pivots))
    if other:
        lines.extend(_render_observable_table("## Other Observables", other))

    lines.extend(
        [
            "## Notes",
            "",
            "This report is generated from a controlled OSINT pipeline and should be reviewed by an analyst before redistribution.",
            "",
        ]
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
