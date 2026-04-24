from __future__ import annotations

from pathlib import Path

from osint_agent.models import Finding, Observable, ReportData


EVIDENCE_TYPES = {
    "social_profile",
    "email_usage",
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
TOOL_RESULT_TYPES = {
    "breach_count",
    "collector_status",
}
PIVOT_TYPES = {
    "search_url",
    "registry_search_url",
}
HUB_TYPES = {"resource_hub"}


def _is_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def _format_value(observable: Observable) -> str:
    if _is_url(observable.value):
        return f"[open]({observable.value})"
    return f"`{observable.value}`"


def _split_observables(
    observables: list[Observable],
) -> tuple[list[Observable], list[Observable], list[Observable], list[Observable], list[Observable]]:
    evidence: list[Observable] = []
    derived: list[Observable] = []
    tool_results: list[Observable] = []
    pivots: list[Observable] = []
    hubs: list[Observable] = []
    other: list[Observable] = []

    for observable in observables:
        if observable.type in EVIDENCE_TYPES:
            evidence.append(observable)
        elif observable.type in DERIVED_TYPES:
            derived.append(observable)
        elif observable.type in TOOL_RESULT_TYPES:
            tool_results.append(observable)
        elif observable.type in PIVOT_TYPES:
            pivots.append(observable)
        elif observable.type in HUB_TYPES:
            hubs.append(observable)
        else:
            other.append(observable)

    return evidence, derived, tool_results, pivots, hubs, other


def _build_analyst_highlights(
    report: ReportData,
    evidence: list[Observable],
    derived: list[Observable],
    tool_results: list[Observable],
    pivots: list[Observable],
) -> list[str]:
    highlights: list[str] = []

    breach_counts = [observable.value for observable in tool_results if observable.type == "breach_count"]
    if breach_counts:
        count_values = ", ".join(breach_counts)
        if any(value != "0" for value in breach_counts):
            highlights.append(f"Breach-related enrichment returned count values: {count_values}.")
        else:
            highlights.append("h8mail did not report breach hits for this email in the current run.")

    collector_statuses = [observable.value for observable in tool_results if observable.type == "collector_status"]
    if collector_statuses:
        highlights.append(f"Collector execution notes: {'; '.join(collector_statuses[:3])}.")

    social_hits = [observable for observable in evidence if observable.type in {"social_profile", "email_usage"}]
    if social_hits:
        highlights.append(f"Direct social or account-usage signals collected: {len(social_hits)}.")
    elif report.target and "@" in report.target:
        highlights.append("No direct social or account-usage hits were confirmed for the email in this run.")

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


def _display_type_name(value: str) -> str:
    return value.replace("_", " ").title()


PIVOT_LABELS = {
    "google_email_general": ("Google exact email search", "Search for public mentions of the exact email string."),
    "google_email_social": ("Google social search", "Look for the email on major social platforms and public communities."),
    "hibp_reference": ("Have I Been Pwned", "Manual breach-reference check for the email."),
    "google_email_files": ("Indexed file search", "Search for indexed documents mentioning the email."),
    "google_person_general": ("Google person search", "Search for exact-name mentions."),
    "google_person_social": ("Google social profile search", "Search for exact-name social profile hits."),
    "google_person_documents": ("Document search", "Search for PDFs and documents mentioning the name."),
    "google_person_images": ("Image search", "Search for public images tied to the name."),
    "google_person_github": ("GitHub mention search", "Search for public GitHub mentions of the name."),
    "google_phone_general": ("Google phone search", "Search for public mentions of the phone number."),
    "google_phone_social": ("Phone social search", "Search for social-platform references to the phone number."),
    "google_location_general": ("Location search", "Search for public references to the location."),
    "google_maps_location": ("Google Maps search", "Open a map search for the location."),
    "openstreetmap_location": ("OpenStreetMap search", "Search the location in OpenStreetMap."),
    "google_document_general": ("Document keyword search", "Search for direct references to the document string."),
    "google_document_files": ("Document file search", "Search indexed documents and spreadsheets mentioning the value."),
    "google_document_github": ("GitHub document search", "Search GitHub for references to the document string."),
    "crtsh_lookup": ("crt.sh search", "Search certificate transparency records."),
    "urlscan_search": ("urlscan search", "Search passive scan data and observed URLs."),
    "github_code_search": ("GitHub code search", "Search public code and repositories."),
    "google_maps_canada": ("Google Maps Canada", "Search for Canada-focused map references."),
    "openstreetmap_search": ("OpenStreetMap Canada", "Search the value in OpenStreetMap with a Canada pivot."),
    "google_canada411": ("Canada411 search", "Search Canadian phone and people directories."),
    "google_gc_ca": ("Government of Canada search", "Search public Government of Canada references."),
    "google_canlii": ("CanLII search", "Search Canadian legal references."),
    "google_opencanada": ("Open Canada search", "Search Canadian open-government data."),
    "google_sedar": ("SEDAR+ search", "Search Canadian securities and filing references."),
    "google_canada_business": ("Canada business registry search", "Search Canadian business registry references."),
    "variant_search": ("Variant search", "Search for alternate username or alias variants."),
    "archive_search": ("Cached search result", "Open an archive/cached query for the value."),
    "images_search": ("Image search", "Search public images tied to the value."),
    "wayback_search": ("Wayback Machine", "Search archived snapshots of the target URL or value."),
    "google_general": ("Google exact match search", "Search general web references for the value."),
    "google_social": ("Google social search", "Search common social platforms for the value."),
    "github_search": ("GitHub user search", "Search GitHub user profiles for the value."),
    "reddit_search": ("Reddit search", "Search Reddit references for the value."),
    "google_github": ("Google GitHub search", "Search Google for GitHub-hosted references."),
    "mastodon_search": ("Mastodon search", "Search selected Mastodon instances."),
    "gitlab_search": ("GitLab user search", "Search GitLab users for the value."),
    "profile_reference": ("Profile URL", "Open the supplied profile URL directly."),
    "wayback_profile": ("Archived profile search", "Search archived snapshots for the supplied profile URL."),
    "opencorporates": ("OpenCorporates", "Search public company records."),
    "canada_business": ("Canada business registry", "Search Canadian business registry records."),
    "sec_edgar": ("SEC EDGAR", "Search U.S. SEC filings and company references."),
}


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


def _render_pivot_table(title: str, observables: list[Observable]) -> list[str]:
    lines: list[str] = [title, ""]
    if not observables:
        lines.extend(["No suggested pivots were recorded.", ""])
        return lines

    lines.extend(["| Pivot | Why it matters | Link |", "|---|---|---|"])
    for observable in observables:
        label, purpose = PIVOT_LABELS.get(observable.source, (_display_type_name(observable.source), "Suggested follow-up pivot."))
        lines.append(f"| {label} | {purpose} | {_format_value(observable)} |")
    lines.append("")
    return lines


def render_markdown_report(report: ReportData, template_dir: Path, output_path: Path) -> Path:
    _ = template_dir
    evidence, derived, tool_results, pivots, hubs, other = _split_observables(report.observables)
    highlights = _build_analyst_highlights(report, evidence, derived, tool_results, pivots)

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
        f"- Tool results: {len(tool_results)}",
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
    lines.extend(_render_observable_table("## Tool Results", tool_results))
    lines.extend(_render_observable_table("## Derived Clues", derived))
    lines.extend(_render_pivot_table("## Suggested Pivots", pivots))
    lines.extend(_render_pivot_table("## Reference Hubs", hubs))
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
