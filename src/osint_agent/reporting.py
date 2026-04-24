from __future__ import annotations

from pathlib import Path

from osint_agent.models import CollectorRun, Finding, Observable, ReportData


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


def _build_key_findings(
    report: ReportData,
    evidence: list[Observable],
    derived: list[Observable],
    tool_results: list[Observable],
    collector_runs: list[CollectorRun],
) -> list[str]:
    findings: list[str] = []

    breach_counts = [observable.value for observable in tool_results if observable.type == "breach_count"]
    if breach_counts:
        count_values = ", ".join(breach_counts)
        if any(value != "0" for value in breach_counts):
            findings.append(f"Breach-related enrichment returned count values: {count_values}.")
        else:
            findings.append("h8mail did not report breach hits for this email in the current run.")

    collector_statuses = [observable.value for observable in tool_results if observable.type == "collector_status"]
    if collector_statuses:
        findings.append(f"Collector execution notes: {'; '.join(collector_statuses[:3])}.")

    social_hits = [observable for observable in evidence if observable.type in {"social_profile", "email_usage"}]
    if social_hits:
        findings.append(f"Direct social or account-usage signals collected: {len(social_hits)}.")
    elif report.target and "@" in report.target:
        findings.append("No direct social or account-usage hits were confirmed for the email in this run.")

    candidate_usernames = [observable.value for observable in derived if observable.type == "candidate_username"]
    if candidate_usernames:
        findings.append(f"Derived candidate usernames: {', '.join(candidate_usernames[:5])}.")

    successful_collectors = [run for run in collector_runs if run.status == "completed" and run.observable_count > 0]
    timeout_collectors = [run for run in collector_runs if run.status == "timeout"]
    if successful_collectors:
        findings.append(
            "Collectors with usable output: "
            + ", ".join(f"{run.collector} ({run.observable_count})" for run in successful_collectors[:5])
            + "."
        )

    if timeout_collectors:
        findings.append("Collector timeouts affected coverage: " + ", ".join(run.collector for run in timeout_collectors) + ".")

    if not evidence and not successful_collectors:
        findings.append("No direct evidence was confirmed by the current collector set; the run mostly produced pivots, references, or execution notes.")

    if not findings:
        findings.append("Collected evidence exists, but it should still be manually validated before any conclusion is drawn.")

    return findings


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


def _status_label(status: str) -> str:
    return {
        "completed": "Completed",
        "timeout": "Timed out",
        "missing": "Missing",
        "skipped": "Skipped",
    }.get(status, status.title())


def _build_scope_lines(report: ReportData) -> list[str]:
    return [
        "## Scope",
        "",
        f"- Investigation target: `{report.target}`",
        f"- Target type: `{report.target_type}`",
        f"- Profile: `{report.profile}`",
        f"- Collection mode: `{report.mode}`",
        "",
        "## Methodology",
        "",
        "This report separates confirmed output, collector execution status, derived leads, and follow-up pivots.",
        "It is meant to show what was searched, what returned evidence, what failed, and what should be reviewed next.",
        "",
    ]


def _render_collector_summary(collector_runs: list[CollectorRun]) -> list[str]:
    lines = ["## Collector Execution Summary", ""]
    if not collector_runs:
        lines.extend(["No collectors were executed for this target/profile combination.", ""])
        return lines

    lines.extend(["| Collector | Query Used | Status | Results | Note |", "|---|---|---|---:|---|"])
    for run in collector_runs:
        lines.append(
            f"| `{run.collector}` | `{run.query}` | {_status_label(run.status)} | {run.observable_count} | {run.note or ''} |"
        )
    lines.append("")
    return lines


def _render_priority_actions(report: ReportData, collector_runs: list[CollectorRun], pivots: list[Observable]) -> list[str]:
    lines = ["## Recommended Next Steps", ""]
    actions: list[str] = []

    if any(run.status == "timeout" for run in collector_runs):
        actions.append("Re-run the timed-out collectors individually or tune their sources before concluding that the target has low public exposure.")

    if report.target_type in {"domain", "subdomain", "hostname", "url"}:
        actions.append("Review certificate-transparency, passive scan, and archived-web pivots before escalating to active checks.")

    if report.target_type in {"email", "username", "alias", "social_handle", "profile_url", "person_name", "phone"}:
        actions.append("Treat derived identity clues as leads only until they are manually confirmed by source review.")

    if pivots:
        actions.append("Open the suggested pivots starting with the most target-specific sources rather than generic references.")

    if not actions:
        actions.append("Review the collector summary and validate all findings manually before redistribution.")

    for action in actions:
        lines.append(f"- {action}")
    lines.append("")
    return lines


def render_markdown_report(report: ReportData, template_dir: Path, output_path: Path) -> Path:
    _ = template_dir
    evidence, derived, tool_results, pivots, hubs, other = _split_observables(report.observables)
    highlights = _build_key_findings(report, evidence, derived, tool_results, report.collector_runs)

    lines: list[str] = [
        "# OSINT Investigation Report",
        "",
        "## Executive Summary",
        "",
        f"This run assessed `{report.target}` as a `{report.target_type}` target using the `{report.profile}` profile in `{report.mode}` mode.",
        f"Generated at `{report.generated_at.isoformat()}`.",
        "",
        "## Key Findings",
        "",
    ]

    for highlight in highlights:
        lines.append(f"- {highlight}")
    lines.append("")

    lines.extend(_build_scope_lines(report))
    lines.extend(["## Analytical Findings", ""])
    lines.extend(_render_finding_lines(report.findings))

    lines.extend(_render_collector_summary(report.collector_runs))
    lines.extend(_render_observable_table("## Confirmed Evidence", evidence))
    lines.extend(_render_observable_table("## Collector Notes", tool_results))
    lines.extend(_render_observable_table("## Leads Requiring Validation", derived))
    lines.extend(_render_priority_actions(report, report.collector_runs, pivots))
    lines.extend(_render_pivot_table("## Suggested Pivots", pivots))
    lines.extend(_render_pivot_table("## Reference Hubs", hubs))
    if other:
        lines.extend(_render_observable_table("## Supporting Observables", other))

    lines.extend(
        [
            "## Analyst Note",
            "",
            "This document is a controlled OSINT working report. Confirm every material claim against the source or raw collector output before sharing it outside the investigation context.",
            "",
        ]
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
