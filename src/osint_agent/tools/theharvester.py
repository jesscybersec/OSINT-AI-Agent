from __future__ import annotations

import re

from osint_agent.models import Observable, Target
from osint_agent.settings import Settings
from osint_agent.tools._common import DOMAIN_PATTERN, EMAIL_PATTERN, IPV4_PATTERN, derive_infra_query, run_command, summarize_command_failure, summarize_tool_warning, unique_strings, write_raw_output


SECTION_HEADER_RE = re.compile(r"^\[\*\]\s+(.+?):?\s*$")
ASN_RE = re.compile(r"\bAS\d+\b", re.IGNORECASE)


def _extract_section_lines(stdout: str, header_startswith: str) -> list[str]:
    lines = stdout.splitlines()
    collecting = False
    output: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        match = SECTION_HEADER_RE.match(line)
        if match:
            section_name = match.group(1).strip().lower()
            if collecting:
                break
            if section_name.startswith(header_startswith.lower()):
                collecting = True
            continue
        if collecting:
            if set(line) <= {"-"}:
                continue
            output.append(line)
    return output


def _parse_theharvester_sections(stdout: str) -> list[Observable]:
    observables: list[Observable] = []

    for line in _extract_section_lines(stdout, "Interesting Urls found"):
        if line.startswith("http://") or line.startswith("https://"):
            observables.append(Observable(type="url", value=line, source="theHarvester", confidence=0.78, tags=["theharvester", "url-enum"]))

    for line in _extract_section_lines(stdout, "ASNS found"):
        for match in ASN_RE.findall(line):
            observables.append(Observable(type="asn", value=match.upper(), source="theHarvester", confidence=0.72, tags=["theharvester", "asn-enum"]))

    for line in _extract_section_lines(stdout, "Hosts found"):
        host = line.split(":", 1)[0].strip()
        if DOMAIN_PATTERN.fullmatch(host):
            observables.append(Observable(type="domain", value=host, source="theHarvester", confidence=0.8, tags=["theharvester", "host-enum"]))
        if ":" in line:
            ip_candidate = line.split(":", 1)[1].strip()
            if IPV4_PATTERN.fullmatch(ip_candidate):
                observables.append(Observable(type="ip", value=ip_candidate, source="theHarvester", confidence=0.76, tags=["theharvester", "host-enum"]))

    return observables


def run(target: Target, settings: Settings) -> list[Observable]:
    if target.type not in {"domain", "organization", "company", "email"}:
        return []

    query = target.value if target.type == "email" else derive_infra_query(target.type, target.value)[0]
    command = [settings.theharvester_binary, "-d", query, "-b", settings.theharvester_sources, "-l", "100"]
    result = run_command(command, timeout=settings.theharvester_timeout)
    if not result.found:
        return [
            Observable(
                type="collector_status",
                value=f"theHarvester binary not found: {settings.theharvester_binary}",
                source="theHarvester",
                confidence=0.98,
                tags=["collector-status", "missing-binary"],
            )
        ]

    if result.returncode == 124:
        return [
            Observable(
                type="collector_status",
                value=f"theHarvester timed out after {settings.theharvester_timeout}s while querying '{query}'",
                source="theHarvester",
                confidence=0.95,
                tags=["collector-status", "timeout"],
            )
        ]

    if result.stdout:
        write_raw_output(settings.data_dir, "theharvester", target.value, "txt", result.stdout)
    if result.stderr:
        write_raw_output(settings.data_dir, "theharvester", f"{target.value}_stderr", "log", result.stderr)

    observables: list[Observable] = []
    for match in unique_strings(EMAIL_PATTERN.findall(result.stdout)):
        observables.append(Observable(type="email", value=match, source="theHarvester", confidence=0.8, tags=["theharvester", "email-enum"]))
    for match in unique_strings(IPV4_PATTERN.findall(result.stdout)):
        observables.append(Observable(type="ip", value=match, source="theHarvester", confidence=0.76, tags=["theharvester", "host-enum"]))
    for match in unique_strings(DOMAIN_PATTERN.findall(result.stdout)):
        observables.append(Observable(type="domain", value=match, source="theHarvester", confidence=0.75, tags=["theharvester", "domain-enum"]))
    observables.extend(_parse_theharvester_sections(result.stdout))

    if observables and result.returncode != 0:
        warning = summarize_tool_warning(result.stderr, result.stdout, result.returncode)
        observables.append(
            Observable(
                type="collector_status",
                value=f"theHarvester returned results with warnings: {warning}",
                source="theHarvester",
                confidence=0.7,
                tags=["collector-status", "warning"],
            )
        )
        return observables

    if result.returncode != 0:
        detail = summarize_command_failure(result.stderr, result.stdout, result.returncode)
        return [
            Observable(
                type="collector_status",
                value=f"theHarvester exited with {detail} while querying '{query}'",
                source="theHarvester",
                confidence=0.9,
                tags=["collector-status", "error"],
            )
        ]
    return observables
