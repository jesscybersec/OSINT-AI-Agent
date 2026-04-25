from __future__ import annotations

from osint_agent.models import Observable, Target
from osint_agent.settings import Settings
from osint_agent.tools._common import DOMAIN_PATTERN, derive_infra_query, run_command, unique_strings, write_raw_output


def run(target: Target, settings: Settings) -> list[Observable]:
    if target.type not in {"domain", "subdomain", "organization", "company"}:
        return []

    query, _ = derive_infra_query(target.type, target.value)
    command = [settings.amass_binary, "enum", "-passive", "-norecursive", "-noalts", "-d", query]
    result = run_command(command, timeout=settings.amass_timeout)
    if not result.found:
        return [
            Observable(
                type="collector_status",
                value=f"amass binary not found: {settings.amass_binary}",
                source="amass",
                confidence=0.98,
                tags=["collector-status", "missing-binary"],
            )
        ]

    if result.returncode == 124:
        return [
            Observable(
                type="collector_status",
                value=f"amass timed out after {settings.amass_timeout}s while querying '{query}'",
                source="amass",
                confidence=0.95,
                tags=["collector-status", "timeout"],
            )
        ]

    if result.stdout:
        write_raw_output(settings.data_dir, "amass", target.value, "txt", result.stdout)
    if result.stderr:
        write_raw_output(settings.data_dir, "amass", f"{target.value}_stderr", "log", result.stderr)

    if result.returncode != 0:
        detail = result.stderr.strip() or f"return code {result.returncode}"
        return [
            Observable(
                type="collector_status",
                value=f"amass exited with {detail} while querying '{query}'",
                source="amass",
                confidence=0.9,
                tags=["collector-status", "error"],
            )
        ]

    matches = unique_strings(DOMAIN_PATTERN.findall(result.stdout))
    return [
        Observable(
            type="domain",
            value=match,
            source="amass",
            confidence=0.82,
            tags=["infrastructure", "subdomain-enum", "passive"],
        )
        for match in matches
    ]
