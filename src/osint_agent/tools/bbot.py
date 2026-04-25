from __future__ import annotations

import json
from pathlib import Path

from osint_agent.models import Observable, Target
from osint_agent.settings import Settings
from osint_agent.tools._common import EMAIL_PATTERN, IPV4_PATTERN, URL_PATTERN, derive_infra_query, read_text_if_exists, run_command, summarize_command_failure, write_raw_output


def _event_to_observable(event: dict) -> Observable | None:
    event_type = str(event.get("type", "")).upper()
    data = str(event.get("data", "")).strip()
    tags = [str(tag) for tag in event.get("tags", []) if isinstance(tag, str)]

    if not data:
        return None

    if event_type == "DNS_NAME":
        return Observable(type="domain", value=data, source="bbot", confidence=0.84, tags=["bbot", *tags])
    if event_type == "EMAIL_ADDRESS":
        return Observable(type="email", value=data, source="bbot", confidence=0.84, tags=["bbot", *tags])
    if event_type == "URL":
        return Observable(type="url", value=data, source="bbot", confidence=0.82, tags=["bbot", *tags])
    if event_type == "IP_ADDRESS":
        return Observable(type="ip", value=data, source="bbot", confidence=0.82, tags=["bbot", *tags])
    if event_type == "OPEN_TCP_PORT":
        return Observable(type="open_port", value=data, source="bbot", confidence=0.8, tags=["bbot", *tags])
    return None


def _parse_bbot_json_lines(text: str) -> list[Observable]:
    observables: list[Observable] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        observable = _event_to_observable(event)
        if observable is not None:
            observables.append(observable)
    return observables


def _load_bbot_output_artifacts(output_dir: Path, scan_name: str) -> str:
    candidate_paths = [
        output_dir / scan_name / "output.json",
        output_dir / scan_name / "output.ndjson",
        output_dir / f"{scan_name}.json",
        output_dir / f"{scan_name}.ndjson",
    ]

    combined: list[str] = []
    for path in candidate_paths:
        text = read_text_if_exists(path)
        if text:
            combined.append(text)

    if combined:
        return "\n".join(combined)

    for path in sorted(output_dir.rglob("*.json")) + sorted(output_dir.rglob("*.ndjson")):
        text = read_text_if_exists(path)
        if text:
            combined.append(text)
    return "\n".join(combined)


def run(target: Target, settings: Settings) -> list[Observable]:
    if target.type not in {"domain", "subdomain", "ip", "organization", "company"}:
        return []

    query, _ = derive_infra_query(target.type, target.value)
    output_dir = settings.data_dir / "raw" / "bbot"
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [
        settings.bbot_binary,
        "-t",
        query,
        "-p",
        "subdomain-enum",
        "email-enum",
        "-rf",
        "passive",
        "-om",
        "json",
        "-o",
        str(output_dir),
        "--name",
        query.replace("/", "_"),
    ]
    result = run_command(command, timeout=settings.bbot_timeout)
    if not result.found:
        return [
            Observable(
                type="collector_status",
                value=f"bbot binary not found: {settings.bbot_binary}",
                source="bbot",
                confidence=0.98,
                tags=["collector-status", "missing-binary"],
            )
        ]

    if result.returncode == 124:
        return [
            Observable(
                type="collector_status",
                value=f"bbot timed out after {settings.bbot_timeout}s while querying '{query}'",
                source="bbot",
                confidence=0.95,
                tags=["collector-status", "timeout"],
            )
        ]

    if result.stdout:
        write_raw_output(settings.data_dir, "bbot", target.value, "ndjson", result.stdout)
    if result.stderr:
        write_raw_output(settings.data_dir, "bbot", f"{target.value}_stderr", "log", result.stderr)

    if result.returncode != 0:
        detail = summarize_command_failure(result.stderr, result.stdout, result.returncode)
        return [
            Observable(
                type="collector_status",
                value=f"bbot exited with {detail} while querying '{query}'",
                source="bbot",
                confidence=0.9,
                tags=["collector-status", "error"],
            )
        ]

    observables = _parse_bbot_json_lines(result.stdout)
    if not observables:
        artifact_text = _load_bbot_output_artifacts(output_dir, query.replace("/", "_"))
        if artifact_text:
            observables = _parse_bbot_json_lines(artifact_text)
            if observables:
                write_raw_output(settings.data_dir, "bbot", f"{target.value}_artifact_output", "ndjson", artifact_text)

    if observables:
        return observables

    fallback: list[Observable] = []
    fallback_text = result.stdout
    if not fallback_text:
        fallback_text = _load_bbot_output_artifacts(output_dir, query.replace("/", "_"))
    for match in EMAIL_PATTERN.findall(fallback_text):
        fallback.append(Observable(type="email", value=match, source="bbot", confidence=0.72, tags=["bbot", "regex"]))
    for match in IPV4_PATTERN.findall(fallback_text):
        fallback.append(Observable(type="ip", value=match, source="bbot", confidence=0.72, tags=["bbot", "regex"]))
    for match in URL_PATTERN.findall(fallback_text):
        fallback.append(Observable(type="url", value=match, source="bbot", confidence=0.72, tags=["bbot", "regex"]))
    return fallback
