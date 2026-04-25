from __future__ import annotations

from osint_agent.models import Target


GLOBAL_INSTRUCTIONS = [
    "instructions/agent-operating-model.md",
    "instructions/reporting-standard.md",
]


def select_active_instructions(target: Target, profile_id: str) -> list[str]:
    _ = target
    _ = profile_id
    return list(GLOBAL_INSTRUCTIONS)


def select_active_skills(target: Target, profile_id: str) -> list[str]:
    skills: list[str] = []

    if target.type in {"domain", "subdomain", "hostname", "url", "ip", "cidr", "asn", "organization", "company"}:
        skills.append("skills/passive-domain-infra-osint/SKILL.md")

    if target.type in {"email"}:
        skills.append("skills/evidence-first-email-osint/SKILL.md")

    if profile_id == "canada_localization" or target.type in {"location"}:
        skills.append("skills/canada-records-location-osint/SKILL.md")

    deduped: list[str] = []
    seen: set[str] = set()
    for skill in skills:
        if skill in seen:
            continue
        seen.add(skill)
        deduped.append(skill)
    return deduped
