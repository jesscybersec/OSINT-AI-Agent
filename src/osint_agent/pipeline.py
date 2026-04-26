from __future__ import annotations

from collections import OrderedDict

from osint_agent.methodology import select_active_instructions, select_active_skills
from osint_agent.models import CollectorRun, Finding, Observable, ReportData, Target
from osint_agent.profiles import InvestigationProfile, get_profile, profile_reference_observables
from osint_agent.settings import Settings
from osint_agent.tools import amass, bbot, company_registry, identity, social, spiderfoot, theharvester
from osint_agent.tools._common import derive_infra_query


class Pipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.collector_timeouts = {
            "amass": self.settings.amass_timeout,
            "bbot": self.settings.bbot_timeout,
            "theHarvester": self.settings.theharvester_timeout,
            "spiderfoot": self.settings.spiderfoot_timeout,
            "social": self.settings.social_timeout,
            "identity": self.settings.identity_timeout,
        }

    def _progress(self, message: str) -> None:
        if self.settings.show_progress:
            print(message, flush=True)

    def _resolve_collector_query(self, label: str, target: Target) -> str:
        if label in {"amass", "bbot", "theHarvester", "spiderfoot"}:
            return derive_infra_query(target.type, target.value)[0]
        return target.value

    def _run_collector(self, label: str, runner, target: Target) -> tuple[list[Observable], CollectorRun]:
        timeout = self.collector_timeouts.get(label)
        timeout_note = f" (timeout: {timeout}s)" if timeout else ""
        self._progress(f"[+] Running {label} for {target.type}: {target.value}{timeout_note}")
        query = self._resolve_collector_query(label, target)
        observables = runner(target, self.settings)
        self._progress(f"[+] {label} completed with {len(observables)} observable(s)")
        status = "completed"
        note = None
        collector_statuses = [observable.value for observable in observables if observable.type == "collector_status"]
        if any("timed out" in value for value in collector_statuses):
            status = "timeout"
            note = next(value for value in collector_statuses if "timed out" in value)
        elif collector_statuses:
            status = "error"
            note = "; ".join(collector_statuses[:2])
        elif not observables:
            note = "No observable output returned for the current query."

        return observables, CollectorRun(
            collector=label,
            query=query,
            status=status,
            observable_count=len([observable for observable in observables if observable.type != "collector_status"]),
            timeout_seconds=timeout,
            note=note,
        )

    def run(self, target: Target, profile_id: str = "default") -> ReportData:
        profile = get_profile(profile_id)
        observables: list[Observable] = []
        collector_runs: list[CollectorRun] = []
        active_instructions = select_active_instructions(target, profile.profile_id)
        active_skills = select_active_skills(target, profile.profile_id)
        self._progress(f"[+] Starting pipeline for target '{target.value}' ({target.type}) with profile '{profile.profile_id}'")
        if active_instructions:
            self._progress(f"[+] Active instructions: {', '.join(active_instructions)}")
        if active_skills:
            self._progress(f"[+] Active skills: {', '.join(active_skills)}")

        enabled = set(profile.force_enable)

        infrastructure_targets = {"domain", "subdomain", "hostname", "ip", "cidr", "asn", "organization", "company", "url"}
        domain_like_targets = {"domain", "subdomain", "hostname", "organization", "company"}
        social_targets = {"username", "alias", "social_handle", "profile_url", "person_name", "organization", "company", "email", "location"}
        identity_targets = {"person_name", "email", "phone", "alias", "location", "document"}
        company_targets = {"company", "organization", "person_name", "location"}

        normalized_infra_query, normalization_note = derive_infra_query(target.type, target.value)
        if normalization_note is not None:
            self._progress(f"[+] Infrastructure query normalized to '{normalized_infra_query}'")

        if (self.settings.enable_amass or "amass" in enabled) and target.type in domain_like_targets:
            collector_observables, collector_run = self._run_collector("amass", amass.run, target)
            observables.extend(collector_observables)
            collector_runs.append(collector_run)
        if (self.settings.enable_bbot or "bbot" in enabled) and target.type in infrastructure_targets:
            collector_observables, collector_run = self._run_collector("bbot", bbot.run, target)
            observables.extend(collector_observables)
            collector_runs.append(collector_run)
        if (self.settings.enable_theharvester or "theharvester" in enabled) and target.type in {"domain", "subdomain", "hostname", "organization", "company", "url"}:
            collector_observables, collector_run = self._run_collector("theHarvester", theharvester.run, target)
            observables.extend(collector_observables)
            collector_runs.append(collector_run)
        if (self.settings.enable_spiderfoot or "spiderfoot" in enabled) and target.type in infrastructure_targets | {"email", "username", "alias", "social_handle", "profile_url", "person_name", "phone", "location", "document"}:
            collector_observables, collector_run = self._run_collector("spiderfoot", spiderfoot.run, target)
            observables.extend(collector_observables)
            collector_runs.append(collector_run)
        if (self.settings.enable_social or "social" in enabled) and target.type in social_targets:
            collector_observables, collector_run = self._run_collector("social", social.run, target)
            observables.extend(collector_observables)
            collector_runs.append(collector_run)
        if (self.settings.enable_identity or "identity" in enabled) and target.type in identity_targets:
            collector_observables, collector_run = self._run_collector("identity", identity.run, target)
            observables.extend(collector_observables)
            collector_runs.append(collector_run)
        if (self.settings.enable_company_registry or "company_registry" in enabled) and target.type in company_targets:
            collector_observables, collector_run = self._run_collector("company_registry", company_registry.run, target)
            observables.extend(collector_observables)
            collector_runs.append(collector_run)
        profile_observables = profile_reference_observables(target, profile)
        observables.extend(profile_observables)
        self._progress(f"[+] Added {len(profile_observables)} profile pivot/reference observable(s)")

        deduped = self._dedupe_observables(observables)
        self._progress(f"[+] Pipeline finished with {len(deduped)} unique observable(s)")
        findings = self._build_findings(target, deduped, profile)
        return ReportData(
            target=target.value,
            target_type=target.type,
            mode="passive" if target.passive_only else self.settings.default_mode,
            profile=profile.profile_id,
            active_instructions=active_instructions,
            active_skills=active_skills,
            findings=findings,
            observables=deduped,
            collector_runs=collector_runs,
        )

    def _dedupe_observables(self, observables: list[Observable]) -> list[Observable]:
        keyed: OrderedDict[tuple[str, str, str], Observable] = OrderedDict()
        for observable in observables:
            key = (observable.type, observable.value, observable.source)
            keyed[key] = observable
        return list(keyed.values())

    def _build_findings(self, target: Target, observables: list[Observable], profile: InvestigationProfile) -> list[Finding]:
        findings: list[Finding] = []

        if observables:
            findings.append(
                Finding(
                    title="Initial observable set collected",
                    description=f"{len(observables)} observables were collected during the initial pipeline run for target type '{target.type}'.",
                    severity="info",
                    source="pipeline",
                    confidence=0.8,
                )
            )
        else:
            findings.append(
                Finding(
                    title="No collector output produced",
                    description="No observables were produced by the enabled collectors for this target. On Kali, verify that the relevant binaries are installed and reachable in PATH or configured via environment variables.",
                    severity="low",
                    source="pipeline",
                    confidence=0.92,
                )
            )

        if target.type == "email" and "@" not in target.value:
            findings.append(
                Finding(
                    title="Target value does not look like a valid email",
                    description="The selected target type is 'email', but the provided value does not contain an '@' symbol. Email-specific pivots may be weak or misleading until the input is corrected.",
                    severity="low",
                    source="pipeline",
                    confidence=0.95,
                )
            )

        if target.type in {"username", "alias", "social_handle", "profile_url", "email", "phone", "person_name", "location", "document"}:
            findings.append(
                Finding(
                    title="OSINT identity pivot workflow enabled",
                    description="Identity-oriented target types trigger public search pivots and, when installed, Kali-friendly tools such as socialscan, maigret, phoneinfoga, and h8mail.",
                    severity="info",
                    source="pipeline",
                    confidence=0.86,
                )
            )

        if target.type in {"domain", "subdomain", "hostname", "url", "ip", "cidr", "asn"}:
            findings.append(
                Finding(
                    title="Infrastructure pivot workflow enabled",
                    description="Infrastructure-oriented target types trigger passive attack-surface pivots and, when installed, collectors such as amass, bbot, theHarvester, and SpiderFoot.",
                    severity="info",
                    source="pipeline",
                    confidence=0.86,
                )
            )

        if profile.profile_id == "max_coverage":
            findings.append(
                Finding(
                    title="Max coverage profile expanded pivoting",
                    description="The workflow added curated OSINT hub references and broader pivot URLs to widen coverage beyond direct binary collectors.",
                    severity="info",
                    source="profile",
                    confidence=0.9,
                )
            )

        if profile.profile_id == "canada_localization":
            findings.append(
                Finding(
                    title="Canada localization profile expanded regional research",
                    description="The workflow added Canada-focused geolocation, registry, and public-search pivots informed by the configured Canada OSINT hub strategy.",
                    severity="info",
                    source="profile",
                    confidence=0.9,
                )
            )

        findings.append(
            Finding(
                title="Controlled pipeline checkpoint required",
                description="Collected results should be reviewed by an analyst before any final intelligence product is published or shared.",
                severity="info",
                source="pipeline",
                confidence=0.9,
            )
        )
        return findings
