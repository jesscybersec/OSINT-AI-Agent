from __future__ import annotations

from collections import OrderedDict

from osint_agent.models import Finding, Observable, ReportData, Target
from osint_agent.profiles import InvestigationProfile, get_profile, profile_reference_observables
from osint_agent.settings import Settings
from osint_agent.tools import amass, bbot, company_registry, identity, social, spiderfoot, theharvester


class Pipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _progress(self, message: str) -> None:
        if self.settings.show_progress:
            print(message, flush=True)

    def _run_collector(self, label: str, runner, target: Target) -> list[Observable]:
        self._progress(f"[+] Running {label} for {target.type}: {target.value}")
        observables = runner(target, self.settings)
        self._progress(f"[+] {label} completed with {len(observables)} observable(s)")
        return observables

    def run(self, target: Target, profile_id: str = "default") -> ReportData:
        profile = get_profile(profile_id)
        observables: list[Observable] = []
        self._progress(f"[+] Starting pipeline for target '{target.value}' ({target.type}) with profile '{profile.profile_id}'")

        enabled = set(profile.force_enable)

        infrastructure_targets = {"domain", "subdomain", "hostname", "ip", "cidr", "asn", "organization", "company", "url"}
        domain_like_targets = {"domain", "subdomain", "hostname", "organization", "company"}
        social_targets = {"username", "alias", "social_handle", "profile_url", "person_name", "organization", "company", "email", "location"}
        identity_targets = {"person_name", "email", "phone", "alias", "location", "document"}
        company_targets = {"company", "organization", "person_name", "location"}

        if (self.settings.enable_amass or "amass" in enabled) and target.type in domain_like_targets:
            observables.extend(self._run_collector("amass", amass.run, target))
        if (self.settings.enable_bbot or "bbot" in enabled) and target.type in infrastructure_targets:
            observables.extend(self._run_collector("bbot", bbot.run, target))
        if (self.settings.enable_theharvester or "theharvester" in enabled) and target.type in {"domain", "subdomain", "hostname", "organization", "company", "url"}:
            observables.extend(self._run_collector("theHarvester", theharvester.run, target))
        if (self.settings.enable_spiderfoot or "spiderfoot" in enabled) and target.type in infrastructure_targets | {"email", "username", "alias", "social_handle", "profile_url", "person_name", "phone", "location", "document"}:
            observables.extend(self._run_collector("spiderfoot", spiderfoot.run, target))
        if (self.settings.enable_social or "social" in enabled) and target.type in social_targets:
            observables.extend(self._run_collector("social", social.run, target))
        if (self.settings.enable_identity or "identity" in enabled) and target.type in identity_targets:
            observables.extend(self._run_collector("identity", identity.run, target))
        if (self.settings.enable_company_registry or "company_registry" in enabled) and target.type in company_targets:
            observables.extend(self._run_collector("company_registry", company_registry.run, target))
        profile_observables = profile_reference_observables(target, profile)
        observables.extend(profile_observables)
        self._progress(f"[+] Added {len(profile_observables)} profile pivot/reference observable(s)")

        deduped = self._dedupe_observables(observables)
        self._progress(f"[+] Pipeline finished with {len(deduped)} unique observable(s)")
        findings = self._build_findings(target, deduped, profile)
        return ReportData(
            target=target.value,
            mode="passive" if target.passive_only else self.settings.default_mode,
            profile=profile.profile_id,
            findings=findings,
            observables=deduped,
        )

    def _dedupe_observables(self, observables: list[Observable]) -> list[Observable]:
        keyed: OrderedDict[tuple[str, str, str], Observable] = OrderedDict()
        for observable in observables:
            key = (observable.type, observable.value, observable.source)
            keyed[key] = observable
        return list(keyed.values())

    def _build_findings(self, target: Target, observables: list[Observable], profile: InvestigationProfile) -> list[Finding]:
        findings: list[Finding] = []

        findings.append(
            Finding(
                title="Investigation profile selected",
                description=f"Profile '{profile.profile_id}' is active. {profile.description}",
                severity="info",
                source="profile",
                confidence=0.95,
            )
        )

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
