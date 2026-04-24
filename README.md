<h1 align="center">OSINT AI AGENT</h1>

<p align="center">
  <code>CYBERJESS // TERMINAL OPS // CONTROLLED OSINT WORKFLOW</code>
</p>

<p align="center">
  <code>KALI READY // SOCIAL + IDENTITY + INFRA + CANADA LOCALIZATION</code>
</p>

---

## Languages

- GB English: [README.md](./README.md)
- FR Francais: [README_fr.md](./README_fr.md)

---

## BOOT SEQUENCE

```diff
+ status: online
+ mode: controlled pipeline
+ analyst review: required
+ reporting: bilingual
+ target classes: social / identity / company / infrastructure
```

`OSINT AI Agent` is a standalone, Kali Linux-oriented investigation project built for controlled OSINT operations.

The goal is not to create a fully autonomous black box.  
The goal is to create a step-driven OSINT workflow that stays:

- auditable
- explainable
- modular
- automation-friendly
- analyst-controlled

This project is inspired in part by the OWASP SocialOSINTAgent approach:

- [OWASP SocialOSINTAgent](https://owasp.org/www-project-social-osint-agent/)

---

## AGENT DESCRIPTION

`OSINT AI Agent` is a bilingual, Kali-friendly OSINT project designed to orchestrate multiple open-source tools through a controlled investigation pipeline.

It helps collect, expand, correlate, and document findings related to:

- social media
- usernames and aliases
- person names
- phone numbers
- company and registry data
- domains and infrastructure exposure

The AI layer is used to structure the workflow, widen pivots, and help summarize results.  
It is not meant to replace analyst judgment.

---

## MISSION PROFILE

This agent is designed to support investigations involving:

- `username`
- `alias`
- `social_handle`
- `profile_url`
- `person_name`
- `email`
- `phone`
- `company`
- `organization`
- `domain`
- `subdomain`
- `hostname`
- `url`
- `ip`
- `cidr`
- `asn`
- `location`
- `document`

It is meant to correlate open-source signals across:

- social platforms
- aliases and identity fragments
- public phone-related OSINT
- business and registry sources
- technical exposure and attack surface
- regional and Canada-specific pivots

### Target-type routing

| Target type | Main collectors | Expected pivots |
|---|---|---|
| `username` / `alias` / `social_handle` | `socialscan`, `maigret`, public search | social profiles, username variants, platform hits |
| `profile_url` | public search, `spiderfoot` | profile references, archive pivots, related URLs |
| `person_name` / `email` / `phone` | `identity`, `social`, `h8mail`, `phoneinfoga` | public mentions, breach artifacts, people pivots |
| `company` / `organization` | `company_registry`, `social`, `amass`, `bbot` | registries, social presence, related domains |
| `domain` / `subdomain` / `hostname` | `amass`, `bbot`, `theHarvester`, `spiderfoot` | subdomains, emails, passive infra signals |
| `url` / `ip` / `cidr` / `asn` | `bbot`, `theHarvester`, `spiderfoot` | infrastructure pivots, code/search references, archive pivots |
| `location` | public search, Canada profile pivots | maps, geolocation search, local records |
| `document` | public search, `spiderfoot` | file pivots, archive references, related mentions |

---

## OPERATOR MODEL

```text
target input
   -> collector selection
   -> passive-first collection
   -> pivot expansion
   -> normalization
   -> analyst checkpoint
   -> markdown report
```

The agent currently favors a controlled chain rather than unrestricted autonomy.

Why this matters:

- easier to verify findings
- easier to explain methodology
- easier to publish responsibly
- easier to expand collector coverage over time

---

## ACTIVE LOADOUT

### Implemented collectors

- `socialscan`
- `maigret`
- `phoneinfoga`
- `h8mail`
- `amass`
- `bbot`
- `theHarvester`
- `spiderfoot`

### Supported research layers

- social reconnaissance
- username pivoting
- identity enrichment
- phone and email pivots
- company and registry pivots
- domain and external-surface recon
- curated hub references for wider OSINT strategy

### External curation sources considered by the agent

- [awesome-osint](https://github.com/jivoi/awesome-osint)
- [OSINT Framework](https://osintframework.com/)
- [OSINT Resources in Canada](https://start.me/p/aLe0vp/osint-resources-in-canada)
- [OSINT4ALL](https://start.me/p/L1rEYQ/osint4all)

Important:

- these hubs currently act as strategy layers and pivot references
- they do not yet auto-run every tool listed on those pages
- they influence profile behavior and investigation expansion

---

## INVESTIGATION PROFILES

```diff
+ default: balanced workflow
+ max_coverage: broad recon with expanded pivots
+ canada_localization: regional research and Canada-focused sources
```

### `default`

Standard controlled workflow for normal investigations.

### `max_coverage`

This profile:

- force-enables relevant collector families
- injects curated hub references
- adds broader pivot URLs for infrastructure, search, archive, and identity expansion

### `canada_localization`

This profile:

- prioritizes Canada-related research pivots
- expands registry and geolocation search paths
- adds public-search references useful for Canadian investigations

---

## QUICK LAUNCH

```bash
cd OSINT-AI-Agent

python run.py example.com
python run.py cyberjess --target-type username
python run.py "+14155552671" --target-type phone

python run.py example.com --target-type domain --profile max_coverage
python run.py "Jane Doe" --target-type person_name --profile canada_localization
```

Generated reports follow the profile-based naming pattern:

```text
reports/
|-- example.com_max_coverage.md
|-- Jane_Doe_canada_localization.md
`-- Jane_Doe_default.md
```

---

## KALI MODE

```diff
+ recommended distro: Kali Linux
+ passive-first workflow: enabled
+ fallback behavior when tools are missing: safe
```

Quick installer flow:

```bash
git clone https://github.com/jesscybersec/OSINT-AI-Agent.git
cd OSINT-AI-Agent
chmod +x ./scripts/install_kali_tools.sh
sh ./scripts/install_kali_tools.sh
```

Post-install verification:

```bash
amass enum -h
bbot --help
theHarvester -h
python run.py example.com --target-type domain --profile max_coverage
```

Recommended install baseline:

```bash
sudo apt update
sudo apt install -y pipx jq curl git python3-venv amass theharvester
pipx ensurepath

pipx install socialscan
pipx install maigret
pipx install h8mail
pipx install ghunt
pipx install bbot
```

SpiderFoot and PhoneInfoga remain supported as optional additions.

Setup references:

- [Kali Setup](./docs/en/KALI_SETUP.md)
- [Kali installer script](./scripts/install_kali_tools.sh)

---

## FILESYSTEM MAP

```text
OSINT-AI-Agent/
|-- README.md
|-- README_fr.md
|-- config/
|   |-- osint_sources_registry.yaml
|   `-- profiles/
|-- docs/
|   |-- en/
|   `-- fr/
|-- instructions/
|   |-- agent-operating-model.md
|   `-- reporting-standard.md
|-- skills/
|   |-- passive-domain-infra-osint/
|   |   |-- SKILL.md
|   |   |-- agents/
|   |   `-- references/
|   |-- evidence-first-email-osint/
|   |   |-- SKILL.md
|   |   |-- agents/
|   |   `-- references/
|   `-- canada-records-location-osint/
|       |-- SKILL.md
|       |-- agents/
|       `-- references/
|-- reports/
|-- sample_reports/
|-- scripts/
|-- src/
`-- templates/
```

Key references:

- [English Project Overview](./docs/en/PROJECT_OVERVIEW.md)
- [English Architecture](./docs/en/ARCHITECTURE.md)
- [English Max Coverage Strategy](./docs/en/MAX_COVERAGE_STRATEGY.md)
- [English Canada Localization](./docs/en/CANADA_LOCALIZATION.md)
- [Project Overview](./docs/en/PROJECT_OVERVIEW.md)
- [Architecture](./docs/en/ARCHITECTURE.md)
- [Max Coverage Strategy](./docs/en/MAX_COVERAGE_STRATEGY.md)
- [Canada Localization](./docs/en/CANADA_LOCALIZATION.md)
- [Agent Operating Model](./instructions/agent-operating-model.md)
- [Reporting Standard](./instructions/reporting-standard.md)
- [Passive Domain Infra OSINT Skill](./skills/passive-domain-infra-osint/SKILL.md)
- [Evidence-First Email OSINT Skill](./skills/evidence-first-email-osint/SKILL.md)
- [Canada Records Location OSINT Skill](./skills/canada-records-location-osint/SKILL.md)
- [Public sample reports](./sample_reports/README.md)

---

## RULES OF ENGAGEMENT

This project is intended for:

- authorized investigations
- public-information research
- ethical OSINT workflows
- legitimate targets only

```diff
- no unauthorized targeting
- no illegal collection
- no blind trust in automated correlation
+ analyst validation remains mandatory
```
