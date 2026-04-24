# OSINT Report

## Executive Summary

- Target: cyberjess
- Profile: max_coverage
- Generated at: 2026-04-24T03:19:42.638077+00:00
- Mode: passive
- Total findings: 5

## Findings

### Investigation profile selected

- Severity: info
- Source: profile
- Confidence: 0.95
- Description: Profile 'max_coverage' is active. Broad OSINT workflow using all relevant collector families and curated hub references.

### Initial observable set collected

- Severity: info
- Source: pipeline
- Confidence: 0.8
- Description: 13 observables were collected during the initial pipeline run for target type 'alias'.

### OSINT identity pivot workflow enabled

- Severity: info
- Source: pipeline
- Confidence: 0.86
- Description: Identity-oriented target types trigger public search pivots and, when installed, Kali-friendly tools such as socialscan, maigret, phoneinfoga, and h8mail.

### Max coverage profile expanded pivoting

- Severity: info
- Source: profile
- Confidence: 0.9
- Description: The workflow added curated OSINT hub references and broader pivot URLs to widen coverage beyond direct binary collectors.

### Controlled pipeline checkpoint required

- Severity: info
- Source: pipeline
- Confidence: 0.9
- Description: Collected results should be reviewed by an analyst before any final intelligence product is published or shared.

## Observables

| Type | Value | Source |
|---|---|---|
| search_url | https://github.com/search?q=cyberjess&type=users | github_search |
| search_url | https://www.reddit.com/search/?q=cyberjess | reddit_search |
| search_url | https://www.google.com/search?q=site%3Agithub.com+%22cyberjess%22 | google_github |
| search_url | https://www.google.com/search?q=site%3Ainstagram.com+OR+site%3Ax.com+OR+site%3Areddit.com+%22cyberjess%22 | google_social |
| search_url | https://whatsmyname.app/?q=cyberjess | whatsmyname |
| search_url | https://www.google.com/search?q=site%3Amastodon.social+OR+site%3Ainfosec.exchange+%22cyberjess%22 | mastodon_search |
| search_url | https://gitlab.com/search?search=cyberjess&group_id=&project_id=&repository_ref=&scope=users | gitlab_search |
| resource_hub | https://github.com/jivoi/awesome-osint | awesome_osint |
| resource_hub | https://osintframework.com/ | osint_framework |
| resource_hub | https://start.me/p/L1rEYQ/osint4all | startme_osint4all |
| search_url | https://www.google.com/search?q=%22cyberjess%22 | variant_search |
| search_url | https://webcache.allorigins.win/raw?url=https://www.google.com/search?q=%22cyberjess%22 | archive_search |
| search_url | https://www.google.com/search?tbm=isch&q=%22cyberjess%22 | images_search |

## Notes

This report is generated from a controlled OSINT pipeline and should be reviewed by an analyst before redistribution.
