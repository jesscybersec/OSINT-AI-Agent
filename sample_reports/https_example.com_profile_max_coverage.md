# OSINT Report

## Executive Summary

- Target: https://example.com/profile
- Profile: max_coverage
- Generated at: 2026-04-24T03:19:40.373778+00:00
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
- Description: 7 observables were collected during the initial pipeline run for target type 'profile_url'.

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
| search_url | https://example.com/profile | profile_reference |
| search_url | https://web.archive.org/web/*/https%3A%2F%2Fexample.com%2Fprofile | wayback_profile |
| resource_hub | https://github.com/jivoi/awesome-osint | awesome_osint |
| resource_hub | https://osintframework.com/ | osint_framework |
| resource_hub | https://start.me/p/L1rEYQ/osint4all | startme_osint4all |
| search_url | https://www.google.com/search?q=%22https://example.com/profile%22 | google_document_search |
| search_url | https://web.archive.org/web/*/https://example.com/profile | wayback_search |

## Notes

This report is generated from a controlled OSINT pipeline and should be reviewed by an analyst before redistribution.
