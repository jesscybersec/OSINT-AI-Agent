# OSINT Report

## Executive Summary

- Target: Toronto, Ontario
- Profile: canada_localization
- Generated at: 2026-04-24T03:19:38.322150+00:00
- Mode: passive
- Total findings: 5

## Findings

### Investigation profile selected

- Severity: info
- Source: profile
- Confidence: 0.95
- Description: Profile 'canada_localization' is active. Canada-focused workflow for people, company, and location-heavy OSINT.

### Initial observable set collected

- Severity: info
- Source: pipeline
- Confidence: 0.8
- Description: 21 observables were collected during the initial pipeline run for target type 'location'.

### OSINT identity pivot workflow enabled

- Severity: info
- Source: pipeline
- Confidence: 0.86
- Description: Identity-oriented target types trigger public search pivots and, when installed, Kali-friendly tools such as socialscan, maigret, phoneinfoga, and h8mail.

### Canada localization profile expanded regional research

- Severity: info
- Source: profile
- Confidence: 0.9
- Description: The workflow added Canada-focused geolocation, registry, and public-search pivots informed by the configured Canada OSINT hub strategy.

### Controlled pipeline checkpoint required

- Severity: info
- Source: pipeline
- Confidence: 0.9
- Description: Collected results should be reviewed by an analyst before any final intelligence product is published or shared.

## Observables

| Type | Value | Source |
|---|---|---|
| search_url | https://www.google.com/search?q=%22Toronto%2C+Ontario%22 | google_general |
| search_url | https://www.google.com/search?q=site%3Alinkedin.com+OR+site%3Ax.com+OR+site%3Areddit.com+%22Toronto%2C+Ontario%22 | google_social |
| search_url | https://github.com/search?q=Toronto%2C+Ontario&type=users | github_search |
| search_url | https://www.google.com/search?q=%22Toronto%2C+Ontario%22 | google_location_general |
| search_url | https://www.google.com/maps/search/?api=1&query=Toronto%2C+Ontario | google_maps_location |
| search_url | https://www.openstreetmap.org/search?query=Toronto%2C+Ontario | openstreetmap_location |
| registry_search_url | https://opencorporates.com/companies?q=Toronto%2C+Ontario | opencorporates |
| registry_search_url | https://searchapi.mrasservice.ca/Search?SearchText=Toronto%2C+Ontario | canada_business |
| registry_search_url | https://www.sec.gov/edgar/search/#/q=Toronto%2C+Ontario | sec_edgar |
| resource_hub | https://start.me/p/aLe0vp/osint-resources-in-canada | startme_canada |
| resource_hub | https://start.me/p/L1rEYQ/osint4all | startme_osint4all |
| resource_hub | https://github.com/jivoi/awesome-osint | awesome_osint |
| resource_hub | https://osintframework.com/ | osint_framework |
| search_url | https://www.google.com/maps/search/?api=1&query=Toronto,+Ontario+Canada | google_maps_canada |
| search_url | https://www.openstreetmap.org/search?query=Toronto,+Ontario%20Canada | openstreetmap_search |
| search_url | https://www.google.com/search?q=site%3Acanada411.ca+%22Toronto,+Ontario%22 | google_canada411 |
| search_url | https://www.google.com/search?q=site%3Agc.ca+%22Toronto,+Ontario%22 | google_gc_ca |
| search_url | https://www.google.com/search?q=site%3Acanlii.org+%22Toronto,+Ontario%22 | google_canlii |
| search_url | https://www.google.com/search?q=site%3Aopen.canada.ca+%22Toronto,+Ontario%22 | google_opencanada |
| search_url | https://www.google.com/search?q=site%3Asedarplus.ca+%22Toronto,+Ontario%22 | google_sedar |
| search_url | https://www.google.com/search?q=site%3Asearchapi.mrasservice.ca+%22Toronto,+Ontario%22 | google_canada_business |

## Notes

This report is generated from a controlled OSINT pipeline and should be reviewed by an analyst before redistribution.
