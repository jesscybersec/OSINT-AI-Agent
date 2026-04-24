---
name: domain-osint-methodology
description: Structure passive domain and infrastructure OSINT for domains, subdomains, hostnames, URLs, IPs, CIDRs, and ASNs. Use when mapping attack surface, certificate exposure, passive web traces, repository mentions, or archived infrastructure history, and when results need to be classified into confirmed evidence, validation leads, and next pivots.
---

# Domain OSINT Methodology

Use this skill to keep infrastructure OSINT disciplined and readable.

## Workflow

1. Normalize the target before collecting.
   - Reduce obvious web prefixes such as `www.` when the research question is about the parent domain.
   - Preserve the original input and record the normalized query used by collectors.
2. Start with passive infrastructure collection.
   - Run passive DNS, subdomain, certificate-transparency, passive web-scan, and repository-reference collectors first.
   - Prefer broad, low-noise sources before generic search-engine pivots.
3. Classify the output immediately.
   - Treat discovered domains, IPs, URLs, certificates, and repository references as candidate evidence.
   - Treat tool status, timeouts, and empty returns as execution notes, not findings.
4. Group the report by investigation question, not by tool.
   - Use sections such as `Infrastructure Exposure Snapshot`, `DNS and Certificate Pivots`, `Passive Web Exposure`, `Code and Repository References`, and `Archive and Historical Pivots`.
5. Separate confidence levels.
   - `Confirmed evidence`: directly returned by a collector or source.
   - `Lead requiring validation`: derived from a pivot or weak correlation.
   - `Recommended next step`: follow-up action that should be reviewed manually.

## Reporting Rules

- State the normalized infrastructure query when it differs from the original target.
- Show collector execution status in one compact summary table.
- Prefer counts and concrete assets over vague workflow statements.
- Call out missing coverage honestly when collectors return zero results or time out.
- Keep “reference hubs” separate from target-specific pivots.

## Quality Bar

- Do not imply compromise, exposure, or ownership from a generic search pivot alone.
- Do not treat a timeout as a negative result.
- Do not bury the best pivots under generic web-search links.
- Prefer certificate-transparency, passive scan, archive, and code-reference pivots over generic Google searches.

## References

- For the domain workflow checklist and section mapping, read [references/domain-workflow.md](references/domain-workflow.md).
