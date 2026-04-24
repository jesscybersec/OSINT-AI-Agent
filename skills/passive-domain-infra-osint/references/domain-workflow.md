# Domain Workflow

## Investigation order

1. Normalize target
2. Passive DNS and subdomain collection
3. Certificate-transparency review
4. Passive web exposure review
5. Code and repository mention review
6. Archived-web review
7. Analyst summary and next steps

## Section mapping

- `Infrastructure Exposure Snapshot`
  - confirmed domains
  - confirmed IPs
  - confirmed URLs
- `DNS and Certificate Pivots`
  - crt.sh
  - passive DNS style pivots
- `Passive Web Exposure Pivots`
  - urlscan
  - similar passive scan sources
- `Code and Repository Pivots`
  - GitHub code or repo references
- `Archive and Historical Pivots`
  - Wayback Machine

## Evidence grading

- High confidence
  - collector-returned domain, IP, URL, certificate artifact
- Medium confidence
  - repository mention with target string but unclear ownership
- Low confidence
  - generic search hit without corroboration
