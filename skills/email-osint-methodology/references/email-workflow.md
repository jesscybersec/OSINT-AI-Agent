# Email Workflow

## Investigation order

1. Validate email syntax
2. Run direct breach enrichment
3. Run exact-email public reference searches
4. Derive candidate usernames from the local-part
5. Run account-reuse pivots on the candidates
6. Summarize confirmed evidence vs leads

## Evidence grading

- High confidence
  - breach artifact tied to the exact email
  - exact-email public reference from a collector
- Medium confidence
  - exact-email search hit requiring manual verification
- Low confidence
  - username candidate derived from the local-part only

## Reporting reminders

- Report exact-email findings first
- Put candidate usernames in a validation-only section
- Show collectors that timed out or returned zero output
