---
name: email-osint-methodology
description: Structure OSINT for email targets with validation, breach enrichment, account-reuse pivots, candidate username derivation, and evidence grading. Use when investigating an email address, checking public reuse, reviewing breach references, or producing a readable email-focused report with confirmed evidence, derived leads, and manual next steps.
---

# Email OSINT Methodology

Use this skill to investigate email targets without mixing weak pivots with confirmed results.

## Workflow

1. Validate the input first.
   - Confirm the value is a plausible email address before launching email-specific pivots.
   - Split the target into `local-part` and `domain` only after validation.
2. Run direct email checks before derivative pivots.
   - Start with breach enrichment and exact-email public references.
   - Only derive usernames after the direct checks are complete.
3. Derive leads carefully.
   - Treat local-part variants as candidate usernames, not confirmed accounts.
   - Keep exact-email hits separate from local-part reuse hypotheses.
4. Group the report by meaning.
   - Use `Confirmed Evidence`, `Collector Notes`, `Leads Requiring Validation`, and `Suggested Pivots`.
   - Explain what each collector did or failed to do.
5. End with analyst actions.
   - State what should be manually verified next, especially social reuse and breach context.

## Reporting Rules

- Report exact-email findings before candidate usernames.
- Treat `breach_count = 0` as a result, not as proof of safety.
- Remove pivots that imply a platform match when they are only generic searches.
- Prefer concise explanations such as “No direct social or account-usage hit confirmed in this run.”

## Quality Bar

- Do not claim a GitHub, Reddit, or LinkedIn association from a search URL alone.
- Do not merge direct email hits with local-part guesses.
- Do not inflate the findings count with workflow boilerplate.

## References

- For the email workflow checklist and evidence rules, read [references/email-workflow.md](references/email-workflow.md).
