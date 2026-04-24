# Agent Operating Model

Use this file as the high-level operating contract for the OSINT AI Agent project.

## Core principles

- Keep the human in control at decision points that change scope, confidence, or publication risk.
- Prefer passive collection unless the operator explicitly authorizes more intrusive actions.
- Record what was searched, with which normalized query, and what produced evidence.
- Separate confirmed evidence from derived leads and from generic reference pivots.
- Report weak coverage honestly when collectors return zero output or time out.

## Execution order

1. Validate target type and normalize the query if needed.
2. Select the methodology skill that matches the target and profile.
3. Run the relevant collectors.
4. Classify the output into evidence, leads, notes, and next pivots.
5. Produce a report that explains both results and coverage gaps.

## Guardrails

- Do not treat search URLs as evidence.
- Do not treat missing output as proof of absence.
- Do not publish a conclusion without an analyst checkpoint.
