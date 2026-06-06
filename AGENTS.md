# Repository Instructions

## Project purpose

This repository stores collected proxy-rule knowledge.

- `collections/` contains the raw materials: domains, URLs, request clues, or other proxy targets collected by platform/application.
- `rules/` contains the organized output: proxy rules rewritten or normalized for different proxy clients/software.
- `.temp/` is local capture/scratch data and is ignored by git; treat it as diagnostic input only when explicitly relevant.

## Working conventions

- Keep raw collection data and generated/organized rule data separate.
- Prefer deterministic ordering in rule files so diffs stay reviewable.
- Preserve enough source context in `collections/` entries to explain why a domain/URL needs proxying when that context is available.
- Do not add secrets, credentials, private proxy endpoints, cookies, bearer tokens, or personal account identifiers.
- When moving data from `collections/` to `rules/`, keep the rule syntax appropriate for the target proxy software and avoid mixing formats in one file.
- Avoid deleting existing domains/rules unless they are clearly duplicates, invalid, or intentionally superseded; note the reason when it is not obvious.

## Verification

There is no project build system yet. For changes, verify with the smallest useful checks:

- Review the changed files manually for correct directory placement and target software syntax.
- Check for accidental secrets or request/session identifiers before committing.
- For rule files, look for duplicate or malformed entries when practical.
- Use `git diff --check` before reporting completion.

