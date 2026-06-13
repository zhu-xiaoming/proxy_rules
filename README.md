# proxy_rules

This repository stores collected proxy-rule knowledge.

- `collections/` keeps sanitized capture-derived inputs by platform/application.
- `rules/` keeps generated or organized rules for target proxy clients.
- `config/exclude-domains.list` keeps global host/domain suffixes that should be removed from generated rules.
- `.temp/` is local capture/scratch data and is ignored by git.

## Scripts

The scripts read only proxy-rule-relevant metadata and keep raw captures separate from generated rule files.

### 1. Extract a capture into `collections/`

Use `scripts/extract_collection.py` to traverse a capture directory and write a sanitized collection list.

```sh
python3 scripts/extract_collection.py \
  .temp/2026-06-02-041239 \
  --name "Futu / 富途" \
  --output collections/futu/2026-06-02-041239.md
```

What it writes:

- observed `host` values for Quantumult X / Clash domain rules
- sanitized `path_template` values for source context
- `redaction_kind` showing whether query/path data was removed
- `source_ids` pointing back to numeric capture request directories when safe, or sequential aliases for non-numeric request directory names

Safety behavior:

- reads each request directory's `basic` URL only
- does **not** read or copy request headers, request bodies, response bodies, cookies, authorization data, account data, device identifiers, session identifiers, or full query strings
- omits URL query strings and redacts dynamic-looking path segments
- writes a repo-relative source label when the capture is inside the repository; captures outside the repository are recorded by directory name only unless `--source-label` is provided
- defaults to `--source-id-mode safe`, which avoids copying non-numeric request directory names into collections

Optional host filtering:

```sh
python3 scripts/extract_collection.py \
  .temp/2026-06-02-041239 \
  --name "Futu / 富途" \
  --include-host-regex 'futu|myqcloud|app-analytics-services' \
  --output collections/futu/2026-06-02-041239.md
```

### 2. Generate Quantumult X and Clash rules from collections

Use `scripts/generate_rules.py` to read collection files, apply `config/exclude-domains.list`, and update `rules/QuantumultX/<slug>.list` plus `rules/Clash/<slug>.yaml`.
The `--slug` value is used as the rule filename and must contain only letters, numbers, `.`, `_`, or `-`.

Generate every app/category under `collections/`:

```sh
python3 scripts/generate_rules.py collections
```

Generate one app/category directory by combining all supported collection files in that directory:

```sh
python3 scripts/generate_rules.py collections/futu
```

Generate directly from a curated domain suffix list such as `collections/futu/collections.list`:

```sh
python3 scripts/generate_rules.py \
  collections/futu/collections.list \
  --slug futu \
  --name Futu \
  --policy Futu
```

Supported collection inputs:

- extractor markdown files (`*.md`) with a `## Canonical observed targets` table; hosts are treated as exact observed hosts
- curated domain suffix lists (`*.list`, including `collections.list`); plain rows are emitted as `HOST-SUFFIX` / `DOMAIN-SUFFIX`, and comment lines such as `# UPDATED: 2026-06-13 09:50:32` can provide a stable header timestamp
- plain text host lists (`*.txt`); plain rows are treated as exact hosts by default
- existing Quantumult X / Clash rows such as `HOST,api.example.com,Policy`, `DOMAIN,api.example.com`, `HOST-SUFFIX,example.com,Policy`, and `DOMAIN-SUFFIX,example.com`

Use `--plain-list-kind exact` or `--plain-list-kind suffix` when a plain list needs different handling from the default.

```sh
python3 scripts/generate_rules.py \
  collections/futu/2026-06-02-041239.md \
  --slug futu \
  --name Futu \
  --policy Futu \
  --suffix-domain futuhn.com \
  --suffix-domain futunn.com \
  --suffix-domain futustatic.com
```

Output formats:

- Quantumult X: blackmatrix7-style `.list` rules, for example `HOST-SUFFIX,futunn.com,Futu`
- Clash: classical rule-provider YAML payload, for example `- DOMAIN-SUFFIX,futunn.com`

By default, observed hosts are emitted as exact `HOST` / `DOMAIN` rules. Pass `--suffix-domain` for domains that should be collapsed into suffix rules. This explicit flag intentionally avoids automatic public-suffix inference, so broad suffixes are only generated when you choose them.
If a requested suffix would also cover an observed host removed by an exclude file, generation fails fast instead of reintroducing the excluded host through a broad suffix rule.

The generated headers include the source collection, exclude file(s), and active suffix-domain choices so future regenerations can repeat the same tradeoff. If `--updated` is omitted, the script parses a timestamp from a dated collection file such as `2026-06-02-041239.md`; undated files fall back to their file modification time. Pass `--updated 'YYYY-MM-DD HH:MM:SS'` when you need a fixed reproducible header.

Markdown collections are parsed from the `## Canonical observed targets` table. Non-markdown collection files are parsed line-by-line.

### Exclude list

`config/exclude-domains.list` is the global line-based exclude list:

```text
# comments are ignored
app-analytics-services.com
myqcloud.com
```

Each entry excludes the exact host and all subdomains. Keep entries lowercase and sorted for deterministic output.
Inline comments are allowed for rationale:

```text
myqcloud.com # third-party CDN/license service observed in app captures
```

For app-specific policy, pass one or more `--exclude-file` arguments to `generate_rules.py`. When no `--exclude-file` is supplied, the script uses `config/exclude-domains.list`; when you supply the flag, repeat it for every list you want applied:

```sh
python3 scripts/generate_rules.py collections/futu/2026-06-02-041239.md \
  --slug futu \
  --exclude-file config/exclude-domains.list \
  --exclude-file config/futu-exclude-domains.list
```

Every supplied exclude file must exist; the generator fails fast instead of silently dropping an exclude policy.

Extracted path templates are sanitized heuristically for source context, but the `host` column is the canonical rule-generation input. Manually review new collection files before generating or committing rules, especially for unfamiliar apps with opaque alphabetic/base64url path tokens.

## Verification

There is no project build system yet. For changes, run the smallest useful checks:

```sh
python3 - <<'PY'
from pathlib import Path
for path in [Path('scripts/extract_collection.py'), Path('scripts/generate_rules.py')]:
    compile(path.read_text(encoding='utf-8'), str(path), 'exec')
PY
python3 -B scripts/generate_rules.py collections
git diff --check
```

Also review generated rule files for accidental secrets/session identifiers and duplicate or malformed entries.
