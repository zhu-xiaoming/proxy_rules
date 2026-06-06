#!/usr/bin/env python3
"""Extract sanitized proxy-rule collection data from captured HTTP request records.

The expected capture layout is a directory containing one subdirectory per request,
where each request directory has a ``basic`` file whose content includes the URL.
Only URL host/path/source id metadata is read and written; request/response headers,
bodies, cookies, authorization data, and query strings are intentionally ignored.
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote, urlsplit

URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$", re.IGNORECASE)
NUMERIC_SOURCE_ID_RE = re.compile(r"^\d{1,12}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
LONG_HEX_RE = re.compile(r"^[0-9a-f]{12,}$", re.IGNORECASE)
LONG_NUM_RE = re.compile(r"^\d{6,}$")
NUMERIC_TOKEN_RE = re.compile(r"^\d[\d_-]{5,}$")
SENSITIVE_WORD_RE = re.compile(r"(token|secret|session|authorization|auth|cookie|password|passwd|device|account|uid|userid|user_id)", re.IGNORECASE)
STATIC_EXT_RE = re.compile(r"\.(?:css|js|mjs|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|json|license)(?:$|[!._-])", re.IGNORECASE)
OPAQUE_PATH_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,}$")


@dataclass(frozen=True)
class Target:
    host: str
    path_template: str
    redaction_kind: str
    note: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract sanitized host/path targets from a capture directory into a collections markdown list."
    )
    parser.add_argument("capture_dir", type=Path, help="Capture root containing per-request subdirectories with basic files.")
    parser.add_argument("--output", "-o", type=Path, required=True, help="Output markdown file under collections/.")
    parser.add_argument("--name", required=True, help="Collection display name, for example 'Futu / 富途'.")
    parser.add_argument(
        "--source-label",
        help=(
            "Source label written into the collection. Defaults to a repo-relative "
            "path when the capture is under the current repository; otherwise only "
            "the capture directory name is written."
        ),
    )
    parser.add_argument(
        "--include-host-regex",
        action="append",
        default=[],
        help="Optional case-insensitive host regex filter. Can be passed multiple times.",
    )
    parser.add_argument(
        "--source-id-mode",
        choices=("safe", "directory-name", "sequential"),
        default="safe",
        help=(
            "How to write source_ids. 'safe' keeps numeric request directory names "
            "and uses sequential aliases for non-numeric names; 'directory-name' "
            "keeps raw directory names; 'sequential' always writes req-000001 aliases."
        ),
    )
    return parser.parse_args()


def iter_request_dirs(capture_dir: Path) -> Iterable[Path]:
    for child in sorted(capture_dir.iterdir(), key=lambda p: p.name):
        if child.is_dir() and (child / "basic").is_file():
            yield child


def source_id_for(request_dir: Path, ordinal: int, mode: str) -> str:
    if mode == "directory-name":
        return request_dir.name
    if mode == "safe" and NUMERIC_SOURCE_ID_RE.match(request_dir.name):
        return request_dir.name
    return f"req-{ordinal:06d}"


def extract_url(text: str) -> str | None:
    text = text.strip()
    if not text:
        return None
    match = URL_RE.search(text)
    if match:
        return match.group(0)
    if text.lower().startswith(("http://", "https://")):
        return text.split()[0]
    return None


def normalize_host(netloc: str) -> str | None:
    host = netloc.rsplit("@", 1)[-1].split(":", 1)[0].strip("[]").lower().rstrip(".")
    if not host or not DOMAIN_RE.match(host):
        return None
    return host


def looks_opaque_path_token(value: str) -> bool:
    """Detect long path tokens that look like identifiers rather than words."""
    if OPAQUE_PATH_TOKEN_RE.match(value) is None:
        return False
    has_separator = "-" in value or "_" in value
    has_mixed_case = any(ch.islower() for ch in value) and any(ch.isupper() for ch in value)
    # Readable slugs usually contain separators and a single case; long compact
    # tokens or mixed-case base64url-like values are safer to redact.
    return has_mixed_case or not has_separator


def sanitize_segment(segment: str) -> tuple[str, bool]:
    decoded = unquote(segment)
    lower = decoded.lower()
    has_percent_encoding = "%" in segment
    has_digit = any(ch.isdigit() for ch in decoded)
    looks_dynamic = (
        has_percent_encoding
        or UUID_RE.match(decoded) is not None
        or LONG_HEX_RE.match(decoded) is not None
        or LONG_NUM_RE.match(decoded) is not None
        or NUMERIC_TOKEN_RE.match(decoded) is not None
        or looks_opaque_path_token(decoded)
        or (len(decoded) >= 16 and has_digit)
        or (SENSITIVE_WORD_RE.search(lower) is not None and has_digit)
    )
    if looks_dynamic:
        suffix_match = re.search(r"(\.[A-Za-z0-9]{1,8}(?:![A-Za-z0-9._-]+)?)$", decoded)
        if suffix_match and STATIC_EXT_RE.search(decoded):
            return f"<redacted:path-segment>{suffix_match.group(1)}", True
        return "<redacted:path-segment>", True
    # Keep only a conservative path character set; redact odd path data.
    if not re.match(r"^[A-Za-z0-9._~!$&'()+,;=:@-]+$", decoded):
        return "<redacted:path-segment>", True
    return decoded, False


def sanitize_path(path: str) -> tuple[str, bool]:
    if not path or path == "/":
        return "/", False
    parts = path.split("/")
    sanitized_parts: list[str] = []
    redacted = False
    for part in parts:
        if part == "":
            sanitized_parts.append("")
            continue
        sanitized, changed = sanitize_segment(part)
        sanitized_parts.append(sanitized)
        redacted = redacted or changed
    result = "/".join(sanitized_parts)
    return result if result.startswith("/") else f"/{result}", redacted


def redaction_kind(path_redacted: bool, had_query: bool) -> str:
    if path_redacted and had_query:
        return "path+query"
    if path_redacted:
        return "path"
    if had_query:
        return "query"
    return "none"


def classify_note(host: str, path_template: str) -> str:
    host_l = host.lower()
    path_l = path_template.lower()
    if "analytics" in host_l or "collect" in host_l or "collect" in path_l or "trace" in path_l:
        return "Telemetry/analytics endpoint"
    if "license" in host_l or "license" in path_l:
        return "License service"
    if "cdn" in host_l or "static" in host_l or "img" in host_l or STATIC_EXT_RE.search(path_template):
        return "Static asset"
    return "API endpoint"


def host_allowed(host: str, patterns: list[re.Pattern[str]]) -> bool:
    return not patterns or any(pattern.search(host) for pattern in patterns)


def render_markdown(name: str, source_label: str, grouped: dict[Target, list[str]]) -> str:
    lines = [
        f"# {name} request capture — {Path(source_label).name}",
        "",
        f"Source capture: `{source_label}`",
        "",
        "Extraction scope:",
        "",
        "- Kept only proxy-rule-relevant request targets: observed hostnames and sanitized URL path templates.",
        "- Omitted request headers, request bodies, response bodies, cookies, authorization data, account data, device identifiers, session identifiers, and full query strings.",
        "- The `host` column is the canonical input for Quantumult X and Clash domain rule generation.",
        "- The `redaction_kind` field records what was removed: `none`, `query`, `path`, or `path+query`.",
        "- `source_ids` are numeric capture request directory names when safe; otherwise they are sequential aliases.",
        "",
        "## Canonical observed targets",
        "",
        "| host | path_template | redaction_kind | source_ids | note |",
        "| --- | --- | --- | --- | --- |",
    ]
    sort_key = lambda item: (item[0].host, item[0].path_template, item[0].redaction_kind, item[0].note)
    for target, source_ids in sorted(grouped.items(), key=sort_key):
        sources = ", ".join(f"`{source_id}`" for source_id in sorted(source_ids, key=natural_key))
        lines.append(
            f"| `{target.host}` | `{target.path_template}` | `{target.redaction_kind}` | {sources} | {target.note} |"
        )
    lines.append("")
    return "\n".join(lines)


def default_source_label(path: Path) -> str:
    """Return a source label that avoids leaking absolute local paths."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.name


def natural_key(value: str) -> tuple[int, str] | tuple[int, int]:
    return (0, int(value)) if value.isdigit() else (1, value)


def main() -> int:
    args = parse_args()
    capture_dir = args.capture_dir
    if not capture_dir.is_dir():
        raise SystemExit(f"capture_dir does not exist or is not a directory: {capture_dir}")

    include_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in args.include_host_regex]
    grouped: dict[Target, list[str]] = defaultdict(list)

    for ordinal, request_dir in enumerate(iter_request_dirs(capture_dir), start=1):
        basic_text = (request_dir / "basic").read_text(encoding="utf-8", errors="replace")
        url = extract_url(basic_text)
        if not url:
            continue
        parsed = urlsplit(url)
        host = normalize_host(parsed.netloc)
        if not host or not host_allowed(host, include_patterns):
            continue
        path_template, path_redacted = sanitize_path(parsed.path)
        kind = redaction_kind(path_redacted=path_redacted, had_query=bool(parsed.query))
        target = Target(
            host=host,
            path_template=path_template,
            redaction_kind=kind,
            note=classify_note(host, path_template),
        )
        grouped[target].append(source_id_for(request_dir, ordinal, args.source_id_mode))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    source_label = args.source_label or default_source_label(capture_dir)
    args.output.write_text(render_markdown(args.name, source_label, grouped), encoding="utf-8")
    print(f"wrote {args.output} ({len(grouped)} observed targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
