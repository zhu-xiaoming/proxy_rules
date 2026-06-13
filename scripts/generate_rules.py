#!/usr/bin/env python3
"""Generate Quantumult X and Clash domain rules from collection inputs.

The generator consumes collection host/domain lists, removes targets covered by
the repository exclude list, then writes target-client rule files with
deterministic ordering and blackmatrix7-style metadata headers.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

MARKDOWN_HOST_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$", re.IGNORECASE)
COLLECTION_TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})(?:(?:[-_]?(\d{6}))|(?:[ T](\d{2}):(\d{2}):(\d{2})))?"
)
SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+$")
COLLECTION_FILE_SUFFIXES = {".list", ".md", ".txt"}
EXACT_RULE_TYPES = {"HOST", "DOMAIN"}
SUFFIX_RULE_TYPES = {"HOST-SUFFIX", "DOMAIN-SUFFIX"}


@dataclass(frozen=True)
class CollectionTargets:
    exact_hosts: tuple[str, ...]
    suffix_domains: tuple[str, ...]


@dataclass(frozen=True)
class RuleSet:
    exact_hosts: tuple[str, ...]
    suffix_domains: tuple[str, ...]


@dataclass(frozen=True)
class GenerationJob:
    slug: str
    inputs: tuple[Path, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate Quantumult X .list and Clash YAML rules from collection files or "
            "a collections directory."
        )
    )
    parser.add_argument(
        "collection",
        type=Path,
        help=(
            "Collection file, app collection directory, or the collections/ root. "
            "A collections/ root generates one rule set per app subdirectory."
        ),
    )
    parser.add_argument(
        "--slug",
        help=(
            "Rule file slug. Defaults to the collection parent directory name for files, "
            "or the collection directory name for app directories."
        ),
    )
    parser.add_argument("--name", help="Display/policy name. Defaults to title-cased slug.")
    parser.add_argument("--policy", help="Quantumult X policy tag. Defaults to --name.")
    parser.add_argument(
        "--exclude-file",
        type=Path,
        action="append",
        help=(
            "Exclude list file. Can be repeated for global plus app-specific excludes. "
            "Defaults to config/exclude-domains.list when omitted."
        ),
    )
    parser.add_argument("--output-root", type=Path, default=Path("rules"))
    parser.add_argument("--repo", default="https://github.com/zhu-xiaoming/proxy_rules")
    parser.add_argument("--author", default="zhu-xiaoming")
    parser.add_argument(
        "--updated",
        help=(
            "Header timestamp. Defaults to a timestamp parsed from collection "
            "file names/content, then falls back to file modification time."
        ),
    )
    parser.add_argument(
        "--suffix-domain",
        action="append",
        default=[],
        help="Domain to emit as HOST-SUFFIX/DOMAIN-SUFFIX when at least one included host matches it. Repeatable.",
    )
    parser.add_argument(
        "--plain-list-kind",
        choices=("auto", "exact", "suffix"),
        default="auto",
        help=(
            "How to interpret plain domain rows without HOST/DOMAIN-SUFFIX prefixes. "
            "auto treats .list files such as collections.list as suffix-domain lists "
            "and markdown/plain .txt inputs as exact observed hosts."
        ),
    )
    return parser.parse_args()


def normalize_domain(value: str) -> str | None:
    host = value.strip().strip("`'\"").lower().rstrip(".")
    if not host or not DOMAIN_RE.match(host):
        return None
    return host


def normalize_target_token(value: str) -> tuple[str, str | None]:
    """Normalize one domain-like token and infer whether it is exact or suffix."""
    token = value.strip().strip("`'\"")
    if not token:
        return "exact", None
    if token.startswith(("http://", "https://")):
        parsed = urlsplit(token)
        token = parsed.netloc.rsplit("@", 1)[-1].split(":", 1)[0].strip("[]")
        return "exact", normalize_domain(token)
    if token.startswith("||") and token.endswith("^"):
        return "suffix", normalize_domain(token[2:-1])
    if token.startswith("*."):
        return "suffix", normalize_domain(token[2:])
    if token.startswith("."):
        return "suffix", normalize_domain(token[1:])
    return "exact", normalize_domain(token)


def read_excludes(path: Path) -> tuple[str, ...]:
    if not path.exists():
        raise SystemExit(f"exclude file does not exist: {path}")
    domains: list[str] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        domain = normalize_domain(line)
        if domain:
            domains.append(domain)
        else:
            print(f"warning: ignored invalid exclude domain at {path}:{line_no}: {raw.strip()}", file=sys.stderr)
    return tuple(sorted(dict.fromkeys(domains)))


def read_all_excludes(paths: Iterable[Path]) -> tuple[str, ...]:
    domains: list[str] = []
    for path in paths:
        domains.extend(read_excludes(path))
    return tuple(sorted(dict.fromkeys(domains)))


def is_covered_by_domain(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def is_excluded(host: str, excludes: Iterable[str]) -> bool:
    return any(is_covered_by_domain(host, domain) for domain in excludes)


def plain_list_kind_for(path: Path, configured: str) -> str:
    if configured != "auto":
        return configured
    if path.suffix.lower() == ".list" or path.name.lower() in {"collections.list", "domains.list", "domain-suffixes.list"}:
        return "suffix"
    return "exact"


def strip_inline_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


def add_target(
    *,
    value: str,
    kind: str,
    exact_hosts: list[str],
    suffix_domains: list[str],
    path: Path,
    line_no: int,
    raw: str,
) -> None:
    inferred_kind, domain = normalize_target_token(value)
    if not domain:
        print(f"warning: ignored invalid collection target at {path}:{line_no}: {raw.strip()}", file=sys.stderr)
        return
    final_kind = inferred_kind if inferred_kind == "suffix" else kind
    if final_kind == "suffix":
        suffix_domains.append(domain)
    else:
        exact_hosts.append(domain)


def read_collection_targets(path: Path, *, plain_list_kind: str = "auto") -> CollectionTargets:
    all_lines = path.read_text(encoding="utf-8").splitlines()
    canonical_lines: list[str] = []
    in_canonical_section = False
    saw_canonical_section = False
    for raw in all_lines:
        stripped = raw.strip()
        if stripped.startswith("## "):
            if stripped.lower() == "## canonical observed targets":
                saw_canonical_section = True
                in_canonical_section = True
                continue
            if in_canonical_section:
                break
        if in_canonical_section:
            canonical_lines.append(raw)

    # Markdown collections use the canonical table as the machine-readable
    # interface. Plain host lists keep working by falling back to every line.
    source_lines = canonical_lines if saw_canonical_section else all_lines
    exact_hosts: list[str] = []
    suffix_domains: list[str] = []
    default_kind = "exact" if saw_canonical_section else plain_list_kind_for(path, plain_list_kind)
    for line_no, raw in enumerate(source_lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        value: str | None = None
        kind = default_kind
        match = MARKDOWN_HOST_RE.match(line)
        if match:
            markdown_value = match.group(1).strip()
            if markdown_value != "host":
                value = markdown_value
                kind = "exact"
        elif not line.startswith("|") or line.startswith("||"):
            # Support plain domain lists, existing Quantumult X / Clash rows,
            # and YAML payload rows such as "- DOMAIN-SUFFIX,example.com".
            line = strip_inline_comment(line)
            if not line:
                continue
            if line.startswith("- "):
                line = line[2:].strip()
            line = line.strip("'\"")
            parts = [part.strip("` '\"") for part in line.split(",")]
            rule_type = parts[0].upper() if parts else ""
            if len(parts) >= 2 and rule_type in EXACT_RULE_TYPES | SUFFIX_RULE_TYPES:
                value = parts[1]
                kind = "suffix" if rule_type in SUFFIX_RULE_TYPES else "exact"
            elif rule_type in {"PAYLOAD:", "PAYLOAD"}:
                continue
            else:
                value = parts[0] if parts else None
        if value:
            add_target(
                value=value,
                kind=kind,
                exact_hosts=exact_hosts,
                suffix_domains=suffix_domains,
                path=path,
                line_no=line_no,
                raw=raw,
            )
    return CollectionTargets(
        exact_hosts=tuple(sorted(dict.fromkeys(exact_hosts))),
        suffix_domains=tuple(sorted(dict.fromkeys(suffix_domains))),
    )


def read_all_collection_targets(paths: Iterable[Path], *, plain_list_kind: str = "auto") -> CollectionTargets:
    exact_hosts: list[str] = []
    suffix_domains: list[str] = []
    for path in paths:
        targets = read_collection_targets(path, plain_list_kind=plain_list_kind)
        exact_hosts.extend(targets.exact_hosts)
        suffix_domains.extend(targets.suffix_domains)
    return CollectionTargets(
        exact_hosts=tuple(sorted(dict.fromkeys(exact_hosts))),
        suffix_domains=tuple(sorted(dict.fromkeys(suffix_domains))),
    )


def normalize_suffix_domains(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(dict.fromkeys(domain for value in values if (domain := normalize_domain(value)))))


def validate_slug(slug: str) -> str:
    if not SLUG_RE.match(slug):
        raise SystemExit(f"invalid slug {slug!r}; use only letters, numbers, dot, underscore, or hyphen")
    return slug


def build_rules(targets: CollectionTargets, excludes: Iterable[str], collapse_suffix_domains: Iterable[str]) -> RuleSet:
    included_hosts = sorted(host for host in targets.exact_hosts if not is_excluded(host, excludes))
    excluded_hosts = sorted(host for host in targets.exact_hosts if is_excluded(host, excludes))
    source_suffixes = sorted(domain for domain in targets.suffix_domains if not is_excluded(domain, excludes))
    source_suffix_set = set(source_suffixes)
    collapse_candidates = normalize_suffix_domains(collapse_suffix_domains)
    active_suffix_candidates = sorted(
        dict.fromkeys(
            domain
            for domain in (*source_suffixes, *collapse_candidates)
            if not is_excluded(domain, excludes)
        )
    )
    suffix_conflicts = sorted(
        (domain, host)
        for domain in active_suffix_candidates
        for host in excluded_hosts
        if is_covered_by_domain(host, domain)
    )
    if suffix_conflicts:
        details = ", ".join(f"{domain} covers excluded host {host}" for domain, host in suffix_conflicts)
        raise SystemExit(f"suffix-domain conflicts with excluded observed hosts: {details}")
    collapse_suffixes = sorted(
        domain
        for domain in collapse_candidates
        if domain
        and domain not in source_suffix_set
        and not is_excluded(domain, excludes)
        and any(is_covered_by_domain(host, domain) for host in included_hosts)
    )
    suffixes = sorted(dict.fromkeys((*source_suffixes, *collapse_suffixes)))
    exact_hosts = sorted(
        host
        for host in included_hosts
        if not any(is_covered_by_domain(host, suffix) for suffix in suffixes)
    )
    return RuleSet(exact_hosts=tuple(exact_hosts), suffix_domains=tuple(suffixes))


def is_supported_collection_file(path: Path) -> bool:
    return path.is_file() and not path.name.startswith(".") and path.suffix.lower() in COLLECTION_FILE_SUFFIXES


def collection_files_in_dir(path: Path) -> tuple[Path, ...]:
    return tuple(sorted((child for child in path.iterdir() if is_supported_collection_file(child)), key=lambda p: p.name))


def discover_jobs(collection: Path, slug: str | None) -> tuple[GenerationJob, ...]:
    if collection.is_file():
        job_slug = slug or collection.parent.name
        if not job_slug:
            raise SystemExit("cannot infer slug; pass --slug")
        return (GenerationJob(slug=validate_slug(job_slug), inputs=(collection,)),)

    if not collection.is_dir():
        raise SystemExit(f"collection path does not exist: {collection}")

    if slug:
        inputs = collection_files_in_dir(collection)
        if not inputs:
            raise SystemExit(f"no supported collection files found in: {collection}")
        return (GenerationJob(slug=validate_slug(slug), inputs=inputs),)

    direct_inputs = collection_files_in_dir(collection)
    if direct_inputs:
        return (GenerationJob(slug=validate_slug(collection.name), inputs=direct_inputs),)

    jobs: list[GenerationJob] = []
    for child in sorted((item for item in collection.iterdir() if item.is_dir()), key=lambda p: p.name):
        inputs = collection_files_in_dir(child)
        if inputs:
            jobs.append(GenerationJob(slug=validate_slug(child.name), inputs=inputs))
    if not jobs:
        raise SystemExit(f"no supported collection files found in: {collection}")
    return tuple(jobs)


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.name


def timestamp_from_text(text: str) -> str | None:
    match = COLLECTION_TIMESTAMP_RE.search(text)
    if not match:
        return None
    date = match.group(1)
    compact_time = match.group(2)
    hour, minute, second = match.group(3), match.group(4), match.group(5)
    if compact_time:
        return f"{date} {compact_time[0:2]}:{compact_time[2:4]}:{compact_time[4:6]}"
    if hour and minute and second:
        return f"{date} {hour}:{minute}:{second}"
    else:
        return f"{date} 00:00:00"


def mtime_timestamp(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        return None


def infer_updated_for_path(collection: Path) -> str | None:
    candidates = [collection.stem]
    try:
        candidates.append(collection.read_text(encoding="utf-8", errors="replace")[:1000])
    except OSError:
        pass

    for candidate in candidates:
        if timestamp := timestamp_from_text(candidate):
            return timestamp
    return None


def infer_updated(collections: Iterable[Path]) -> str | None:
    timestamps: list[str] = []
    for collection in collections:
        timestamp = infer_updated_for_path(collection) or mtime_timestamp(collection)
        if timestamp:
            timestamps.append(timestamp)
    return max(timestamps) if timestamps else None


def resolve_updated(value: str | None, collections: Iterable[Path]) -> str:
    if value:
        return value
    inputs = tuple(collections)
    inferred = infer_updated(inputs)
    if inferred:
        return inferred
    raise SystemExit(
        "cannot infer deterministic UPDATED header; pass --updated 'YYYY-MM-DD HH:MM:SS' "
        "or use a dated collection file name such as YYYY-MM-DD-HHMMSS.md"
    )


def header_lines(
    name: str,
    author: str,
    repo: str,
    updated: str,
    counts: Counter[str],
    total: int,
    *,
    source: str,
    exclude: str,
    suffix_domains: tuple[str, ...],
) -> list[str]:
    lines = [
        f"# NAME: {name}",
        f"# AUTHOR: {author}",
        f"# REPO: {repo}",
        f"# UPDATED: {updated}",
        f"# SOURCE: {source}",
        f"# EXCLUDE: {exclude}",
    ]
    if suffix_domains:
        lines.append(f"# SUFFIX-DOMAIN: {', '.join(suffix_domains)}")
    for kind in sorted(counts):
        count = counts[kind]
        if count:
            lines.append(f"# {kind}: {count}")
    lines.append(f"# TOTAL: {total}")
    return lines


def render_quantumultx(
    rules: RuleSet,
    *,
    name: str,
    policy: str,
    author: str,
    repo: str,
    updated: str,
    source: str,
    exclude: str,
) -> str:
    counts = Counter({"HOST": len(rules.exact_hosts), "HOST-SUFFIX": len(rules.suffix_domains)})
    total = sum(counts.values())
    lines = header_lines(
        name,
        author,
        repo,
        updated,
        counts,
        total,
        source=source,
        exclude=exclude,
        suffix_domains=rules.suffix_domains,
    )
    lines.extend(f"HOST,{host},{policy}" for host in rules.exact_hosts)
    lines.extend(f"HOST-SUFFIX,{domain},{policy}" for domain in rules.suffix_domains)
    return "\n".join(lines) + "\n"


def render_clash(
    rules: RuleSet,
    *,
    name: str,
    author: str,
    repo: str,
    updated: str,
    source: str,
    exclude: str,
) -> str:
    counts = Counter({"DOMAIN": len(rules.exact_hosts), "DOMAIN-SUFFIX": len(rules.suffix_domains)})
    total = sum(counts.values())
    lines = header_lines(
        name,
        author,
        repo,
        updated,
        counts,
        total,
        source=source,
        exclude=exclude,
        suffix_domains=rules.suffix_domains,
    )
    lines.append("payload:")
    lines.extend(f"  - DOMAIN,{host}" for host in rules.exact_hosts)
    lines.extend(f"  - DOMAIN-SUFFIX,{domain}" for domain in rules.suffix_domains)
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    exclude_files = tuple(args.exclude_file or [Path("config/exclude-domains.list")])
    excludes = read_all_excludes(exclude_files)
    exclude = ", ".join(display_path(path) for path in exclude_files)
    jobs = discover_jobs(args.collection, args.slug)

    if len(jobs) > 1 and (args.name or args.policy):
        raise SystemExit("--name/--policy can only be used when generating one rule set")

    qx_dir = args.output_root / "QuantumultX"
    clash_dir = args.output_root / "Clash"
    qx_dir.mkdir(parents=True, exist_ok=True)
    clash_dir.mkdir(parents=True, exist_ok=True)

    for job in jobs:
        name = args.name or job.slug.replace("-", "_").title().replace("_", " ")
        policy = args.policy or name
        updated = resolve_updated(args.updated, job.inputs)
        targets = read_all_collection_targets(job.inputs, plain_list_kind=args.plain_list_kind)
        rules = build_rules(targets, excludes, args.suffix_domain)
        source = ", ".join(display_path(path) for path in job.inputs)

        qx_path = qx_dir / f"{job.slug}.list"
        clash_path = clash_dir / f"{job.slug}.yaml"
        qx_path.write_text(
            render_quantumultx(
                rules,
                name=name,
                policy=policy,
                author=args.author,
                repo=args.repo,
                updated=updated,
                source=source,
                exclude=exclude,
            ),
            encoding="utf-8",
        )
        clash_path.write_text(
            render_clash(
                rules,
                name=name,
                author=args.author,
                repo=args.repo,
                updated=updated,
                source=source,
                exclude=exclude,
            ),
            encoding="utf-8",
        )

        excluded_exact_count = len([host for host in targets.exact_hosts if is_excluded(host, excludes)])
        excluded_suffix_count = len([domain for domain in targets.suffix_domains if is_excluded(domain, excludes)])
        print(
            f"wrote {qx_path} and {clash_path} "
            f"({len(rules.exact_hosts)} exact, {len(rules.suffix_domains)} suffix, "
            f"{excluded_exact_count} excluded hosts, {excluded_suffix_count} excluded suffixes)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
