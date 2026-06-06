#!/usr/bin/env python3
"""Generate Quantumult X and Clash domain rules from a collections list.

The generator consumes the collection host list, removes hosts covered by the
repository exclude list, then writes target-client rule files with deterministic
ordering and blackmatrix7-style metadata headers.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MARKDOWN_HOST_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$", re.IGNORECASE)
COLLECTION_TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2})(?:[-_]?(\d{6}))?")
SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True)
class RuleSet:
    exact_hosts: tuple[str, ...]
    suffix_domains: tuple[str, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Quantumult X .list and Clash YAML rules from a collections markdown/list file."
    )
    parser.add_argument("collection", type=Path, help="Collection markdown/list file containing observed hosts.")
    parser.add_argument("--slug", help="Rule file slug. Defaults to the collection parent directory name.")
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
            "Header timestamp. Defaults to a deterministic timestamp parsed from "
            "the collection file name/content, for example YYYY-mm-dd-HHMMSS."
        ),
    )
    parser.add_argument(
        "--suffix-domain",
        action="append",
        default=[],
        help="Domain to emit as HOST-SUFFIX/DOMAIN-SUFFIX when at least one included host matches it. Repeatable.",
    )
    return parser.parse_args()


def normalize_domain(value: str) -> str | None:
    host = value.strip().lower().rstrip(".")
    if not host or not DOMAIN_RE.match(host):
        return None
    return host


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


def read_collection_hosts(path: Path) -> tuple[str, ...]:
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
    hosts: list[str] = []
    for raw in source_lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        host: str | None = None
        match = MARKDOWN_HOST_RE.match(line)
        if match:
            value = match.group(1).strip()
            if value != "host":
                host = value
        elif not line.startswith("|"):
            # Also support plain host lists and existing comma-separated
            # Quantumult X / Clash rule rows.
            parts = [part.strip("` ") for part in line.split(",")]
            value = parts[1] if len(parts) >= 2 and parts[0].upper() in {"HOST", "HOST-SUFFIX", "DOMAIN", "DOMAIN-SUFFIX"} else parts[0]
            host = value
        domain = normalize_domain(host or "")
        if domain:
            hosts.append(domain)
    return tuple(sorted(dict.fromkeys(hosts)))


def normalize_suffix_domains(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(dict.fromkeys(domain for value in values if (domain := normalize_domain(value)))))


def validate_slug(slug: str) -> str:
    if not SLUG_RE.match(slug):
        raise SystemExit(f"invalid slug {slug!r}; use only letters, numbers, dot, underscore, or hyphen")
    return slug


def build_rules(hosts: Iterable[str], excludes: Iterable[str], suffix_domains: Iterable[str]) -> RuleSet:
    included_hosts = sorted(host for host in hosts if not is_excluded(host, excludes))
    excluded_hosts = sorted(host for host in hosts if is_excluded(host, excludes))
    suffix_conflicts = sorted(
        (domain, host)
        for domain in dict.fromkeys(normalize_domain(item) for item in suffix_domains)
        if domain
        for host in excluded_hosts
        if is_covered_by_domain(host, domain)
    )
    if suffix_conflicts:
        details = ", ".join(f"{domain} covers excluded host {host}" for domain, host in suffix_conflicts)
        raise SystemExit(f"suffix-domain conflicts with excluded observed hosts: {details}")
    suffixes = sorted(
        domain
        for domain in dict.fromkeys(normalize_domain(item) for item in suffix_domains)
        if domain and not is_excluded(domain, excludes) and any(is_covered_by_domain(host, domain) for host in included_hosts)
    )
    exact_hosts = sorted(
        host
        for host in included_hosts
        if not any(is_covered_by_domain(host, suffix) for suffix in suffixes)
    )
    return RuleSet(exact_hosts=tuple(exact_hosts), suffix_domains=tuple(suffixes))


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.name


def infer_updated(collection: Path) -> str | None:
    candidates = [collection.stem]
    try:
        candidates.append(collection.read_text(encoding="utf-8", errors="replace")[:1000])
    except OSError:
        pass

    for candidate in candidates:
        match = COLLECTION_TIMESTAMP_RE.search(candidate)
        if not match:
            continue
        date = match.group(1)
        time = match.group(2)
        if not time:
            return f"{date} 00:00:00"
        return f"{date} {time[0:2]}:{time[2:4]}:{time[4:6]}"
    return None


def resolve_updated(value: str | None, collection: Path) -> str:
    if value:
        return value
    inferred = infer_updated(collection)
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
    if not args.collection.is_file():
        raise SystemExit(f"collection file does not exist: {args.collection}")

    slug = args.slug or args.collection.parent.name
    if not slug:
        raise SystemExit("cannot infer slug; pass --slug")
    slug = validate_slug(slug)
    name = args.name or slug.replace("-", "_").title().replace("_", " ")
    policy = args.policy or name
    updated = resolve_updated(args.updated, args.collection)

    hosts = read_collection_hosts(args.collection)
    exclude_files = tuple(args.exclude_file or [Path("config/exclude-domains.list")])
    excludes = read_all_excludes(exclude_files)
    suffix_domains = normalize_suffix_domains(args.suffix_domain)
    rules = build_rules(hosts, excludes, suffix_domains)
    source = display_path(args.collection)
    exclude = ", ".join(display_path(path) for path in exclude_files)

    qx_dir = args.output_root / "QuantumultX"
    clash_dir = args.output_root / "Clash"
    qx_dir.mkdir(parents=True, exist_ok=True)
    clash_dir.mkdir(parents=True, exist_ok=True)

    qx_path = qx_dir / f"{slug}.list"
    clash_path = clash_dir / f"{slug}.yaml"
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

    excluded_count = len([host for host in hosts if is_excluded(host, excludes)])
    print(
        f"wrote {qx_path} and {clash_path} "
        f"({len(rules.exact_hosts)} exact, {len(rules.suffix_domains)} suffix, {excluded_count} excluded hosts)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
