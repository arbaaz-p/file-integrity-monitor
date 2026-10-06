"""Small file-integrity monitor for a student cybersecurity portfolio.

The tool creates a SHA-256 baseline for files in a directory and compares a
later scan with that baseline. It reports created, modified, and deleted files.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


DEFAULT_IGNORE_PATTERNS = (".git", ".git/**", ".pytest_cache", ".pytest_cache/**", "__pycache__", "**/__pycache__/**", ".DS_Store")


@dataclass(frozen=True)
class FileRecord:
    sha256: str
    size: int


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def matches_ignore(relative_path: str, patterns: Iterable[str]) -> bool:
    """Return True when a POSIX-style relative path matches an ignore pattern."""
    return any(
        fnmatch.fnmatch(relative_path, pattern)
        or any(fnmatch.fnmatch(part, pattern) for part in relative_path.split("/"))
        for pattern in patterns
    )


def iter_files(root: Path, ignored_patterns: Iterable[str] | None = None) -> Iterable[Path]:
    patterns = tuple(DEFAULT_IGNORE_PATTERNS) + tuple(ignored_patterns or ())
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if matches_ignore(relative, patterns):
            continue
        if path.is_file() and not path.is_symlink():
            yield path


def scan(
    root: Path,
    excluded_files: set[Path] | None = None,
    ignored_patterns: Iterable[str] | None = None,
) -> dict[str, FileRecord]:
    root = root.resolve()
    excluded = {p.resolve() for p in (excluded_files or set())}
    records: dict[str, FileRecord] = {}
    for path in iter_files(root, ignored_patterns):
        if path.resolve() in excluded:
            continue
        relative = path.relative_to(root).as_posix()
        records[relative] = FileRecord(sha256=sha256_file(path), size=path.stat().st_size)
    return records


def save_baseline(path: Path, root: Path, records: dict[str, FileRecord]) -> None:
    payload = {
        "schema_version": 1,
        "algorithm": "SHA-256",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "root": str(root.resolve()),
        "file_count": len(records),
        "files": {name: asdict(record) for name, record in sorted(records.items())},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> dict[str, FileRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("algorithm") != "SHA-256":
        raise ValueError("Unsupported or missing baseline algorithm")
    files = payload.get("files")
    if not isinstance(files, dict):
        raise ValueError("Baseline is missing the files object")
    records: dict[str, FileRecord] = {}
    for name, record in files.items():
        if not isinstance(name, str) or not isinstance(record, dict):
            raise ValueError("Baseline contains an invalid file record")
        sha256 = record.get("sha256")
        size = record.get("size")
        if not isinstance(sha256, str) or len(sha256) != 64 or any(character not in "0123456789abcdef" for character in sha256.lower()):
            raise ValueError(f"Baseline contains an invalid SHA-256 value for {name}")
        if not isinstance(size, int) or size < 0:
            raise ValueError(f"Baseline contains an invalid file size for {name}")
        records[name] = FileRecord(sha256=sha256.lower(), size=size)
    return records


def compare(baseline: dict[str, FileRecord], current: dict[str, FileRecord]) -> dict[str, list[str]]:
    old_names = set(baseline)
    new_names = set(current)
    return {
        "created": sorted(new_names - old_names),
        "modified": sorted(name for name in old_names & new_names if baseline[name] != current[name]),
        "deleted": sorted(old_names - new_names),
    }


def has_changes(report: dict[str, list[str]]) -> bool:
    return any(report.values())


def build_report(root: Path, baseline_path: Path, changes: dict[str, list[str]]) -> dict[str, object]:
    return {
        "algorithm": "SHA-256",
        "scanned_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scanned_root": str(root.resolve()),
        "baseline": str(baseline_path.resolve()),
        "changed": has_changes(changes),
        "changes": changes,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create and verify SHA-256 file-integrity baselines.")
    sub = parser.add_subparsers(dest="command", required=True)

    baseline = sub.add_parser("baseline", help="Create or replace a baseline")
    baseline.add_argument("directory", type=Path)
    baseline.add_argument("--output", type=Path, default=Path("baseline.json"))
    baseline.add_argument("--ignore", action="append", default=[], metavar="PATTERN", help="Ignore a glob pattern; may be repeated")

    verify = sub.add_parser("verify", help="Compare a directory with a baseline")
    verify.add_argument("directory", type=Path)
    verify.add_argument("--baseline", type=Path, default=Path("baseline.json"))
    verify.add_argument("--report", type=Path, help="Optional path for a JSON report")
    verify.add_argument("--ignore", action="append", default=[], metavar="PATTERN", help="Ignore a glob pattern; may be repeated")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    directory = args.directory.resolve()
    if not directory.is_dir():
        print(f"error: directory not found: {directory}", file=sys.stderr)
        return 1

    try:
        if args.command == "baseline":
            output = args.output.resolve()
            records = scan(directory, excluded_files={output}, ignored_patterns=args.ignore)
            save_baseline(output, directory, records)
            print(f"Baseline written to {output} with {len(records)} files.")
            return 0

        baseline_path = args.baseline.resolve()
        baseline = load_baseline(baseline_path)
        excluded = {baseline_path}
        if args.report:
            excluded.add(args.report.resolve())
        current = scan(directory, excluded_files=excluded, ignored_patterns=args.ignore)
        changes = compare(baseline, current)
        report = build_report(directory, baseline_path, changes)
        output_text = json.dumps(report, indent=2, sort_keys=True)
        print(output_text)
        if args.report:
            args.report.write_text(output_text + "\n", encoding="utf-8")
        return 2 if has_changes(changes) else 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
