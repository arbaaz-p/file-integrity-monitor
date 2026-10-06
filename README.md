# SHA-256 File Integrity Monitor

A Python command-line tool that creates a SHA-256 baseline for a directory and later reports created, modified, and deleted files. It is a focused defensive-security project built to practise hashing, repeatable evidence checks, structured reporting, and testing.

This project is a learning exercise for file integrity, evidence handling, and defensive security. A matching hash indicates that the file bytes are unchanged relative to the saved baseline. It does not prove who changed a file, when a change happened, or whether the original baseline was trustworthy.

## Run it

Python 3.10 or newer is recommended. The project has no third-party dependencies.

```bash
python3 fim.py baseline sample-directory --output baseline.json
python3 fim.py verify sample-directory --baseline baseline.json --report report.json
```

Repeat `--ignore` to exclude files or paths that should not be monitored:

```bash
python3 fim.py baseline sample-directory --output baseline.json --ignore "*.log" --ignore "cache/**"
```

The verify command exits with code `0` when no changes are found, `2` when changes are detected, and `1` for an error.

## Test it

```bash
python3 -m unittest -v
```

## What it demonstrates

- Streams files in binary chunks so large files do not need to be loaded into memory.
- Stores SHA-256 hashes and byte sizes in a versioned JSON baseline.
- Detects same-size content changes, additions, and deletions.
- Supports repeatable glob-based ignore rules without following symbolic links.
- Produces a timestamped JSON verification report and meaningful command-line exit codes.
- Includes automated tests for baseline round trips, change detection, ignores, and symlink handling.

## Example verification result

```json
{
  "changed": true,
  "changes": {
    "created": ["new-note.txt"],
    "deleted": ["old-note.txt"],
    "modified": ["evidence.txt"]
  }
}
```

## Security and forensic limitations

This tool checks whether file bytes differ from a saved baseline. It does not identify who made a change, establish when it happened, prove the baseline was trustworthy, protect the baseline from tampering, acquire a forensic disk image, or maintain chain of custody. A real deployment would protect and sign the baseline, centralize logs, control access, preserve trusted timestamps, and use documented evidence-handling procedures.

## Design decisions to explain

- Files are opened in binary mode so the hash represents their exact bytes rather than decoded text.
- SHA-256 is used as a strong general-purpose digest; comparing only file sizes would miss same-size edits.
- Symbolic links are skipped to avoid unexpectedly scanning outside the selected directory.
- Exit code `2` distinguishes detected changes from execution errors, which use exit code `1`.
