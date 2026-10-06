import tempfile
import unittest
from pathlib import Path

from fim import FileRecord, build_report, compare, load_baseline, save_baseline, scan


class FileIntegrityMonitorTests(unittest.TestCase):
    def test_scan_and_baseline_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "evidence.txt").write_text("original", encoding="utf-8")
            records = scan(root)
            baseline_path = root / "baseline.json"
            save_baseline(baseline_path, root, records)

            loaded = load_baseline(baseline_path)
            self.assertEqual(records, loaded)
            self.assertEqual(set(records), {"evidence.txt"})

    def test_compare_detects_created_modified_and_deleted(self):
        baseline = {
            "changed.txt": FileRecord("aaa", 3),
            "deleted.txt": FileRecord("bbb", 3),
        }
        current = {
            "changed.txt": FileRecord("ccc", 3),
            "created.txt": FileRecord("ddd", 3),
        }
        self.assertEqual(
            compare(baseline, current),
            {
                "created": ["created.txt"],
                "modified": ["changed.txt"],
                "deleted": ["deleted.txt"],
            },
        )

    def test_scan_ignores_git_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".git").mkdir()
            (root / ".git" / "secret").write_text("not scanned", encoding="utf-8")
            (root / "visible.txt").write_text("scanned", encoding="utf-8")
            self.assertEqual(set(scan(root)), {"visible.txt"})

    def test_same_size_content_change_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence.txt"
            evidence.write_text("first!", encoding="utf-8")
            baseline = scan(root)
            evidence.write_text("second", encoding="utf-8")
            current = scan(root)
            self.assertEqual(baseline["evidence.txt"].size, current["evidence.txt"].size)
            self.assertEqual(compare(baseline, current)["modified"], ["evidence.txt"])

    def test_custom_ignore_pattern(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "keep.txt").write_text("keep", encoding="utf-8")
            (root / "debug.log").write_text("ignore", encoding="utf-8")
            self.assertEqual(set(scan(root, ignored_patterns=["*.log"])), {"keep.txt"})

    def test_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.txt"
            target.write_text("data", encoding="utf-8")
            (root / "link.txt").symlink_to(target)
            self.assertEqual(set(scan(root)), {"target.txt"})

    def test_report_records_change_state(self):
        changes = {"created": ["new.txt"], "modified": [], "deleted": []}
        report = build_report(Path("."), Path("baseline.json"), changes)
        self.assertTrue(report["changed"])
        self.assertEqual(report["changes"], changes)


if __name__ == "__main__":
    unittest.main()
