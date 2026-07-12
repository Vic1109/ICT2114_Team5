"""Focused regressions for bounded plain and compressed Wazuh archives."""

from __future__ import annotations

import gzip
import io
import sys
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from ssh import ArchiveFormatError, ArchiveReadLimitError, ArchiveReader  # noqa: E402


class _TrackedBytesIO(io.BytesIO):
    def __init__(self, payload: bytes):
        super().__init__(payload)
        self.readline_sizes: list[int] = []

    def readline(self, size: int = -1) -> bytes:
        self.readline_sizes.append(size)
        return super().readline(size)


class _MemorySFTP:
    def __init__(self, files: dict[str, bytes]):
        self.files = files
        self.opened: list[_TrackedBytesIO] = []

    def stat(self, path: str):
        if path not in self.files:
            raise FileNotFoundError(path)
        return SimpleNamespace(st_size=len(self.files[path]))

    def open(self, path: str, _mode: str):
        if path not in self.files:
            raise FileNotFoundError(path)
        handle = _TrackedBytesIO(self.files[path])
        self.opened.append(handle)
        return handle


def _connection(files: dict[str, bytes]):
    sftp = _MemorySFTP(files)
    return SimpleNamespace(
        is_connected=True,
        timeout=3,
        sftp=sftp,
        _set_remote_file_timeout=lambda _file, _timeout: None,
    )


def _archive_path(root: str, day: datetime, compressed: bool = False) -> str:
    suffix = ".json.gz" if compressed else ".json"
    return (
        f"{root}/{day.year}/{day.strftime('%b')}/"
        f"ossec-archive-{day.strftime('%d')}{suffix}"
    )


class ArchiveInputBoundTests(unittest.TestCase):
    def test_exact_record_limit_is_accepted_when_the_archive_is_exhausted(self):
        day = datetime(2026, 7, 9)
        root = "/archives"
        path = _archive_path(root, day)
        connection = _connection({path: b'{"record":1}\n'})
        reader = ArchiveReader(
            connection,
            root,
            max_archive_days=1,
            max_archive_records=1,
            max_archive_bytes=1024,
            max_archive_line_bytes=1024,
        )
        reader.get_smart_archive_dates = lambda _days: [day]
        accepted: list[dict] = []
        reader._append_log = accepted.append

        self.assertEqual(reader.read_archives_smart(1), 1)
        self.assertEqual(accepted, [{"record": 1}])

    def test_record_limit_aborts_instead_of_returning_a_partial_source_set(self):
        day = datetime(2026, 7, 9)
        root = "/archives"
        path = _archive_path(root, day)
        connection = _connection({path: b'{"record":1}\n{"record":2}\n'})
        reader = ArchiveReader(
            connection,
            root,
            max_archive_days=1,
            max_archive_records=1,
            max_archive_bytes=1024,
            max_archive_line_bytes=1024,
        )
        reader.get_smart_archive_dates = lambda _days: [day]
        accepted: list[dict] = []
        reader._append_log = accepted.append

        with self.assertRaisesRegex(ArchiveReadLimitError, "record limit"):
            reader.read_archives_smart(1)

        self.assertEqual(accepted, [{"record": 1}, {"record": 2}])
        self.assertTrue(all(handle.closed for handle in connection.sftp.opened))

    def test_plain_archive_corrupt_record_aborts_the_source_set(self):
        day = datetime(2026, 7, 9)
        root = "/archives"
        path = _archive_path(root, day)
        connection = _connection({path: b'{"record":1}\n{broken\n'})
        reader = ArchiveReader(connection, root, max_archive_days=1)
        reader.get_smart_archive_dates = lambda _days: [day]
        accepted: list[dict] = []
        reader._append_log = accepted.append

        with self.assertRaisesRegex(ArchiveFormatError, "line 2"):
            reader.read_archives_smart(1)

        self.assertEqual(accepted, [])

    def test_compressed_archive_nonobject_record_aborts_the_source_set(self):
        day = datetime(2026, 7, 9)
        root = "/archives"
        path = _archive_path(root, day, compressed=True)
        connection = _connection({path: gzip.compress(b'{"record":1}\n["not-an-object"]\n')})
        reader = ArchiveReader(connection, root, max_archive_days=1)
        reader.get_smart_archive_dates = lambda _days: [day]
        accepted: list[dict] = []
        reader._append_log = accepted.append

        with self.assertRaisesRegex(ArchiveFormatError, "line 2"):
            reader.read_archives_smart(1)

        self.assertEqual(accepted, [])

    def test_plain_archive_line_is_read_with_a_hard_size_bound(self):
        day = datetime(2026, 7, 9)
        root = "/archives"
        path = _archive_path(root, day)
        connection = _connection({path: b'{"value":"' + (b"A" * 200) + b'"}\n'})
        reader = ArchiveReader(
            connection,
            root,
            max_archive_days=1,
            max_archive_bytes=1024,
            max_archive_line_bytes=64,
        )
        reader.get_smart_archive_dates = lambda _days: [day]

        with self.assertRaisesRegex(ArchiveReadLimitError, "line-size limit"):
            reader.read_archives_smart(1)

        self.assertTrue(connection.sftp.opened[0].closed)
        self.assertLessEqual(max(connection.sftp.opened[0].readline_sizes), 65)

    def test_gzip_expansion_is_stopped_by_decompressed_byte_budget(self):
        day = datetime(2026, 7, 9)
        root = "/archives"
        gz_path = _archive_path(root, day, compressed=True)
        expanded = b'{"value":"' + (b"B" * 10_000) + b'"}\n'
        compressed = gzip.compress(expanded)
        self.assertLess(len(compressed), 256)
        connection = _connection({gz_path: compressed})
        reader = ArchiveReader(
            connection,
            root,
            max_archive_days=1,
            max_archive_bytes=128,
            max_archive_line_bytes=20_000,
        )
        reader.get_smart_archive_dates = lambda _days: [day]

        with self.assertRaisesRegex(ArchiveReadLimitError, "decompressed-byte limit"):
            reader.read_archives_smart(1)

        self.assertTrue(connection.sftp.opened[0].closed)

    def test_decompressed_budget_is_shared_across_archive_days(self):
        first_day = datetime(2026, 7, 9)
        second_day = datetime(2026, 7, 8)
        root = "/archives"
        first_line = b'{"day":1,"padding":"1234567890"}\n'
        second_line = b'{"day":2,"padding":"1234567890"}\n'
        connection = _connection({
            _archive_path(root, first_day): first_line,
            _archive_path(root, second_day): second_line,
        })
        reader = ArchiveReader(
            connection,
            root,
            max_archive_days=2,
            max_archive_bytes=len(first_line) + len(second_line) - 1,
            max_archive_line_bytes=1024,
        )
        reader.get_smart_archive_dates = lambda _days: [first_day, second_day]
        accepted: list[dict] = []
        reader._append_log = accepted.append

        with self.assertRaisesRegex(ArchiveReadLimitError, "decompressed-byte limit"):
            reader.read_archives_smart(2)

        self.assertEqual(accepted, [{"day": 1, "padding": "1234567890"}])
        self.assertTrue(all(handle.closed for handle in connection.sftp.opened))


if __name__ == "__main__":
    unittest.main()
