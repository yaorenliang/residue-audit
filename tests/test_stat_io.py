"""stat_io is the boundary: every reader either returns a value or an error.

The tests here pin both halves of that promise, because the A-class finding was
exactly the missing second half - a failed listdir used to look like an empty
directory, and an empty directory looks like a clean one.
"""

import os
import shutil
import tempfile
import unittest

from residue import stat_io

OLD_MS = 1609459200000


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-stat-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, rel, body="x", mode=None):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        if mode is not None:
            os.chmod(path, mode)
        return path


class StatOfTest(TempDirTest):
    def test_one_call_answers_all_three_stamps(self):
        path = self.write("file")
        info, err = stat_io.stat_of(path)
        self.assertIsNone(err)
        self.assertEqual(info.mtime_ms, os.lstat(path).st_mtime_ns // stat_io.MS)
        self.assertEqual(info.ctime_ms, os.lstat(path).st_ctime_ns // stat_io.MS)
        self.assertEqual(info.ino, os.lstat(path).st_ino)

    def test_a_missing_path_returns_the_error_not_a_zero(self):
        info, err = stat_io.stat_of(os.path.join(self.tmp, "nope"))
        self.assertIsNone(info)
        self.assertEqual((err.op, err.err), ("stat", "No such file or directory"))
        self.assertTrue(err.path.endswith("nope"))


class SetMtimeTest(TempDirTest):
    def test_f15_set_mtime_keeps_millisecond_precision(self):
        path = self.write("file")
        wanted = OLD_MS + 123
        stat_io.set_mtime_ms(path, wanted)
        info, err = stat_io.stat_of(path)
        self.assertIsNone(err)
        self.assertEqual(info.mtime_ms, wanted)
        self.assertGreater(info.ino, 0)
        with self.assertRaises(AttributeError):
            info.mtime_ms = 0

    def test_f15_a_nonsense_mtime_is_refused_not_guessed(self):
        path = self.write("file")
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                stat_io.set_mtime_ms(path, bad)


class ListdirTest(TempDirTest):
    def test_a_missing_directory_is_not_an_error(self):
        names, err = stat_io.listdir_sorted(os.path.join(self.tmp, "nope"))
        self.assertEqual(names, [])
        self.assertIsNone(err)

    def test_f02_an_unreadable_directory_returns_the_error(self):
        path = os.path.join(self.tmp, "locked")
        os.makedirs(path)
        os.chmod(path, 0o000)
        self.addCleanup(os.chmod, path, 0o755)
        names, err = stat_io.listdir_sorted(path)
        self.assertEqual(names, [])
        self.assertIsNotNone(err)
        self.assertEqual(err.op, "listdir")
        self.assertEqual(err.path, path)
        self.assertTrue(err.err)
        self.assertEqual(err.to_dict(), {"path": path, "op": "listdir", "err": err.err})


class ReadHeadTest(TempDirTest):
    def test_f02_truncation_is_reported_with_the_text(self):
        path = self.write("long", "a" * 20)
        text, truncated, err = stat_io.read_head(path, limit=10)
        self.assertEqual(text, "a" * 10)
        self.assertTrue(truncated)
        self.assertIsNone(err)

    def test_a_short_file_is_not_truncated(self):
        path = self.write("short", "abc")
        text, truncated, err = stat_io.read_head(path, limit=10)
        self.assertEqual(text, "abc")
        self.assertFalse(truncated)
        self.assertIsNone(err)

    def test_f02_an_unreadable_file_returns_the_error(self):
        path = self.write("secret", "x", mode=0o000)
        self.addCleanup(os.chmod, path, 0o644)
        text, truncated, err = stat_io.read_head(path)
        self.assertEqual(text, "")
        self.assertFalse(truncated)
        self.assertIsNotNone(err)
        self.assertEqual(err.op, "read")


class DirStatsTest(TempDirTest):
    def test_f03_only_regular_files_are_siblings(self):
        self.write("a", "1")
        stat_io.set_mtime_ms(os.path.join(self.tmp, "a"), OLD_MS)
        self.write("b", "2")
        stat_io.set_mtime_ms(os.path.join(self.tmp, "b"), OLD_MS + 5)
        deeper = os.path.join(self.tmp, "sub")
        os.makedirs(deeper)
        os.utime(deeper, ns=((OLD_MS + 9000) * stat_io.MS, (OLD_MS + 9000) * stat_io.MS))
        os.symlink(os.path.join(self.tmp, "a"), os.path.join(self.tmp, "link"))

        cap, _cap_ctime, _max_ino, count = stat_io.dir_stats(self.tmp)
        self.assertEqual(count, 2)
        self.assertEqual(cap, OLD_MS + 5)

    def test_f03_our_own_files_are_not_their_own_sibling(self):
        mine = self.write("mine", "1")
        stat_io.set_mtime_ms(mine, OLD_MS + 5000)
        other = self.write("other", "2")
        stat_io.set_mtime_ms(other, OLD_MS)

        cap, _cap_ctime, _max_ino, count = stat_io.dir_stats(self.tmp, {mine})
        self.assertEqual(count, 1)
        self.assertEqual(cap, OLD_MS)

    def test_the_three_stamp_readers_are_gone(self):
        # Three readers meant three lstats, and the caller could catch one error
        # and keep the two values it already had. One reader, one answer.
        for name in ("mtime_ms", "ctime_ms", "ino", "dir_cap_ms"):
            self.assertFalse(hasattr(stat_io, name), name)
        cap, cap_ctime, _max_ino, count = stat_io.dir_stats(self.tmp)
        self.assertEqual(count, 0)
        self.assertEqual((cap, cap_ctime), (0, 0))


class WalkFilesTest(TempDirTest):
    def test_f21_members_are_files_and_resolving_symlinks(self):
        real = self.write("real", "x")
        os.symlink(real, os.path.join(self.tmp, "link"))
        os.symlink(self.tmp, os.path.join(self.tmp, "dirlink"))
        os.makedirs(os.path.join(self.tmp, "sub"))
        self.write("sub/nested", "x")

        paths, errors = stat_io.walk_files(self.tmp, "")
        self.assertEqual(errors, [])
        self.assertEqual(sorted(os.path.basename(p) for p in paths), ["link", "real"])

    def test_f02_a_missing_scan_directory_yields_no_error(self):
        paths, errors = stat_io.walk_files(self.tmp, "etc/nope")
        self.assertEqual(paths, [])
        self.assertEqual(errors, [])


class UnreachableScanTest(unittest.TestCase):
    """A scan directory we cannot search is a gap, a missing one is not."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-stat-perm-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.makedirs(os.path.join(self.tmp, "etc", "cron.d"))

    def test_an_unsearchable_scan_directory_is_reported(self):
        locked = os.path.join(self.tmp, "etc")
        os.chmod(locked, 0o444)
        self.addCleanup(os.chmod, locked, 0o755)
        paths, errors = stat_io.walk_files(self.tmp, "etc/cron.d")
        self.assertEqual(paths, [])
        self.assertEqual([error.op for error in errors], ["resolve"])
        self.assertIn("Permission denied", errors[0].err)
