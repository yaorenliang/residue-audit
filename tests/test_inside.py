"""Which paths are ours to read: the image decides, not the host running the audit."""

import os
import shutil
import tempfile
import unittest

from residue import inside


class InsideTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-inside-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "img")
        os.makedirs(self.root)

    def write(self, rel, body="x"):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path

    def link(self, rel, target):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(target, path)
        return path

    def test_a_plain_path_comes_back_as_its_real_path(self):
        path = self.write("etc/cron.d/job")
        real, why = inside.resolve(self.root, path)
        self.assertIsNone(why)
        self.assertEqual(real, os.path.realpath(path))

    def test_a_relative_link_is_followed_within_its_own_directory(self):
        target = self.write("usr/libexec/worker")
        link = self.link("etc/cron.d/job", "../../usr/libexec/worker")
        real, why = inside.resolve(self.root, link)
        self.assertIsNone(why)
        self.assertEqual(real, os.path.realpath(target))

    def test_an_absolute_link_is_read_as_a_path_inside_the_image(self):
        target = self.write("lib/systemd/system/zz.service", "KillSignal=SIGCONT\n")
        link = self.link("etc/systemd/system/zz.service", "/lib/systemd/system/zz.service")
        real, why = inside.resolve(self.root, link)
        self.assertIsNone(why)
        self.assertEqual(real, os.path.realpath(target))

    def test_an_absolute_link_with_no_image_counterpart_is_refused(self):
        link = self.link("etc/systemd/system/host.service", "/etc/passwd")
        real, why = inside.resolve(self.root, link)
        self.assertIsNone(real)
        self.assertIn("outside", why)

    def test_an_absolute_chain_that_stays_inside_the_root_is_read(self):
        # A tree mounted at its own absolute path is its own counterpart: the host
        # path is the same file, and refusing it would refuse the audited tree.
        target = self.write("usr/libexec/worker")
        link = self.link("etc/cron.d/job", target)
        real, why = inside.resolve(self.root, link)
        self.assertIsNone(why)
        self.assertEqual(real, os.path.realpath(target))

    def test_a_dangling_target_is_named_not_silently_dropped(self):
        link = self.link("etc/cron.d/job", "../../usr/libexec/missing")
        real, why = inside.resolve(self.root, link)
        self.assertIsNone(real)
        self.assertIn("no counterpart", why)

    def test_a_loop_is_named_not_walked_forever(self):
        first = os.path.join(self.root, "a")
        second = os.path.join(self.root, "b")
        os.symlink("b", first)
        os.symlink("a", second)
        real, why = inside.resolve(self.root, first)
        self.assertIsNone(real)
        self.assertIn("loop", why)

    def test_a_chain_longer_than_the_hop_limit_is_a_named_gap(self):
        end = self.write("end")
        previous = end
        for index in range(inside.MAX_HOPS + 5):
            hop = os.path.join(self.root, "hop-%02d" % index)
            os.symlink(os.path.basename(previous), hop)
            previous = hop
        real, why = inside.resolve(self.root, previous)
        self.assertIsNone(real)
        self.assertIn("longer than", why)

    def test_is_link_answers_for_the_entry_itself(self):
        entry = self.write("etc/cron.d/job")
        alias = self.link("etc/cron.d/alias", "job")
        self.assertTrue(inside.is_link(alias))
        self.assertFalse(inside.is_link(entry))


if __name__ == "__main__":
    unittest.main()
