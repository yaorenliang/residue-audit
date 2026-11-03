"""The branches that only a failure can reach, and the ones that carry no value.

Every test here is aimed at a mutation that survived the suite: a guard that
looks defensive but has never been entered, or an expression whose two spellings
differ only where nobody looked. They are grouped by the question they answer,
not by the module they live in, because the point of each one is the behaviour
that was invisible.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from residue import _fixtures, batch, cli, demo, dwell, inside, model, report, stat_io, trace


def touch(path: str, text: str = "x\n") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def hits_none() -> "trace.Hits":
    return trace.Hits((), (), (), (), (), (), ())


def art(path: str, stamp=None, marker: str = "m") -> "trace.ArtifactObs":
    return trace.ArtifactObs(path, path, marker, stamp)


class SanitizeTest(unittest.TestCase):
    """The token is built from the root as the caller spelled it."""

    def test_a_root_spelled_with_a_dot_still_becomes_the_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            path = touch(os.path.join(root, "etc", "x"))
            self.assertEqual(
                trace.sanitize(path, root + os.sep + "."), "<root>/etc/x"
            )

    def test_a_path_outside_the_root_is_shown_in_full(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            other = os.path.join(tmp, "other")
            self.assertEqual(trace.sanitize(other, root), other)


class MarkerReadingTest(unittest.TestCase):
    """Two readers that answer a question about text, not about the disk."""

    def test_text_without_a_marker_is_false_not_none(self):
        self.assertIs(trace.carries_marker("nothing here\n", ("marker",)), False)

    def test_a_quoted_exec_start_still_names_its_path(self):
        self.assertEqual(
            trace.exec_start_targets("ExecStart='/bin/sh' -c 'echo hi'"), ["/bin/sh"]
        )


class ListingIsCachedTest(unittest.TestCase):
    """One pass lists a set of directories once: a tree can change under it."""

    def test_the_second_visit_reuses_the_first_listing(self):
        scratch = trace._Scratch(root="/r", scan=("etc",), markers=(), broad=False)
        with mock.patch.object(
            stat_io, "walk_files", side_effect=[(["/r/etc/a"], []), (["/r/etc/b"], [])]
        ) as walk:
            first = trace._list(scratch, ("etc",))
            second = trace._list(scratch, ("etc",))
        self.assertEqual(first, ["/r/etc/a"])
        self.assertEqual(second, ["/r/etc/a"])
        self.assertEqual(walk.call_count, 1)


class StampReadingTest(unittest.TestCase):
    """A claim is stamped by the entry itself, and a gap in the path is named."""

    def test_a_link_that_leaves_the_image_is_a_named_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            link = os.path.join(root, "etc", "systemd", "system", "zz.service")
            os.makedirs(os.path.dirname(link))
            os.symlink("/etc/hostname", link)
            scratch = trace._Scratch(root=root, scan=(), markers=(), broad=False)
            scratch.claims[link] = "unit:marker"
            arts = trace._stamp(scratch)
        self.assertEqual(len(arts), 1)
        self.assertIsNotNone(arts[0].stamp)
        self.assertTrue(
            any(err.op == "resolve" for err in scratch.errors),
            "the link was read anyway: %r" % (scratch.errors,),
        )

    def test_a_claim_under_a_directory_that_leaves_the_image_is_not_stamped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            outside = os.path.join(tmp, "outside")
            os.makedirs(root)
            os.makedirs(outside)
            path = os.path.join(root, "etc", "systemd", "system", "x.service")
            os.makedirs(os.path.dirname(os.path.dirname(path)))
            os.symlink(outside, os.path.dirname(path))
            scratch = trace._Scratch(root=root, scan=(), markers=(), broad=False)
            scratch.claims[path] = "unit:marker"
            arts = trace._stamp(scratch)
        self.assertEqual(len(arts), 1)
        self.assertIsNone(arts[0].stamp)
        self.assertEqual([err.path for err in scratch.errors], [path])
        self.assertEqual(scratch.errors[0].op, "resolve")

    def test_a_stamp_that_could_not_be_read_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            path = touch(os.path.join(root, "f"))
            scratch = trace._Scratch(root=root, scan=(), markers=(), broad=False)
            scratch.claims[path] = "unit:marker"
            err = stat_io.StatError(path, "stat", "boom")
            with mock.patch.object(stat_io, "stat_of", return_value=(None, err)):
                trace._stamp(scratch)
        self.assertEqual(list(scratch.errors), [err])


class DirectoryChangedTest(unittest.TestCase):
    """Every early exit of the directory-changed comparison."""

    def _scratch(self, root: str) -> "trace._Scratch":
        return trace._Scratch(root=root, scan=(), markers=(), broad=False)

    def test_a_directory_that_cannot_be_resolved_is_not_dated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            gone = os.path.join(root, "gone")
            self.assertIsNone(
                trace._directory_changed_after(self._scratch(root), gone, ())
            )

    def test_a_directory_that_cannot_be_stamped_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            scratch = self._scratch(root)
            err = stat_io.StatError(root, "stat", "boom")
            with mock.patch.object(stat_io, "stat_of", return_value=(None, err)):
                self.assertIsNone(
                    trace._directory_changed_after(scratch, root, ())
                )
        self.assertEqual(list(scratch.errors), [err])

    def test_an_unstamped_artifact_stops_the_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            self.assertIsNone(
                trace._directory_changed_after(
                    self._scratch(root), root, (art(os.path.join(root, "f")),)
                )
            )

    def test_an_empty_group_is_not_dated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            self.assertIsNone(
                trace._directory_changed_after(self._scratch(root), root, ())
            )

    def test_an_unreadable_directory_contributes_no_neighbours(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            gone = os.path.join(root, "gone")
            obs = trace._dir_stamp(self._scratch(root), gone, ())
        self.assertEqual(
            (obs.cap_mtime_ms, obs.cap_ctime_ms, obs.max_ino, obs.neighbours),
            (0, 0, 0, 0),
        )


class FreshnessTest(unittest.TestCase):
    """Freshness is asked of the artifact's own stamp, once."""

    def test_an_artifact_inside_the_window_is_fresh(self):
        stamp = stat_io.Stat(1_000_000, 1_000_000, 1)
        self.assertEqual(
            trace._fresh((art("/r/a", stamp),), 1_000_500, 120), (art("/r/a", stamp),)
        )

    def test_an_artifact_without_a_stamp_proves_nothing_about_its_neighbours(self):
        group = trace.DirObs("/r", "/r", 0, 0, 0, 2, (), None)
        self.assertIs(trace._newer_than_siblings(art("/r/a"), group), False)

    def test_an_unstamped_artifact_is_not_sorted_as_aligned(self):
        group = trace.DirObs("/r", "/r", 0, 0, 0, 2, (art("/r/a"),), None)
        found = trace._hits((group,), 0, 120)
        self.assertEqual(found.aligned, ())
        self.assertEqual(found.uncorroborated, ())


class TruncatedArtifactTest(unittest.TestCase):
    """A file cut off at the read window makes the set itself incomplete."""

    def test_a_long_unit_is_reported_as_cut_off(self):
        obs = trace.Observations(
            root="/r",
            now_ms=0,
            fresh_window_s=120,
            scan=(),
            artifacts=(art("/r/etc/systemd/system/big.service"),),
            dirs=(),
            hits=hits_none(),
            truncated_files=2,
        )
        check = trace._check_artifacts(obs)
        self.assertEqual(check.status, model.PARTIAL)
        self.assertIn("cut off at the read window", check.why)
        self.assertIn("2 file(s)", check.why)


class ObserveDefaultsTest(unittest.TestCase):
    """The default call: now is the clock, and broad claims stay off."""

    def test_a_neighbour_named_by_a_unit_is_not_claimed_without_broad(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            unit = touch(
                os.path.join(root, "etc", "systemd", "system", "z.service"),
                "KillSignal=SIGCONT\nExecStart=/usr/bin/minerd\n",
            )
            neighbour = touch(os.path.join(root, "etc", "cron.d", "minerd"))
            obs = trace.observe(root)
        self.assertEqual([a.path for a in obs.artifacts], [unit])
        self.assertIn(neighbour, obs.weak)
        self.assertEqual(obs.weak[neighbour], "named by a unit, not audited without --broad")

    def test_a_broad_claim_carries_the_rule_that_made_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            touch(
                os.path.join(root, "etc", "systemd", "system", "z.service"),
                "KillSignal=SIGCONT\nExecStart=/usr/bin/minerd\n",
            )
            neighbour = touch(os.path.join(root, "etc", "cron.d", "minerd"))
            obs = trace.observe(root, broad=True)
        self.assertEqual(
            [a.path for a in obs.artifacts if a.marker.startswith("broad:")], [neighbour]
        )


class CollectTest(unittest.TestCase):
    """The opt-in error channel: no list means no bookkeeping, not a crash."""

    def test_no_list_is_not_a_reason_to_fail(self):
        stat_io._collect(None, stat_io.StatError("p", "stat", "boom"))

    def test_a_list_keeps_the_error(self):
        err = stat_io.StatError("p", "stat", "boom")
        errors = []
        stat_io._collect(errors, err)
        self.assertEqual(errors, [err])

    def test_a_missing_error_is_not_a_report(self):
        errors = []
        stat_io._collect(errors, None)
        self.assertEqual(errors, [])


class DirEntriesTest(unittest.TestCase):
    """A name the auditor could see is either a group or an error."""

    def test_a_clean_directory_reports_no_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            touch(os.path.join(tmp, "a"))
            groups, errors = stat_io.dir_entries(tmp)
        self.assertEqual(groups["files"], ["a"])
        self.assertEqual(errors, [])

    def test_an_entry_that_cannot_be_stamped_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            touch(os.path.join(tmp, "a"))
            touch(os.path.join(tmp, "b"))
            err = stat_io.StatError(os.path.join(tmp, "b"), "stat", "boom")
            real = stat_io.stat_of

            def fake(path: str):
                if path.endswith("b"):
                    return None, err
                return real(path)

            with mock.patch.object(stat_io, "stat_of", side_effect=fake):
                groups, errors = stat_io.dir_entries(tmp)
        self.assertEqual(errors, [err])
        self.assertEqual(groups["files"], ["a"])

    def test_a_directory_that_cannot_be_listed_reports_the_failure(self):
        err = stat_io.StatError("/x", "listdir", "boom")
        with mock.patch.object(stat_io, "listdir_sorted", return_value=([], err)):
            groups, errors = stat_io.dir_entries("/x")
        self.assertEqual(errors, [err])
        self.assertEqual(groups, {"files": [], "symlinks": [], "dirs": []})


class IsMemberTest(unittest.TestCase):
    """Membership without a root is a plain file question, and it says so."""

    def test_a_regular_file_is_a_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = touch(os.path.join(tmp, "a"))
            self.assertEqual(stat_io.is_member(path), (True, None))

    def test_a_directory_is_not_a_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(stat_io.is_member(tmp), (False, None))

    def test_a_missing_path_is_not_a_member_and_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(stat_io.is_member(os.path.join(tmp, "nope")), (False, None))

    def test_a_stamp_that_fails_means_no_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = touch(os.path.join(tmp, "a"))
            err = stat_io.StatError(path, "stat", "boom")
            with mock.patch.object(stat_io, "stat_of", return_value=(None, err)):
                self.assertEqual(stat_io.is_member(path), (False, err))

    def test_a_link_that_leaves_the_root_is_a_named_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            link = os.path.join(root, "escape")
            os.symlink("/etc/hostname", link)
            member, err = stat_io.is_member(link, root)
        self.assertFalse(member)
        self.assertIsNotNone(err)
        self.assertEqual(err.op, "resolve")

    def test_a_member_whose_stamp_fails_is_not_a_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            path = touch(os.path.join(root, "a"))
            err = stat_io.StatError(path, "stat", "boom")
            with mock.patch.object(stat_io, "stat_of", return_value=(None, err)):
                self.assertEqual(stat_io.is_member(path, root), (False, err))


class ReadHeadTest(unittest.TestCase):
    """A link that leaves the image cannot pull a host file into evidence."""

    def test_a_link_that_leaves_the_root_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            link = os.path.join(root, "escape")
            os.symlink("/etc/hostname", link)
            text, truncated, err = stat_io.read_head(link, root=root)
        self.assertEqual(text, "")
        self.assertFalse(truncated)
        self.assertEqual(err.op, "resolve")


class WalkFilesTest(unittest.TestCase):
    """A scanned directory that leaves the root is a gap, not an empty answer."""

    def test_a_scan_directory_that_is_a_link_out_of_the_root_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "img")
            os.makedirs(root)
            outside = os.path.join(tmp, "outside")
            os.makedirs(outside)
            os.symlink(outside, os.path.join(root, "etc"))
            paths, errors = stat_io.walk_files(root, "etc")
        self.assertEqual(paths, [])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].op, "resolve")


class DirStatsTest(unittest.TestCase):
    """Siblings that cannot be stamped are neither counted nor fatal."""

    def test_no_error_list_means_no_bookkeeping(self):
        with tempfile.TemporaryDirectory() as tmp:
            touch(os.path.join(tmp, "a"))
            err = stat_io.StatError(os.path.join(tmp, "a"), "stat", "boom")
            with mock.patch.object(stat_io, "stat_of", return_value=(None, err)):
                cap, cap_ctime, max_ino, count = stat_io.dir_stats(tmp)
        self.assertEqual((cap, cap_ctime, max_ino, count), (0, 0, 0, 0))

    def test_an_error_list_keeps_the_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            touch(os.path.join(tmp, "a"))
            err = stat_io.StatError(os.path.join(tmp, "a"), "stat", "boom")
            errors = []
            with mock.patch.object(stat_io, "stat_of", return_value=(None, err)):
                count = stat_io.dir_stats(tmp, errors=errors)[3]
        self.assertEqual(count, 0)
        self.assertEqual(errors, [err])


class CliTest(unittest.TestCase):
    """The parser's own failures, and the two entry points that report them."""

    def test_a_usage_error_prints_the_usage(self):
        with mock.patch("sys.stderr", new_callable=__import__("io").StringIO) as err:
            self.assertEqual(cli.main(["trace"]), 4)
        self.assertIn("usage:", err.getvalue())

    def test_a_marker_is_handed_on_unchanged(self):
        self.assertEqual(cli._marker("KillSignal=SIGCONT"), "KillSignal=SIGCONT")

    def test_broad_is_off_unless_asked_for(self):
        self.assertIs(cli._parser().parse_args(["trace", "/r"]).broad, False)

    def test_dwell_needs_a_ledger(self):
        with mock.patch("sys.stderr", new_callable=__import__("io").StringIO):
            with self.assertRaises(SystemExit):
                cli._parser().parse_args(["dwell"])

    def test_hits_are_not_supplied_by_default(self):
        self.assertIsNone(cli._parser().parse_args(["dwell", "ledger"]).hits)

    def test_an_unreadable_root_is_a_tool_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o000)
            try:
                with mock.patch(
                    "sys.stderr", new_callable=__import__("io").StringIO
                ) as err:
                    self.assertEqual(cli.main(["trace", tmp]), 4)
            finally:
                os.chmod(tmp, 0o755)
        self.assertIn("cannot be read", err.getvalue())

    def test_a_read_error_without_a_reason_still_names_the_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("residue.cli.os.scandir", side_effect=OSError(13, "")):
                with self.assertRaises(cli.ToolError) as caught:
                    cli._require_walkable(tmp)
        self.assertIn("[Errno 13]", str(caught.exception))

    def test_no_subcommand_is_a_tool_failure(self):
        with mock.patch("sys.stderr", new_callable=__import__("io").StringIO) as err:
            self.assertEqual(cli.main([]), 4)
        self.assertIn("a subcommand is required", err.getvalue())

    def test_a_silent_exit_is_success(self):
        self.assertEqual(cli._exit_code(SystemExit(None)), 0)
        self.assertEqual(cli._exit_code(SystemExit(0)), 0)

    def test_a_message_in_a_system_exit_is_a_tool_failure(self):
        with mock.patch("sys.stderr", new_callable=__import__("io").StringIO) as err:
            self.assertEqual(cli._exit_code(SystemExit("boom")), 4)
        self.assertIn("boom", err.getvalue())


class DwellLedgerTest(unittest.TestCase):
    """Reading a ledger: blank lines, unknown kinds, and a mine without a flag."""

    def test_blank_lines_and_comments_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.ndjson")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n# a note\n")
                fh.write(json.dumps({"ts": 1, "host": "h1", "event": "deploy"}) + "\n")
            events = dwell.load_ledger(path)
        self.assertEqual(events, [{"ts": 1, "host": "h1", "event": "deploy"}])

    def test_unknown_kinds_are_counted_per_name(self):
        tally = dwell._tally(
            [
                {"ts": 1, "host": "h1", "event": "bogus"},
                {"ts": 2, "host": "h1", "event": "bogus"},
            ]
        )
        self.assertEqual(tally.unknown, {"bogus": 2})

    def test_a_mine_without_a_result_counts_as_mined(self):
        tally = dwell._tally(
            [
                {"ts": 1, "host": "h1", "event": "deploy"},
                {"ts": 2, "host": "h1", "event": "mine"},
            ]
        )
        self.assertIn("h1", tally.mined)
        self.assertEqual(tally.failed, set())

    def test_a_mine_that_failed_is_not_coverage(self):
        tally = dwell._tally(
            [{"ts": 2, "host": "h1", "event": "mine", "ok": False}]
        )
        self.assertEqual(tally.mined, set())
        self.assertIn("h1", tally.failed)

    def test_the_all_hosts_rate_needs_both_deploys_and_hits(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = os.path.join(tmp, "ledger.ndjson")
            hits = os.path.join(tmp, "hits.json")
            _fixtures.write_ledger(ledger, _fixtures.LEDGER)
            _fixtures.write_hits(hits, _fixtures.HITS)
            reported = dwell.run(ledger, hits).facts
            unmeasured = dwell.run(ledger, None).facts
        self.assertIsNotNone(reported["hit_rate_all_hosts"])
        self.assertIsNone(unmeasured["hit_rate_all_hosts"])


class ReportShapeTest(unittest.TestCase):
    """Rendering: None stays null, and the keys are sorted."""

    def test_a_none_fact_is_null_in_the_json(self):
        built = model.Report("x", [model.Check("x.a", model.PASS, "ok")], {"b": None})
        self.assertIn('"b": null', report.as_json(built))

    def test_the_keys_are_sorted(self):
        built = model.Report("x", [model.Check("x.a", model.PASS, "ok")], {"b": 1, "a": 2})
        text = report.as_json(built)
        self.assertLess(text.index('"a": 2'), text.index('"b": 1'))

    def test_the_report_can_name_its_own_failures(self):
        built = model.Report(
            "x",
            [
                model.Check("x.a", model.FAIL, "bad"),
                model.Check("x.b", model.PASS, "fine"),
            ],
        )
        self.assertEqual(built.failed(), ["x.a"])


class BatchBandTest(unittest.TestCase):
    """The partial band is inclusive at both edges."""

    def test_a_score_exactly_one_step_below_the_threshold_is_partial(self):
        self.assertEqual(batch._verdict(0.96, 0.98)[0], model.PARTIAL)
        self.assertEqual(batch._verdict(0.9599, 0.98)[0], model.PASS)


class InsideTest(unittest.TestCase):
    """Resolution: the root as spelled, the refusals, and an unreadable link."""

    def test_a_root_with_a_trailing_separator_still_holds_its_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = touch(os.path.join(tmp, "f"))
            real, why = inside.resolve(tmp + os.sep, path)
        self.assertEqual(real, os.path.realpath(path))
        self.assertIsNone(why)

    def test_a_root_spelled_through_a_parent_component_still_holds_its_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "sub"))
            path = touch(os.path.join(tmp, "f"))
            real, why = inside.resolve(
                os.path.join(tmp, "sub", ".."), os.path.join(tmp, "sub", "..", "f")
            )
        self.assertEqual(real, os.path.realpath(path))
        self.assertIsNone(why)

    def test_a_path_outside_the_root_is_refused_with_the_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            real, why = inside.resolve(tmp, "/etc/passwd")
        self.assertIsNone(real)
        self.assertIn("is not under", why)

    def test_a_link_that_cannot_be_read_names_the_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = os.path.join(tmp, "link")
            os.symlink("/etc/hostname", link)
            with mock.patch.object(inside.os, "readlink", side_effect=OSError(13, "")):
                real, why = inside.resolve(tmp, link)
        self.assertIsNone(real)
        self.assertEqual(why, "PermissionError")


class FixturesTest(unittest.TestCase):
    """The helpers the demo and the tests share."""

    def test_writing_the_same_directories_twice_is_fine(self):
        with tempfile.TemporaryDirectory() as tmp:
            _fixtures.make_dirs(tmp, ["etc", "usr"])
            _fixtures.make_dirs(tmp, ["etc", "usr"])
            self.assertTrue(os.path.isdir(os.path.join(tmp, "etc")))

    def test_neighbours_are_returned_and_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            _fixtures.make_dirs(tmp, ["etc"])
            made = _fixtures.write_neighbours(tmp, ["etc"])
            self.assertTrue(made)
            for path in made:
                self.assertTrue(os.path.exists(path))

    def test_borrowing_without_extra_artifacts_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            _fixtures.make_dirs(tmp, ["etc"])
            _fixtures.write_neighbours(tmp, ["etc"])
            path = touch(os.path.join(tmp, "etc", "artifact"))
            _fixtures.borrow_sibling_mtimes([path])
            self.assertTrue(os.path.exists(path))



class TheCommandLineSaysItOnce(unittest.TestCase):
    """A missing subcommand is one message, not that message plus a second failure."""

    def test_no_subcommand_reports_once(self):
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            rc = cli.main([])
        self.assertEqual(rc, 4)
        self.assertEqual(err.getvalue().count("residue: error:"), 1)


class RelativeNamesResolveLikeAbsoluteOnes(unittest.TestCase):
    """inside.resolve accepts what a shell accepts: "." and a bare relative path."""

    def test_a_relative_root_is_absolute_before_the_walk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = touch(os.path.join(tmp, "etc", "x"))
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                real, why = inside.resolve(".", "etc/x")
            finally:
                os.chdir(cwd)
        self.assertIsNone(why)
        self.assertEqual(os.path.realpath(real), os.path.realpath(path))

    def test_a_relative_path_is_absolute_before_the_walk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = touch(os.path.join(tmp, "etc", "x"))
            cwd = os.getcwd()
            here = os.path.realpath(tmp)
            os.chdir(here)
            try:
                real, why = inside.resolve(here, "etc/x")
            finally:
                os.chdir(cwd)
        self.assertIsNone(why)
        self.assertEqual(os.path.realpath(real), os.path.realpath(path))


class ADirectorySiblingThatFailsOnTheSecondRead(unittest.TestCase):
    """dir_stats names a file it cannot stamp, and does not count it."""

    def test_a_second_read_failure_is_recorded_and_not_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            touch(os.path.join(tmp, "a"))
            real = stat_io.stat_of
            seen = {"n": 0}

            def fake(path):
                if os.path.basename(path) == "a":
                    seen["n"] += 1
                    if seen["n"] >= 2:
                        return None, stat_io.StatError(path, "stat", "gone")
                return real(path)

            errors = []
            with mock.patch.object(stat_io, "stat_of", side_effect=fake):
                cap, cap_ctime, max_ino, count = stat_io.dir_stats(tmp, errors=errors)
        self.assertEqual(count, 0)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].op, "stat")


class ALinkWeCannotReadIsNotCalledAbsolute(unittest.TestCase):
    """readlink failing means no answer, and the caller must not read that as absolute."""

    def test_an_unreadable_link_is_not_absolute(self):
        if os.geteuid() == 0:
            self.skipTest("root can readlink anything")
        with tempfile.TemporaryDirectory() as tmp:
            holder = os.path.join(tmp, "locked")
            os.makedirs(holder)
            link = os.path.join(holder, "link")
            os.symlink("/etc/hostname", link)
            os.chmod(holder, 0)
            try:
                self.assertFalse(trace._absolute_link(link))
            finally:
                os.chmod(holder, 0o755)


class AnOmittedClockIsNow(unittest.TestCase):
    """observe() without now_ms reads the wall clock, so a unit written now is fresh."""

    def test_a_unit_written_now_is_fresh_when_the_clock_is_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan = os.path.join(tmp, "etc", "systemd", "system")
            os.makedirs(scan)
            touch(os.path.join(scan, "zz-unit.service"), "[Service]\nKillSignal=SIGCONT\n")
            obs = trace.observe(tmp)
        self.assertEqual(trace.facts(obs)["fresh"], 1)


class TheSecondEntryPointPrintsToStdout(unittest.TestCase):
    """demo.run() with no stream prints to stdout and still returns the report."""

    def test_run_without_a_stream_writes_to_stdout(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out):
            report = demo.run()
        self.assertEqual(report.exit_code(), 2)
        self.assertIn("summary command=batch", out.getvalue())


class ARowWithoutAKindIsNamed(unittest.TestCase):
    """A ledger row with no event or phase is reported as missing, not read as scan."""

    def test_a_row_without_a_kind_is_counted_as_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"ts": 100, "host": "h1"}\n')
            report = dwell.run(path)
        self.assertEqual(report.facts["unknown_events"], ["<missing>"])



class AReasonForAGapIsTheOneWeWereGiven(unittest.TestCase):
    """A resolve failure keeps the reason it was given, and falls back only when empty."""

    def test_is_member_keeps_the_reason_it_was_given(self):
        with mock.patch.object(inside, "resolve", return_value=(None, "boom")):
            member, err = stat_io.is_member("/r/etc/x", root="/r")
        self.assertFalse(member)
        self.assertEqual(err.err, "boom")

    def test_read_head_keeps_the_reason_it_was_given(self):
        with mock.patch.object(inside, "resolve", return_value=(None, "boom")):
            text, truncated, err = stat_io.read_head("/r/etc/x", root="/r")
        self.assertEqual((text, truncated), ("", False))
        self.assertEqual(err.err, "boom")

    def test_walk_files_keeps_the_reason_it_was_given(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "etc"))
            with mock.patch.object(inside, "resolve", return_value=(None, "boom")):
                paths, errors = stat_io.walk_files(tmp, "etc")
        self.assertEqual(paths, [])
        self.assertEqual(errors[0].err, "boom")

    def test_an_empty_reason_falls_back_to_the_link_name(self):
        with mock.patch.object(inside, "resolve", return_value=(None, "")):
            member, err = stat_io.is_member("/r/etc/x", root="/r")
        self.assertEqual(err.err, "unresolvable link")

    def test_an_empty_reason_falls_back_to_the_directory_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "etc"))
            with mock.patch.object(inside, "resolve", return_value=(None, "")):
                paths, errors = stat_io.walk_files(tmp, "etc")
        self.assertEqual(errors[0].err, "unresolvable directory")


class AnOmittedClockIsNowAtTheOtherEnd(unittest.TestCase):
    """The wall clock is read once, so an old artifact is not called fresh."""

    def test_a_unit_written_long_ago_is_not_fresh_when_the_clock_is_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan = os.path.join(tmp, "etc", "systemd", "system")
            os.makedirs(scan)
            path = touch(os.path.join(scan, "zz-unit.service"), "[Service]\nKillSignal=SIGCONT\n")
            os.utime(path, (1600000000, 1600000000))
            obs = trace.observe(tmp)
        self.assertEqual(trace.facts(obs)["fresh"], 0)


if __name__ == "__main__":
    unittest.main()
