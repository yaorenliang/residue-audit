"""The judges, tested without a filesystem.

Every observation here is built by hand, because the point of splitting the pass
from the verdict is that a verdict can be asked its opinion about a tree that
never existed. These tests fail if a judge starts reading the disk again, and
they pin the two answers that used to be decided by which branch happened to run
first: a directory can only ever be partial, and two empty feature sets have no
similarity to report.
"""

import inspect
import unittest
from unittest import mock

from residue import model, stat_io, trace

ROOT = "/r"
NOW = 10_000_000


def stamp(mtime_ms, ctime_ms=None, ino=1):
    return stat_io.Stat(mtime_ms, mtime_ms if ctime_ms is None else ctime_ms, ino)


def art(path, mtime_ms=1000, ctime_ms=None, ino=1, marker="unit:marker"):
    return trace.ArtifactObs(
        path, trace.sanitize(path, ROOT), marker, stamp(mtime_ms, ctime_ms, ino)
    )


def held(directory, arts, cap=1000, cap_ctime=1000, max_ino=99, neighbours=1, changed=None):
    return trace.DirObs(
        directory,
        trace.sanitize(directory, ROOT),
        cap,
        cap_ctime,
        max_ino,
        neighbours,
        tuple(arts),
        changed,
    )


def seen(dirs, errors=(), weak=(), truncated=0, window=120):
    dirs = tuple(dirs)
    return trace.Observations(
        ROOT,
        NOW,
        window,
        ("etc",),
        tuple(one for group in dirs for one in group.artifacts),
        dirs,
        trace._hits(dirs, NOW, window),
        {path: "not audited" for path in weak},
        tuple(errors),
        truncated,
    )


def status_of(observations, name):
    for check in trace.checks(observations):
        if check.name == name:
            return check
    raise AssertionError("no check named %r" % (name,))


class JudgeTest(unittest.TestCase):
    def test_nothing_claimed_is_a_skip_not_a_clean_host(self):
        check = status_of(seen([]), "trace.artifacts")
        self.assertEqual(check.status, model.SKIP)
        self.assertIn("nothing to audit", check.why)

    def test_a_pass_says_how_many_claims_it_did_not_audit(self):
        obs = seen([held("/r/usr/libexec", [art("/r/usr/libexec/kworker")])],
                   weak=["/r/usr/libexec/a", "/r/usr/libexec/b"])
        check = status_of(obs, "trace.artifacts")
        self.assertEqual(check.status, model.PASS)
        self.assertTrue(check.why.endswith("(+2 weak claim(s) not audited)"))

    def test_alignment_is_a_skip_when_no_artifact_has_a_sibling(self):
        obs = seen([held("/r/usr/libexec", [art("/r/usr/libexec/kworker")], neighbours=0)])
        self.assertEqual(status_of(obs, "trace.aligned").status, model.SKIP)

    def test_alignment_fails_when_every_artifact_outruns_the_cap(self):
        obs = seen([held("/r/etc", [art("/r/etc/a", 2000), art("/r/etc/b", 2000)], cap=1000)])
        check = status_of(obs, "trace.aligned")
        self.assertEqual(check.status, model.FAIL)
        self.assertIn("all 2 artifact(s)", check.why)

    def test_alignment_is_partial_when_only_some_artifacts_leak(self):
        obs = seen([
            held("/r/etc", [art("/r/etc/loud", 2000), art("/r/etc/quiet", 500)], cap=1000)
        ])
        check = status_of(obs, "trace.aligned")
        self.assertEqual(check.status, model.PARTIAL)
        self.assertIn("1 of 2 artifact(s)", check.why)

    def test_alignment_evidence_names_the_cap_after_the_artifact(self):
        obs = seen([held("/r/etc", [art("/r/etc/loud", 2000)], cap=1000)])
        evidence = status_of(obs, "trace.aligned").evidence
        self.assertEqual([one.field for one in evidence], ["mtime_ms", "neighbour_cap_ms"])
        self.assertEqual(evidence[1].value, "1000")

    def test_an_artifact_with_no_sibling_is_named_not_counted_as_aligned(self):
        obs = seen([held("/r/usr/libexec", [art("/r/usr/libexec/kworker")], neighbours=0)])
        check = status_of(obs, "trace.corroborated")
        self.assertEqual(check.status, model.PARTIAL)
        self.assertEqual([(one.field, one.value) for one in check.evidence],
                         [("corroborator", "none")])
        self.assertEqual(obs.hits.aligned, ())

    def test_a_ctime_above_every_sibling_is_a_failure(self):
        obs = seen([held("/r/etc", [art("/r/etc/a", 1000, ctime_ms=2000)], cap_ctime=1500)])
        self.assertEqual(status_of(obs, "trace.ctime").status, model.FAIL)

    def test_a_changed_directory_is_never_more_than_partial(self):
        for count in (1, 5):
            dirs = [
                held("/r/d%d" % index, [art("/r/d%d/a" % index)], changed=(2000, 1000))
                for index in range(count)
            ]
            check = status_of(seen(dirs), "trace.directory_ctime")
            self.assertEqual(check.status, model.PARTIAL)
            self.assertIn("%d holding director(y/ies)" % count, check.why)

    def test_freshness_counts_the_window_edge_as_fresh(self):
        edge = NOW - 120 * 1000
        obs = seen([
            held("/r/etc", [art("/r/etc/edge", edge), art("/r/etc/old", edge - 1000)])
        ])
        self.assertEqual([one.value for one in status_of(obs, "trace.fresh").evidence],
                         ["120"])
        self.assertEqual(len(obs.hits.fresh), 1)

    def test_an_inode_above_every_sibling_is_a_failure(self):
        obs = seen([held("/r/etc", [art("/r/etc/a", ino=5000)], max_ino=99)])
        self.assertEqual(status_of(obs, "trace.order").status, model.FAIL)

    def test_an_unreadable_path_is_partial_and_named(self):
        err = stat_io.StatError("/r/etc/locked", "stat", "Permission denied")
        obs = seen([held("/r/etc", [art("/r/etc/a")])], errors=[err])
        check = status_of(obs, "trace.readable")
        self.assertEqual(check.status, model.PARTIAL)
        self.assertEqual([(one.path, one.value) for one in check.evidence],
                         [("/r/etc/locked", "stat: Permission denied")])

    def test_the_judges_never_touch_the_filesystem(self):
        obs = seen([held("/nowhere/at/all", [art("/nowhere/at/all/kworker", 2000)])])
        with mock.patch.object(trace.stat_io, "stat_of", side_effect=AssertionError("read")):
            checks = trace.checks(obs)
        self.assertEqual(len(checks), len(trace.JUDGES))

    def test_facts_are_derived_from_the_hits(self):
        obs = seen([
            held("/r/etc", [art("/r/etc/loud", 2000), art("/r/etc/quiet", 500)], cap=1000),
            held("/r/solo", [art("/r/solo/a")], neighbours=0),
        ])
        facts = trace.facts(obs)
        self.assertEqual((facts["aligned"], facts["leaks"], facts["uncorroborated"]),
                         (1, 1, 1))
        self.assertEqual(facts["artifacts"], 3)

    def test_the_ladder_is_a_table_and_not_four_branches(self):
        self.assertEqual(
            trace.HIT_VERDICT,
            {
                "ctime": model.FAIL,
                "directory_ctime": model.PARTIAL,
                "fresh": model.FAIL,
                "order": model.FAIL,
            },
        )

    def test_no_hit_check_states_its_own_verdict(self):
        for name in trace.HIT_VERDICT:
            source = inspect.getsource(getattr(trace, "_check_" + name))
            self.assertNotIn("FAIL", source, name)
            self.assertNotIn("PARTIAL", source, name)
            self.assertIn("_spike_check", source, name)

    def test_a_hit_takes_its_verdict_from_the_table(self):
        obs = seen([
            held(
                "/r/etc",
                [art("/r/etc/a", NOW - 1000, ino=5)],
                cap=1,
                cap_ctime=1,
                max_ino=1,
                changed=(5000, 1000),
            )
        ])
        for name, verdict in trace.HIT_VERDICT.items():
            self.assertEqual(status_of(obs, "trace." + name).status, verdict, name)


if __name__ == "__main__":
    unittest.main()