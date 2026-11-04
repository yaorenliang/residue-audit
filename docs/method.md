# Method

Fourteen checks across three commands, one stance: **recompute, never self-report.**

A measurement is worth something only if someone else can reproduce it without
trusting the program that produced it. Everything below is written so that a second
implementation can arrive at the same number and disagree if it does not agree. That
second implementation can be a shell script, a different language, or a person with
`stat(1)`.

## trace: did the artifacts blend into their neighbours?

An implant that drops files leaves two kinds of residue: the files themselves, and
the shape of their metadata relative to everything around them. `trace` reads a
root directory (a mounted image, a live host, a fixture tree) and answers three
separable questions, then reports how deep the floors go.

**1. Alignment.** For every artifact, compare its mtime against the newest sibling
in the same directory that is not ours. If the artifact is newer than every
sibling, it stands out, because the first thing anyone does on a suspicious host is
`ls -lt`. Alignment borrows a timestamp from the neighbourhood, so the
neighbourhood has to exist.

**2. Corroboration.** This is why alignment and corroboration are separate checks.
In a directory with no non-artifact sibling there is nothing to borrow from, and
"aligned" would be an assumption with a verdict's name on it. The tool reports
`partial` instead of `pass`. The case is not hypothetical: it is what happens in
an empty `/etc/cron.d` on a minimal image.

**3. Freshness.** Alignment can be correct and still be a lie. If the whole tree was
written ninety seconds ago, an artifact that is "no newer than its siblings" is
still obviously part of the same burst. Freshness compares against the wall clock,
not against the directory.

**4. Creation order** is reported but rarely passes. Most
filesystems allocate inode numbers monotonically, so the file written last has the
highest inode, and no user-space call changes that. It is a floor on how deeply a
delivery can hide, and the tool prints the floor instead of hiding it.

**5. The holding directory.** Writing a file updates its parent's mtime and ctime,
and neither can be set back from user space. Comparing the directory's ctime with
the oldest artifact mtime inside it dates the *assembly*: the directory changed
after the files it holds were dated. This is reported as `partial` and not `fail`,
because the same signal comes from a package upgrade touching the directory, and a
check that cannot distinguish those two is a lead, not a finding.

**6. Readability.** Every scanned path is either read or named. A directory that
cannot be listed lands in `facts.errors`, the artifacts behind it are not counted,
and `trace.readable` drops to `partial`. Without this the tool's failure mode was
the worst available one: an unreadable directory looked exactly like an empty one,
so `chmod 000` turned a blind spot into a clean result.

### Identification versus measurement

Which files count as "ours" is a judgement call, and it is the one place where the
tool trusts a heuristic. The rule set is deliberately narrow, and it is anchored on
evidence of the pattern rather than on adjacency:

1. a unit whose body carries an artifact marker (`KillSignal=SIGCONT`,
   `SendSIGKILL=no`) is ours;
2. a file that such a unit starts (`ExecStart=`) is ours;
3. a file whose body names one of those paths is ours. This is what catches cron
   entries, which carry no marker of their own but always name the binary they run.

The narrowness is measured, not assumed. The first version of the rule was broader:
*any* file named by *any* unit's `ExecStart=` counted as ours. On a stock Ubuntu
24.04 root that rule claimed 13 files, of which 5 were ours, for **38% precision**.
`packagekitd`, `boltd`, `qmi-proxy`, `packagekit-direct`,
`pk-debconf-helper`, `pk-offline-update`, `mbim-proxy` and
`/etc/cron.d/e2scrub_all` are all legitimately started by legitimately installed
units. On a live host that is not a small error. It turns system binaries into
findings.

Anchoring on the marker instead gives 5 claims and 0 false positives on the same
root, at a cost: 8 files that the broad rule would have claimed are now reported as
**weak claims** and are not audited at all. That trade is stated in the output
(`(+8 weak claim(s) not audited)`) rather than hidden. `--broad` restores the
old rule for cases where a responder would rather over-claim than miss.

Everything *measured* after identification (mtimes, inode ordering, sibling caps,
ctime) is metadata, and metadata can be recomputed by anyone with `stat`. That is
the part that has to survive distrust. The identification is the part that has to be
labelled.

## dwell: how long did it live, and how much of that was covered?

Two numbers get conflated constantly in incident reports: how long the implant was
present, and how much of that presence the detection stack actually saw.

The ledger is newline-delimited JSON: `{"ts": 1180, "host": "h1", "event": "mine"}`.
From it, `dwell` computes a per-host span, an aggregate distribution, and a
coverage rate.

The coverage rate has two rules that exist because the naive version is wrong:

* The denominator is the hosts that reached `deploy`, not every host observed. A
  host that was only scanned had nothing to detect, and counting it lets an
  operator flatter the rate by scanning more than it infected.
* Hits before deploy and hits after deploy are counted separately. A rule that fires
  before the implant exists is a false positive, and folding it into the same rate
  makes the stack look better than it is.

Three more rules, each of which exists because the honest number is the
unflattering one:

* **Two denominators, both printed.** `hit_rate` uses the deployed hosts;
  `hit_rate_all_hosts` uses every host in the ledger. Reporting only the first lets
  a reader mistake "half the deployed hosts" for "half the fleet"; reporting only the
  second mixes hosts that had nothing to detect into the denominator.
* **An unknown event kind is named, not absorbed.** Anything outside
  `{deploy, mine, scan}` goes into `unknown_events` and raises a `dwell.schema`
  partial. Folding it into `scan` would silently shrink the denominator, and every
  rate over a shrinking denominator goes up.
* **A hit on an undeployed host is listed.** It lands in `hits_unmatched` instead of
  being dropped while its rule keeps printing a count in the evidence block.

And one rule about language: exactly half is not a majority. `rate > 50.0` passes;
50.0 is `partial-coverage`. If no hits were supplied at all, coverage is `skip`
with the reason `unknown, not zero`, because zero is a measurement and not looking
is not.

The distribution is a distribution: the median is the true median (the mean of the
two middle spans for an even count, not the upper one), and p90 uses nearest-rank.
A span starts at the earliest `deploy` for that host, not at the first line in the
file, so re-sorting a ledger cannot change the answer.

## batch: can one signature cluster two builds?

Two builds of the same family should not be mutually recognisable. `batch` takes
feature sets (strings, symbols, whatever the caller extracted) and scores every pair
with Jaccard similarity against a threshold.

The interesting case is not "different". It is "almost the same": a pair at 0.99
looks distinct to a human comparing two file lists and identical to a clusterer. The
band between `threshold - 0.02` and `threshold` is reported as `partial` on
purpose. Near the line, one more build decides the verdict, and a pass there is a
coin flip reported as a fact.

Two empty feature sets are `skip`, not `fail`. Jaccard similarity is undefined
when the denominator is zero, and two sets that share nothing because neither build
extracted anything is not evidence of difference. The pair is reported with
`min_similarity=None` so it cannot quietly enter a minimum computed from other
pairs.

## The exit code is part of the contract

| code | meaning |
|---|---|
| 0 | `pass` |
| 1 | `partial`: something is unmeasurable |
| 2 | `fail`: a check found residue |
| 3 | `skip`: nothing matched, the audit did not happen |
| 4 | tool failure: bad usage, unreadable input, or a crash |

Verdicts and failures share one enum and never share a value. Before that split,
argparse exited 2 on a mistyped flag and Python exits 1 on an uncaught exception, so
a gate written as `exit == 2` fired on a typo and `exit == 1` read a crash as
"unmeasurable". A gate that cannot tell "found something" from "ran wrong" is not a
gate.

## The four layers of verification, and a floor

There is a fifth gate underneath the four: `make cov` fails under two floors, so a
suite that stops exercising a module is red instead of quiet. The total may not fall
below `COVERAGE_FLOOR`, and no module may fall more than `MODULE_FLOOR` points below
the value recorded in `tests/coverage_baseline.json`. The second half exists because
the total hides a deletion: dropping `tests/test_dwell.py` left the total at 88.2%
while `dwell.py` fell from 96.5% to 83.0%. Coverage is measured with the stdlib
tracer, and the entry point is measured in a child process, because a tracer cannot
follow a subprocess: `residue/__main__.py` used to print 0/4 for a module the entry
tests prove is executed.

```
L0  contract      fixture -> golden JSON, compared field by field
L1  negative      every check gets an input on which it must not pass
L2  real ext4     the same fixtures on a QEMU guest with no egress (manual)
L3  cross-check   a second implementation recomputes the number with stat(1)
```

L0 and L1 run in CI on Linux and macOS. L2 needs qemu and is run by hand. L3 is
`tests/cross_check.sh`: residue identifies the artifacts, the shell measures
them, and the two counts have to agree.

Without L1, "it passed" means "it was not tested". Without L3, "recomputed" means
"the same program said the same thing twice".
