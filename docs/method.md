# Method

Three checks, one stance: **recompute, never self-report.**

A measurement is only worth something if someone else can reproduce it without
trusting the program that produced it. Everything below is written so a second
implementation — a shell script, a different language, a person with `stat(1)`
— can arrive at the same number and disagree if they do not agree.

## trace — did the artifacts blend into their neighbours?

An implant that drops files leaves two kinds of residue: the files themselves,
and the shape of their metadata relative to everything around them. `trace`
reads a root directory (a mounted image, a live host, a fixture tree) and answers
three separable questions.

**1. Alignment.** For every artifact, compare its mtime against the newest
*sibling that is not ours* in the same directory. If the artifact is newer than
every sibling, it stands out: the first thing anyone does on a suspicious host is
`ls -lt`. Alignment borrows a timestamp from the neighbourhood, so the
neighbourhood must exist.

**2. Corroboration.** Which is why alignment and corroboration are different
checks. In a directory with no non-artifact sibling there is nothing to borrow
from, and "aligned" would be an assumption wearing a verdict's clothes. The tool
reports `partial` instead of `pass`. This case is not hypothetical: it is
exactly what happens in an empty `/etc/cron.d` on a minimal image.

**3. Freshness.** Alignment can be correct and still be a lie: if the whole tree
was written ninety seconds ago, an artifact that is "no newer than its siblings"
is still obviously part of the same burst. Freshness compares against the wall
clock, not the directory.

A fourth question — creation **order** — is reported but rarely passes. Inode
numbers are allocated monotonically by most filesystems, so the file written last
has the highest inode, and no user-space call can change that. This is a floor on
how deeply a delivery can hide, and the tool says so instead of hiding the floor.

### Identification versus measurement

Which files count as "ours" is a judgement call, and it is the one place where the
tool trusts a heuristic. The rule set is deliberately narrow, and it is anchored on
evidence of the *pattern* rather than on adjacency:

1. a unit whose body carries an artifact marker (`KillSignal=SIGCONT`,
   `SendSIGKILL=no`) is ours;
2. a file that such a unit starts (`ExecStart=`) is ours;
3. a file whose body names one of those paths is ours — this is what catches cron
   entries, which carry no marker of their own but always name the binary they run.

The narrowness is measured, not assumed. The first version of the rule was broader:
*any* file named by *any* unit's `ExecStart=` counted as ours. On a stock Ubuntu
24.04 root that rule claimed 13 files, of which 5 were ours — **38% precision**,
because `packagekitd`, `boltd`, `qmi-proxy`, `packagekit-direct`,
`pk-debconf-helper`, `pk-offline-update`, `mbim-proxy` and
`/etc/cron.d/e2scrub_all` are all legitimately started by legitimately installed
units. On a live host that is not a small error: it turns system binaries into
findings.

Anchoring on the marker instead gives 5 claims and 0 false positives on the same
root, at a cost: 8 files that the broad rule would have claimed are now reported as
**weak claims** and are not audited at all. That trade is stated in the output
(`(+​8 weak claim(s) not audited)`) rather than hidden. `--broad` restores the old
rule for the cases where a responder would rather over-claim than miss.

Everything *measured* after identification — mtimes, inode ordering, sibling caps,
ctime — is metadata, and metadata can be recomputed by anyone with `stat`. That is
the part that has to survive distrust; the identification is the part that has to be
labelled.

## dwell — how long did it live, and how much of that was covered?

Two numbers get conflated constantly in incident reports: how long the implant was
present, and how much of that presence the detection stack actually saw.

The ledger is newline-delimited JSON: `{"ts": 1180, "host": "h1", "event": "mine"}`.
From it, `dwell` computes a per-host span, an aggregate distribution, and a
coverage rate.

The coverage rate has two rules that exist because the naive version is wrong:

* The denominator is the hosts that reached `deploy`, not every host observed.
  A host that was only scanned had nothing to detect; counting it would let an
  operator flatter the rate by scanning more than it infected.
* Hits before deploy and hits after deploy are counted separately. A rule that
  fires before the implant exists is a false positive, and folding it into the
  same rate makes the stack look better than it is.

And one rule about language: exactly half is not a majority. `rate > 50.0`
passes; 50.0 is `partial-coverage`. If no hits were supplied at all, coverage is
`skip` with the reason `unknown, not zero` — because zero is a measurement and
"we did not look" is not.

## batch — can one signature cluster two builds?

Two builds of the same family should not be mutually recognisable. `batch` takes
feature sets (strings, symbols — whatever the caller extracted) and scores every
pair with Jaccard similarity against a threshold.

The interesting case is not "different". It is "almost the same": a pair at 0.99
looks distinct to a human comparing two file lists and identical to a clusterer.
The band between `threshold - 0.02` and `threshold` is reported as `partial`
on purpose — near the line, one more build decides the verdict, and a pass there
is a coin flip reported as a fact.

## The four layers of verification

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