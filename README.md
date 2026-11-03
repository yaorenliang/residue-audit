# residue-audit

**Measure what a hidden implant left behind, from a third party's position.**

Incident reports often end with the same sentence: no evidence of persistence.
That sentence has two meanings and most tooling does not separate them.
One is that the implant was never there. The other is that it was there,
and the way we looked could not have seen it. This project measures the distance.

```
$ residue demo    # section 1 of 6
### borrowed. artifacts written last, mtimes borrowed from a neighbour
trace.artifacts        pass     5 artifact(s) matched the marker set
                                  <root>/etc/cron.d/kworkers-updater marker=content:kworker
                                  <root>/etc/systemd/system/zz-bridge.service marker=unit:marker
                                  <root>/etc/systemd/system/zz-harvest.service marker=unit:marker
                                  <root>/usr/libexec/kworker marker=marker:KillSignal=SIGCONT
                                  <root>/usr/local/bin/bridge-client-x marker=unit:execstart
trace.aligned          pass     all 5 artifact(s) are no newer than a sibling
                                  <root>/etc/cron.d neighbour_cap_ms=1609459200000
                                  <root>/etc/systemd/system neighbour_cap_ms=1609459200000
                                  <root>/usr/libexec neighbour_cap_ms=1609459200000
                                  <root>/usr/local/bin neighbour_cap_ms=1609459200000
trace.corroborated     pass     every directory holding an artifact also holds a non-artifact sibling
trace.ctime            fail     5 artifact(s) have a ctime newer than every sibling: mtime can be borrowed, ctime cannot
                                  <root>/etc/cron.d/kworkers-updater ctime_vs_cap=newer
                                  <root>/etc/systemd/system/zz-bridge.service ctime_vs_cap=newer
                                  <root>/etc/systemd/system/zz-harvest.service ctime_vs_cap=newer
                                  <root>/usr/libexec/kworker ctime_vs_cap=newer
                                  <root>/usr/local/bin/bridge-client-x ctime_vs_cap=newer
trace.directory_ctime  partial  4 holding director(y/ies) changed after the artifacts they hold: a directory mtime/ctime is the usual hiding place, and it dates the assembly, not the intent
                                  <root>/etc/cron.d dir_ctime_vs_oldest_mtime=1793628189582 > 1609459200000
                                  <root>/etc/systemd/system dir_ctime_vs_oldest_mtime=1793628189582 > 1609459200000
                                  <root>/usr/libexec dir_ctime_vs_oldest_mtime=1793628189582 > 1609459200000
                                  <root>/usr/local/bin dir_ctime_vs_oldest_mtime=1793628189582 > 1609459200000
trace.fresh            pass     no artifact carries an mtime within 120s of now
trace.order            fail     5 artifact(s) have a higher inode than every sibling, so creation order is recoverable
                                  <root>/etc/cron.d/kworkers-updater inode_order=newest
                                  <root>/etc/systemd/system/zz-bridge.service inode_order=newest
                                  <root>/etc/systemd/system/zz-harvest.service inode_order=newest
                                  <root>/usr/libexec/kworker inode_order=newest
                                  <root>/usr/local/bin/bridge-client-x inode_order=newest
trace.readable         pass     every scanned path was read; no verdict rests on a skipped path

aligned=5
artifacts=5
ctime=5
errors=[]
fresh=0
leaks=0
order=5
root=/var/folders/x9/ftfjbsxx70s1_15hm5lfmvjm0000gn/T/residue-demo-x1hisjkl/leak
scan=["etc/systemd/system", "etc/cron.d", "usr/libexec", "usr/local/bin"]
truncated_files=0
uncorroborated=0
weak_claims=0

summary command=trace status=fail exit=2
note: order and ctime still fail here. utimensat rewrites a timestamp;
      nothing user-space can rewrite the inode number or the ctime.
```

`make docs-sample` prints the six demo sections this README quotes (the block above
is section 1) plus the `--json` shape, so the text can be diffed instead of trusted. `<root>` is the
throwaway tree the demo builds under `$TMPDIR`; the absolute timestamps in
`directory_ctime` come from that run's clock.

That implant did everything a careful operator does. It borrowed timestamps from
its neighbours, it landed in directories that already had company, and it stayed
out of the last two minutes of history. It is still visible in three places: a
timestamp can be rewritten and a creation order cannot; changing an mtime moves a
ctime that nobody can put back; and the directory holding the file was touched
after the file was dated.

### What the exit code means

| code | meaning | what a gate should do |
|---|---|---|
| 0 | `pass` | the checks that ran found nothing |
| 1 | `partial` | something is unmeasurable, not clean |
| 2 | `fail` | at least one check found residue |
| 3 | `skip` | nothing matched; the audit did not happen |
| 4 | tool failure | bad usage, unreadable input, or a crash - never a verdict |

4 exists because 1 and 2 are verdicts. Before the code space was split, a mistyped
flag (argparse's 2) and an uncaught exception (Python's 1) read as "found residue"
and "unmeasurable", so a gate written as `if exit == 2` fired on a typo.

So the question is not "can we detect it". The question is where the hiding stops
working, and how somebody else checks that claim without trusting this code.

## Thirty seconds

```bash
git clone https://github.com/yaorenliang/residue-audit
cd residue-audit
make demo
```

Zero dependencies, Python 3.9+. No network, no root, no writes outside the paths
you point it at. The demo builds throwaway trees and prints six sections: the
borrowed-mtime tree above, the best a synthetic tree can reach (alignment, ctime
and order pass; the holding directory still dates the assembly), a coverage run
that passes, a ledger where exactly half the hosts were covered, two builds that
cluster, and two that do not. It shows all three verdicts and **exits on them**, so
a demo that rots into "everything fails" is a red build instead of a screenshot.

## What it says on a real host

The lab boots a stock Ubuntu 24.04 root with no egress and audits it twice.

**Identification.** The first rule set claimed any binary named by any unit. On that
root it claimed 13 files, 5 of them ours: 38% precision. The other eight were
`packagekitd`, `boltd`, `qmi-proxy`, `packagekit-direct`,
`pk-debconf-helper`, `pk-offline-update`, `mbim-proxy` and
`/etc/cron.d/e2scrub_all`, each started by a legitimately installed unit. Anchoring
the rule on a marker-bearing unit and following `ExecStart=` outward gives 5 claims,
0 false positives, and 8 files reported as weak claims and left unaudited.
`--broad` restores the old rule if you would rather over-claim than miss.

**The floor.** The scoped run aligns 5 of 5 artifacts and leaks none. It still fails,
on `ctime` and `order`, and reports `partial` on `directory_ctime`. That is not a
fixture bug. It is the answer to "how deep can this go", and it comes with numbers.

13 = 5 claimed + 8 weak, so 5/13 = 38% precision for the broad rule. The lab prints
`LAB_ROOT_OURS=5` and `LAB_ROOT_WEAK=8` in `out/lab-console.log`; the arithmetic is
one line because a reader should never have to take a percentage on faith.

## Three questions

### 1. Did the artifacts blend in? `residue trace`

Writing files leaves two kinds of residue: the files, and the shape of their metadata
relative to everything around them. `trace` reads a root (a mounted image, a live
host, a fixture tree) and separates three questions that are usually collapsed into
one.

* **alignment**: is the artifact's mtime no newer than the newest non-artifact
  sibling? The first command anyone runs on a suspicious host is `ls -lt`, and
  alignment is the answer to that command.
* **corroboration**: does such a sibling exist at all? In an empty `/etc/cron.d`
  there is nothing to borrow from, so "aligned" would be an assumption wearing a
  verdict's clothes. The tool returns `partial`, not `pass`.
* **freshness**: is the whole tree new enough that alignment means nothing? An
  artifact written ninety seconds ago belongs to the same burst no matter how well
  its mtime matches.

Two more checks are floors rather than findings. **ctime**: rewriting an mtime moves
the status-change time, which user space cannot set back. **Creation order**: inode
numbers are allocated monotonically and no syscall renumbers a file. Both fail on a
successfully hidden implant, and the tool draws that boundary instead of hiding it.

### 2. How long did it live, and how much was covered? `residue dwell`

Input is an ndjson ledger (`{"ts": 1180, "host": "h1", "event": "mine"}`) and an
optional hit list. Output is per-host spans, a distribution, and a coverage rate with
three rules that exist because the naive rate is wrong.

* The denominator is hosts that reached `deploy`. A host that was only scanned had
  nothing to detect; counting it lets an operator raise the rate by scanning more
  than it infected.
* Hits before deploy and after deploy are counted separately. A rule that fires
  before the implant exists is a false positive, and folding it in makes the stack
  look better than it is.
* Exactly half is not a majority. `> 50.0` passes, `50.0` is
  `partial-coverage`, and no hits supplied is `unknown, not zero`. Zero is a
  measurement; not looking is not.
* The other denominator is still reported. `hit_rate_all_hosts` answers "of every
  host we observed", so a reader can see how far the two rates diverge instead of
  being handed the flattering one.
* An event kind outside `{deploy, mine, scan}` is named, not absorbed. An upstream
  vocabulary change would otherwise shrink the denominator quietly, and every rate
  computed from a shrinking denominator goes up: `unknown_events` plus a
  `dwell.schema` partial.
* A hit on a host the ledger never deployed to is listed in `hits_unmatched`
  instead of being dropped while its rule count keeps printing.

### 3. Can one signature cluster two builds? `residue batch`

Given feature sets from two builds, `batch` scores the pair with Jaccard
similarity against a threshold. The interesting case is not "different", it is
"almost the same": a pair at 0.99 looks distinct to a human comparing two file lists
and identical to a clusterer. The band between `threshold - 0.02` and the threshold
is reported as `partial` on purpose, because one more build flips the verdict there.
`--threshold` moves the line; say which one you used, because it changes the verdict.

## How I got here

This started as one of my own bugs. The implant wrote systemd units into
`/etc/systemd/system` and borrowed mtimes from the neighbours, and the checker I
wrote said "all aligned". It was wrong. The client binary was written to
`/usr/local/bin`, where the alignment step had failed silently, and in that
directory the checker found no non-artifact sibling either, so it compared the
artifact against itself and reported "not newer than a neighbour".

The same judgement was identification, measurement and verdict at once. The artifact
had corroborated itself.

The fix was not an extra branch. It was separating identification (heuristic, and
labelled as such), measurement (metadata, recomputable by anyone) and verdict (a
claim somebody else can overturn). The first thing that separation produced was an
uncomfortable fact: in a directory with no neighbours, "aligned" is not a finding,
it is an assumption. That is why `trace.corroborated` exists, and why
`tests/cross_check.sh` recomputes the counts in shell.

## Why this repo exists

The space is uneven. Timestamp forensics is mature: `$STANDARD_INFORMATION` versus
`$FILE_NAME` on NTFS, a long Windows toolkit lineage, published work on disk-level
time tampering. Dwell time is named everywhere and computed nowhere; every vendor has
a glossary entry for MTTD and none ships the arithmetic. Cross-build similarity lives
inside commercial clustering products.

What is missing is the middle: a small, dependency-free, reproducible way to check
somebody's claim that their implant hides well. Not a scanner and not a framework,
an audit. Small enough to point at an image at 3am, documented enough to point at a
paper's results table.

The design constraint that follows is unusual. Every number has to be recomputable by
someone who does not trust this code. That is why identification and measurement are
separate modules, and why the shell cross-check fails loudly when the two counts
disagree.

## Limits

Read [docs/limits.md](docs/limits.md) before quoting any number from this tool.
The short version:

* **Memory is invisible here.** The file behind `/proc/<pid>/exe` stays readable
  after deletion, and nothing under `/proc` is read.
* **Directory timestamps are a signal, not a proof.** `trace.directory_ctime` reports
  `partial` when a holding directory changed after the artifacts inside it were dated:
  it dates the assembly, not the intent, so it cannot stand alone as a finding. A
  package upgrade touches the same directory.
* **Unreadable paths are reported, not counted as empty.** A directory the tool
  cannot list lands in `facts.errors` and downgrades `trace.readable` to `partial`.
  Before this existed, `chmod 000` on a scanned directory made the audit return
  "nothing to audit" with no mention of the failure.
* **`--scan` narrows where claims are filed, not where the anchor is.** Anchors come
  from the marker-bearing units the tool can reach, including the default
  directories, because reading a unit to learn which binary the implant starts files
  no claim of its own. `--scan etc/cron.d` therefore still finds a cron entry that
  names our binary, and still claims nothing outside `etc/cron.d`.
* **`demo --json` keeps one stream machine-readable.** The six sections are prose,
  so with `--json` they go to stderr and stdout carries the report document alone.
* **`ctime` proves the file changed after its neighbours**, not who changed it.
  A package upgrade leaves the same signal.
* **Inode order is a floor.** Reuse after deletion blunts it.
* **Identification is heuristic.** Persistence that does not look like systemd is not
  claimed, and an unclaimed artifact is never measured. Silence about such a file is
  not a finding.
* **`batch` sees one projection.** A low similarity score says the strings did not
  separate the builds. It does not prove they cannot be linked.

## Verify it yourself

```bash
make test     # unit tests: golden contracts and negative controls
make cross    # L3: recompute the same counts with stat(1)
make cov      # line coverage, stdlib only, total and per-module floors
make verify   # all three
make lab      # L2: the same fixtures on a real ext4 guest, no egress
```

Four layers, plus a floor. The middle two are the ones that matter.

| layer | what it proves | how |
|---|---|---|
| L0 | the verdict is what we said it is | fixture to golden JSON, field by field |
| L1 | each check can fail | a negative input that must not pass: 8 checks, 8 negative controls, plus one case for a recognized-but-unreadable path |
| L2 | the claim holds on ext4, not only on macOS temp dirs | QEMU guest, `-netdev user,restrict=on` |
| L3 | the number survives a different implementation | shell and `stat(1)` recompute, diffed against ours |
| floor | the suite covers what it claims | `make cov` fails under the total floor, and under any module more than 2 points below `tests/coverage_baseline.json` |

Without L1, "it passed" means "it was not tested". Without L3, "recomputed" means
"the same program said the same thing twice".

## Scope

In scope: filesystem metadata consistency, dwell-time and detection-coverage
measurement, cross-build similarity scoring.

Out of scope, permanently: delivery, lateral movement, persistence installation,
credential access, or anything that acts on a host it was not pointed at. The lab's
implant is five fixtures that write text files and exit; the guest has no egress and
the repository is mounted read-only.

## Docs

* [docs/method.md](docs/method.md): what each check measures, and why it is shaped
  that way
* [docs/limits.md](docs/limits.md): what it cannot see, per check
* [docs/essay.zh-CN.md](docs/essay.zh-CN.md): 残迹审计，a long-form Chinese write-up

## License

MIT. See [LICENSE](LICENSE).
