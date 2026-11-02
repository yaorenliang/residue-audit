# residue-audit

**Measure what a hidden implant left behind, from a third party's position.**

Incident reports often end with the same sentence: no evidence of persistence.
That sentence has two meanings and most tooling does not separate them.
One is that the implant was never there. The other is that it was there,
and the way we looked could not have seen it. This project measures the distance.

```
$ residue trace /mnt/image
trace.artifacts     pass     5 artifact(s) matched the marker set
trace.aligned       pass     all 5 artifact(s) are no newer than a sibling
trace.corroborated  pass     every directory holding an artifact also holds a non-artifact sibling
trace.ctime         fail     5 artifact(s) have a ctime newer than every sibling:
                             mtime can be borrowed, ctime cannot
trace.fresh         pass     no artifact carries an mtime within 120s of now
trace.order         fail     5 artifact(s) have a higher inode than every sibling,
                             so creation order is recoverable

summary command=trace status=fail exit=2
```

That implant did everything a careful operator does. It borrowed timestamps from
its neighbours, it landed in directories that already had company, and it stayed
out of the last two minutes of history. It is still visible in two places, because
a timestamp can be rewritten and a creation order cannot, and because changing an
mtime moves a ctime that nobody can put back.

So the question is not "can we detect it". The question is where the hiding stops
working, and how somebody else checks that claim without trusting this code.

## Thirty seconds

```bash
git clone https://github.com/yaorenliang/residue-audit
cd residue-audit
make demo
```

Zero dependencies, Python 3.9+. No network, no root, no writes outside the paths
you point it at. The demo builds a throwaway tree, plants a synthetic artifact set,
prints the three verdicts above, and adds two counter-examples: an unaligned tree
that must fail, and a ledger where exactly half the hosts were covered.

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
on `ctime` and `order`. That is not a fixture bug. It is the answer to "how deep
can this go", and it comes with numbers.

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

### 3. Can one signature cluster two builds? `residue batch`

Given feature sets from two builds, `batch` scores the pair with Jaccard
similarity against a threshold. The interesting case is not "different", it is
"almost the same": a pair at 0.99 looks distinct to a human comparing two file lists
and identical to a clusterer. The band between `threshold - 0.02` and the threshold
is reported as `partial` on purpose, because one more build flips the verdict there.

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
* **Directories are not checked yet.** Writing a file updates the parent directory's
  mtime and ctime, and ctime cannot be set. This is the most likely way the tool
  returns `pass` on a host a human would call dirty. Known gap, written down.
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
make test     # 16 unit tests: golden contracts and negative controls
make cross    # L3: recompute the same counts with stat(1)
make verify   # both
make lab      # L2: the same fixtures on a real ext4 guest, no egress
```

Four layers. The last two are the ones that matter.

| layer | what it proves | how |
|---|---|---|
| L0 | the verdict is what we said it is | fixture to golden JSON, field by field |
| L1 | each check can fail | a negative input per check that must not pass |
| L2 | the claim holds on ext4, not only on macOS temp dirs | QEMU guest, `-netdev user,restrict=on` |
| L3 | the number survives a different implementation | shell and `stat(1)` recompute, diffed against ours |

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
