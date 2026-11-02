# residue-audit

**Measure what a hidden implant leaves behind — from a third party's point of view.**

![verify](https://github.com/yaorenliang/residue-audit/actions/workflows/ci.yml/badge.svg)

Every incident report ends the same way: *we found no evidence of persistence.*
That sentence has two very different meanings, and most tooling cannot tell them
apart. It can mean **it was not there**. It can also mean **it was there, and the
way we looked could not have seen it**.

This project measures the difference.

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

Read that output again. The implant did everything a careful operator does: it
borrowed timestamps from its neighbours, it landed in directories that already had
company, it stayed out of the last two minutes of history. **And it is still
visible in two places** — because a timestamp can be rewritten and a creation order
cannot, and because changing an mtime moves a ctime that nobody can put back.

That is the whole idea. Not "can we detect it", but **at which layer does the
hiding stop working, and how would someone else check that claim without trusting
us**.

## Thirty seconds

```bash
git clone https://github.com/yaorenliang/residue-audit
cd residue-audit
make demo
```

Zero dependencies, Python 3.9+. Nothing leaves your machine, no network, no
privileges. The demo builds a throwaway tree, plants a synthetic artifact set, and
prints the three verdicts above plus two counter-examples — an unaligned tree that
must fail, and a detection ledger where exactly half the hosts were covered (which
is not a majority, and the tool says so).

## What it says on a real host

The lab boots a stock Ubuntu 24.04 root with no egress and audits it twice.

**Identification.** A rule of the shape "any binary named by any unit" claimed 13
files on that root, 5 of them ours — 38% precision, because `packagekitd`,
`boltd`, `qmi-proxy` and five more are legitimately started by legitimately
installed units. Anchoring the rule on a marker-bearing unit and following
`ExecStart=` outward gives 5 claims, 0 false positives, and 8 files reported as
weak claims (not audited). `--broad` restores the old rule if you would rather
over-claim than miss.

**The floor.** The scoped run aligns 5 of 5 artifacts and leaks none — and still
fails, on `ctime` and `order`. That is not a bug in the fixture. It is the
answer to "how deep can this go", and it comes with a number.

## Three questions

### 1. Did the artifacts actually blend in? — `residue trace`

An implant that writes files leaves the files, and the *shape* of their metadata
relative to everything around them. `trace` reads a root (a mounted image, a live
host, a fixture tree) and separates three questions that are usually collapsed into
one:

* **alignment** — is the artifact's mtime no newer than the newest non-artifact
  sibling in its directory? The first command anyone runs on a suspicious host is
  `ls -lt`; alignment is the answer to that command.
* **corroboration** — does such a sibling exist at all? In an empty `/etc/cron.d`
  there is nothing to borrow from, and "aligned" would be an assumption wearing a
  verdict's clothes. The tool returns `partial`, not `pass`.
* **freshness** — is the whole tree new enough that alignment is meaningless? A
  perfectly aligned artifact written ninety seconds ago is still obviously part of
  the same burst.

Then two checks that are floors rather than findings: **ctime** (rewriting an mtime
moves the status-change time, which user space cannot set back) and **creation
order** (inode numbers are allocated monotonically; no syscall renumbers a file).
Both fail on a "successfully" hidden implant, and that is the point — depth has a
boundary, and the tool draws it instead of pretending it is not there.

### 2. How long did it live, and how much of that was covered? — `residue dwell`

Given an ndjson ledger (`{"ts": 1180, "host": "h1", "event": "mine"}`) and an
optional hit list, `dwell` reports per-host spans, the distribution, and a
coverage rate with three rules that exist because the naive rate is wrong:

* the denominator is hosts that reached `deploy` — a host that was only scanned
  had nothing to detect, and counting it lets an operator flatter the rate by
  scanning more than it infected;
* hits before deploy and after deploy are counted separately — a rule that fires
  before the implant exists is a false positive, and folding it in makes the stack
  look better than it is;
* exactly half is not a majority. `> 50.0` passes, `50.0` is
  `partial-coverage`, and "no hits supplied" is `unknown, not zero`.

### 3. Can one signature cluster two builds? — `residue batch`

Given feature sets extracted from two builds, `batch` scores the pair with Jaccard
similarity against a threshold. The interesting case is not "different" — it is
"almost the same": a pair at 0.99 looks distinct to a human comparing two file lists
and identical to a clusterer. The band between `threshold - 0.02` and the
threshold is reported as `partial` on purpose: near the line, one more build
flips the verdict.

## Why this exists

The niche is not empty, but it is lopsided. Timestamp forensics is mature —
`$STANDARD_INFORMATION` versus `$FILE_NAME` on NTFS, a well-known Windows toolkit
lineage, public papers on disk-level time tampering. Dwell time is *named*
everywhere and *computed* nowhere: every major vendor has a glossary entry for MTTD
and none of them ship the arithmetic. Cross-build similarity lives inside
commercial clustering products.

What is missing is the thing in the middle: **a small, dependency-free,
reproducible way to check someone's claim that their implant hides well.** Not a
scanner, not a framework — an audit. Something an incident responder can point at
an image at 3am, and something a researcher can point at a paper's table.

So the design constraint is unusual: every number must be **recomputable by someone
who does not trust this code**. That is why the checks are split into *identify*
(heuristic, and honestly labelled as such) and *measure* (plain metadata, redoable
with `stat(1)`), and why `tests/cross_check.sh` recomputes the counts in shell
and fails if the two disagree.

## Limits

Read [docs/limits.md](docs/limits.md) before quoting any number from this tool. The
short version:

* **Memory is not visible here.** The file behind `/proc/<pid>/exe` stays readable
  after deletion; nothing under `/proc` is read.
* **Directories are not checked yet.** Writing a file updates its parent directory's
  mtime *and* ctime, and ctime cannot be set. This is the most likely way the tool
  returns `pass` on a host a human would call dirty. Known gap, written down.
* **`ctime` proves the file changed after its neighbours, not that an attacker
  changed it.** A package upgrade leaves the same signal.
* **inode order is a floor.** Inode reuse after deletion blunts it.
* **Identification is heuristic.** Persistence that does not look like systemd is
  not claimed, and an unclaimed artifact is not measured. Silence is not a finding.
* **`batch` sees one projection.** A low similarity score is evidence about
  strings, not a proof of unlinkability.

## Verify it yourself

```bash
make test     # 15 unit tests: golden contracts + negative controls
make cross    # L3: recompute the same numbers with stat(1)
make verify   # both
make lab      # L2: the same fixtures on a real ext4 guest, no egress
```

Four layers, and the last two are the ones that matter:

| layer | what it proves | how |
|---|---|---|
| L0 | the verdict is what we said it is | fixture → golden JSON, field by field |
| L1 | the check can fail | a negative input per check that must not pass |
| L2 | the claim holds on ext4, not just on macOS temp dirs | QEMU guest, `-netdev user,restrict=on` |
| L3 | the number survives a different implementation | shell + `stat(1)` recompute, diff against ours |

Without L1, "it passed" means "it was not tested". Without L3, "recomputed" means
"the same program said the same thing twice".

## Scope

In scope: filesystem metadata consistency, dwell-time and detection-coverage
measurement, cross-build similarity scoring.

Out of scope, permanently: payload delivery, lateral movement, persistence
installation, credential access, or anything that acts on a host it was not pointed
at. The lab's "implant" is a five-file fixture that writes text files and exits; the
guest has no egress and the repository is mounted read-only.

## Docs

* [docs/method.md](docs/method.md) — what each check measures and why it is shaped
  that way
* [docs/limits.md](docs/limits.md) — what it cannot see, per check
* [docs/essay.zh-CN.md](docs/essay.zh-CN.md) — 残迹审计：我怎么验证一个木马到底藏得多深

## License

MIT — see [LICENSE](LICENSE).