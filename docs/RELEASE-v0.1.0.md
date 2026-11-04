# v0.1.0: first measurement release

**What this release is.** Fourteen checks across three commands that recompute how
well a hidden implant hid, and the machinery to prove the recomputation is not
self-attestation.

**What it is not.** A scanner, a framework, or a toolkit. Nothing here executes
against a host; every subcommand reads a path or a JSON file and returns a verdict.

## Checks

| name | question | verdicts |
|---|---|---|
| `trace.artifacts` | which files under the root match the artifact markers | pass / partial / skip |
| `trace.aligned` | is each artifact's mtime no newer than the newest non-artifact sibling | pass / partial / fail / skip |
| `trace.corroborated` | does such a sibling exist at all | pass / partial |
| `trace.ctime` | did the artifact's status-change time outrun every sibling | pass / fail |
| `trace.directory_ctime` | does the holding directory's ctime outrun the artifacts inside it | pass / partial |
| `trace.fresh` | was the tree written inside the freshness window, or dated ahead of the clock | pass / fail |
| `trace.order` | is the artifact's inode higher than every sibling's | pass / fail |
| `trace.readable` | could every scanned path be read | pass / partial |
| `dwell.span` | per-host presence, min/median/p90/max | pass / skip |
| `dwell.coverage` | hits over **deployed** hosts, pre/post split, half is not a majority | pass / partial / skip |
| `dwell.data` | is there a ledger to measure | pass / skip |
| `dwell.hosts` | how many hosts deployed, mined, failed | pass |
| `dwell.schema` | does every event carry a kind the tool knows | pass / partial |
| `batch.<a>_vs_<b>` | Jaccard of feature sets against the threshold, one check per pair | pass / partial / fail / skip |

## What it can honestly claim

* **Recomputable.** `tests/cross_check.sh` identifies with `residue` and measures
  with `stat(1)`; the two counts must agree or the script fails.
* **Falsifiable.** Every check has an input on which it must not pass, and the
  negative controls in `tests/` name both the input and the verdict it must not
  reach. The counts live in the suite, not in this note: a number written here
  rots the first time a test is added.
* **Portable.** Zero dependencies, Python 3.9+, runs on Linux and macOS in CI; the
  QEMU lab runs the same fixtures on real ext4 with no egress.

## What it cannot claim

* It does not read memory, `/proc`, deleted inodes, or any filesystem state that
  is not on disk right now.
* A directory stamp is a lead, not a verdict. `trace.directory_ctime` compares the
  holding directory's ctime against the artifacts inside it and can reach
  `partial`; it never reaches `fail`, because a package upgrade touches the same
  directory in the same order. Documented in `docs/limits.md`.
* `ctime` proves the file changed after its siblings, not that an attacker changed it.
* Inode order is a floor: reuse after deletion blunts it.
* `batch` sees one projection of a build. A low score is not a proof of unlinkability.

## Layout

```
residue/        model, stat_io, report, trace, dwell, batch, cli, demo
tests/          unit tests, golden contracts, negative controls, cross_check.sh
lab/            one-command QEMU guest: read-only 9p mount, no egress
docs/           method (EN/中文), limits (EN/中文), essay (中文)
```

## Install

```bash
git clone https://github.com/yaorenliang/residue-audit
cd residue-audit
make demo
make verify
make lab        # needs qemu; first run takes a few minutes
```

## Thanks

To everyone who has ever written "no evidence of persistence" in a report and
meant the second thing.