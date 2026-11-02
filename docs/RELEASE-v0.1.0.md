# v0.1.0: first measurement release

**What this release is.** Three checks that recompute how well a hidden implant
hid, and the machinery to prove the recomputation is not self-attestation.

**What it is not.** A scanner, a framework, or a toolkit. Nothing here executes
against a host; every subcommand reads a path or a JSON file and returns a verdict.

## Checks

| name | question | verdicts |
|---|---|---|
| `trace.artifacts` | which files under the root match the artifact markers | pass / skip |
| `trace.aligned` | is each artifact's mtime no newer than the newest non-artifact sibling | pass / partial / fail |
| `trace.corroborated` | does such a sibling exist at all | pass / partial / skip |
| `trace.ctime` | did the artifact's status-change time outrun every sibling | pass / fail |
| `trace.fresh` | was the tree written inside the freshness window | pass / fail |
| `trace.order` | is the artifact's inode higher than every sibling's | pass / fail |
| `dwell.span` | per-host presence, min/median/p90/max | pass / skip |
| `dwell.coverage` | hits over **deployed** hosts, pre/post split, half is not a majority | pass / partial / skip |
| `dwell.data` | is there a ledger to measure | pass / skip |
| `batch.A_vs_B` | Jaccard of feature sets against the threshold | pass / partial / fail |

## What it can honestly claim

* **Recomputable.** `tests/cross_check.sh` identifies with `residue` and measures
  with `stat(1)`; the two counts must agree or the script fails.
* **Falsifiable.** Sixteen unit tests, of which five are negative controls: every
  check has an input on which it must not pass.
* **Portable.** Zero dependencies, Python 3.9+, runs on Linux and macOS in CI; the
  QEMU lab runs the same fixtures on real ext4 with no egress.

## What it cannot claim

* It does not read memory, `/proc`, deleted inodes, or any filesystem state that
  is not on disk right now.
* It does not check directory ctime. Writing a file updates the parent directory's
  mtime and ctime, and ctime cannot be set. This is the most likely way the tool
  returns `pass` on a dirty host. Documented in `docs/limits.md`.
* `ctime` proves the file changed after its siblings, not that an attacker changed it.
* Inode order is a floor: reuse after deletion blunts it.
* `batch` sees one projection of a build. A low score is not a proof of unlinkability.

## Layout

```
residue/        model, stat_io, report, trace, dwell, batch, cli, demo
tests/          15 unit tests, golden contracts, negative controls, cross_check.sh
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