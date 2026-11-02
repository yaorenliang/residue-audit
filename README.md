# residue-audit

**Measure what a hidden implant leaves behind — from a third party's point of view.**

Most security tooling answers *"did we detect it?"*. This project asks a question
that is harder to fake: *"what is still visible on the host, after it tried to hide?"*

Three checks, one stance: **recompute, never self-report.**

| Check | Question it answers |
|---|---|
| `residue trace` | Do the artifacts an implant dropped actually blend into their neighbours — file mtime, directory order, corroborating siblings? |
| `residue dwell` | Given a ledger and a set of detection hits, how long did it live, and how much of that is genuinely covered by rules? |
| `residue batch` | Are two builds of the same family mutually distinguishable, or can one signature cluster them? |

## Status

`v0.0.0` — repository scaffold. The three checks land in `v0.1.0`.
Nothing here executes anything against a host: every subcommand reads paths and
JSON and returns a verdict.

## Design stance

1. **Recompute, don't self-attest.** A claim like "timestamps are aligned" is worth
   nothing if the program that aligned them also prints the verdict. Every check is
   designed so a second, independent implementation can reproduce the number.
2. **Every check has a negative control.** If there is no input that makes a check
   fail, the check is not a check.
3. **Limits are part of the output.** Each verdict carries `why` and `evidence`;
   each check documents the cases where it *cannot* tell. See `docs/limits.md`.

## Scope

In scope: filesystem metadata consistency, dwell-time and detection-coverage
measurement, cross-build similarity scoring.

Out of scope, permanently: payload delivery, lateral movement, persistence
installation, credential access, or anything that acts on a host it was not pointed at.

## Reproduce

```bash
git clone https://github.com/yaorenliang/residue-audit
cd residue-audit
make demo        # fixture-only, no VM, no network
```

A QEMU lab (`make lab`) runs the same fixtures on a real ext4 guest with no egress,
because macOS and ext4 disagree about directory mtimes in ways that matter here.

## License

MIT — see [LICENSE](LICENSE).
