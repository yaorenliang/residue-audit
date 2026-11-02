# Limits

Every check in this tool has a domain, and outside that domain its output means
nothing. This file is the boundary, written down so that nobody has to discover it
by being wrong in public.

If you quote a number from `residue`, quote the limit that comes with it.

## trace

**What it sees.** Metadata of files that already exist under the root you pointed
it at. That is all.

**It does not see memory.** Strings of a running implant live in a process image
that was mapped before your mount. Nothing under `/proc/<pid>` is read here, and
the binary behind `/proc/<pid>/exe` stays readable even after the file is
deleted — this tool will happily report a clean filesystem while the process that
matters is still resident.

**It does not see deleted files.** An unlinked inode survives in the page cache and
in the journal. If the artifact was removed before you mounted, the file is gone
from this view and the checks below it have nothing to say.

**It does not see the directory.** Creating a file updates its parent directory's
mtime, and no user-space trick avoids that write — the parent has a ctime too, and
ctime cannot be set. A careful responder runs `stat /etc/systemd/system` and sees
a directory that changed at 03:14 while every file inside claims to be from 2019.
`trace` reports directory caps as neighbour evidence but does **not** yet raise a
check on directory ctime. That gap is known, and it is the single most likely way
this tool returns `pass` on a host that a human would call dirty.

**ctime is evidence of change, not of malice.** ctime cannot be backdated, so an
artifact whose ctime is newer than every sibling was written after its neighbours.
But "after" is not "by an attacker": any process that rewrites a legitimate unit
file — a package upgrade, a config rollback — produces the same signal. ctime
narrows the window; it does not assign blame.

**inode order is a floor, not a proof.** Most Linux filesystems allocate inode
numbers monotonically, so the file created last usually has the highest number.
Two things blunt this: inode reuse after deletion can hand a new file a low number,
and directory-internal ordering depends on the filesystem. A pass here means "no
obvious allocation-order signal", not "created before its neighbours".

**Identification is heuristic, and its precision is measured.** A file counts as an
artifact only if (a) it is a unit that carries a body marker, (b) it is started by
such a unit, or (c) its body names a file from (a) or (b).

Two failure directions, both real:

* **Over-claim, if you widen it.** The first rule set claimed any file named by any
  unit's `ExecStart=`. On a stock Ubuntu 24.04 root it claimed 13 files, 5 of them
  ours — 38% precision, with `packagekitd`, `boltd`, `qmi-proxy` and five more
  sitting in the false positives. That rule is still available as `--broad`, and
  it prints the same numbers.
* **Under-claim, always.** An implant whose persistence does not look like systemd —
  a shell profile line, an `LD_PRELOAD` entry, a cron file invoking `/bin/sh -c`
  with an inline payload — is not claimed, and an unclaimed artifact is not measured
  at all. Files the narrow rule rejects are counted as `weak_claims` and reported,
  but **the tool's silence about such a file is not a finding.**

**Freshness depends on the clock you give it.** `--fresh-window` compares against
`time.time()`. On a mounted image from last month, everything looks old, including
the intrusion. Use freshness on live hosts, not on cold images.

## dwell

**The ledger is a model, not a record.** If an implant deployed to a host and the
event was not written to the ledger, the tool treats that host as never deployed,
and every rate it computes inherits the omission. Garbage in, confident percentage
out.

**Coverage is coverage by the rules you supplied.** `--detections` is a file of
hit events. The rate answers "of the hosts we deployed to, how many produced at
least one of *these* hits". It is not a statement about the detection stack's real
recall, and it cannot be, because nobody handed the tool the rules that did not
fire.

**Pre/post depends on clock agreement.** The boundary is each host's own `deploy`
timestamp. Hosts with skewed clocks will misclassify hits near the boundary. This
tool does not correct skew.

**Spans measure presence, not activity.** A span runs from deploy to the last event
seen for that host. Absence of later events is not proof the implant stopped; it may
mean the ledger stopped.

## batch

**Features are a lossy projection.** Jaccard over extracted strings answers exactly
one question: do these two builds share more than 98% of their string set. Two
builds can sit at 0.90 and still be trivially clustered by control-flow shape,
function ordering, constant tables, or the order of their sections — none of which
this tool looks at.

**A low score is not evidence of unlinkability.** It is evidence that *this*
projection does not separate them. The claim "these two builds cannot be
correlated" requires an argument about every projection an analyst might use, and
no single score can carry it.

**The threshold is a convention, not a law.** 0.98 comes from reproducing a result
in the field: two builds of the same family at 0.96-0.98 were still clustered by
hand. Change the threshold and you change the verdict; say which one you used.

## Platform

The claims hold on ext4. On APFS, directory mtime and inode allocation behave
differently, and there is an extra field — birthtime — that this tool does not
read. Running `trace` on a macOS host produces numbers; whether they mean what
they mean on Linux is untested. L2 in the method document is the check that
matters: the fixtures run on a real ext4 guest, with no network, and the verdict
is compared against the same golden values.

## What this tool is for

It is for replacing "we found nothing" with "here is the layer at which we would
have found it, and here is the layer where we would not". The second half of that
sentence is the part that has to be written down, and this file is it.