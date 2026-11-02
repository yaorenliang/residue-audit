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
the binary behind `/proc/<pid>/exe` stays readable after the file is deleted. This
tool will report a clean filesystem while the process that matters is still
resident.

**It does not see deleted files.** An unlinked inode survives in the page cache and
in the journal. If the artifact was removed before you mounted, the file is gone from
this view and the checks below it have nothing to say.

**It sees the holding directory, and only as a lead.** Creating a file updates its
parent directory's mtime, and no user-space trick avoids that write. The parent has a
ctime too, and ctime cannot be set. A careful responder runs
`stat /etc/systemd/system` and sees a directory that changed at 03:14 while every
file inside claims to be from 2019. `trace.directory_ctime` compares that directory
timestamp against the oldest artifact inside it and reports `partial` when the
directory is newer. It stays `partial` and never becomes `fail` for a reason: a
package upgrade touches the same directory in the same order. The check dates the
assembly, not the intent.

**An unreadable path is a named gap, not an empty directory.** A directory the tool
cannot list lands in `facts.errors`, the artifacts behind it are not measured, and
`trace.readable` drops to `partial`. This limit is listed here because the
failure mode it replaced was invisible: `chmod 000` on a scanned directory used to
produce "nothing to audit" with no indication that anything had been skipped. If
`trace.readable` is not `pass`, the counts below it describe a smaller tree than
the one you pointed at.

**ctime is evidence of change, not of malice.** ctime cannot be backdated, so an
artifact whose ctime is newer than every sibling was written after its neighbours.
But "after" is not "by an attacker". Any process that rewrites a legitimate unit file
produces the same signal, including a package upgrade or a config rollback. ctime
narrows the window. It does not assign blame.

**inode order is a floor, not a proof.** Most Linux filesystems allocate inode
numbers monotonically, so the file created last usually has the highest number. Two
things blunt this: inode reuse after deletion can hand a new file a low number, and
directory-internal ordering depends on the filesystem. A pass here means "no obvious
allocation-order signal", not "created before its neighbours".

**Identification is heuristic, and its precision is measured.** A file counts as an
artifact only if (a) it is a unit that carries a body marker, (b) it is started by
such a unit, or (c) its body names a file from (a) or (b).

Two failure directions, both real:

* **Over-claim, if you widen it.** The first rule set claimed any file named by any
  unit's `ExecStart=`. On a stock Ubuntu 24.04 root it claimed 13 files, 5 of them
  ours, for 38% precision, with `packagekitd`, `boltd`, `qmi-proxy` and five
  more sitting in the false positives. That rule is still available as `--broad`,
  and it prints the same numbers.
* **Under-claim, always.** An implant whose persistence does not look like systemd
  (a shell profile line, an `LD_PRELOAD` entry, a cron file invoking `/bin/sh -c`
  with an inline payload) is not claimed, and an unclaimed artifact is not measured
  at all. Files the narrow rule rejects are counted as `weak_claims` and reported,
  but **the tool's silence about such a file is not a finding.**

**Freshness depends on the clock you give it.** `--fresh-window` compares against
`time.time()`. On a mounted image from last month, everything looks old, including
the intrusion. Use freshness on live hosts, not on cold images.

## dwell

**The ledger is a model, not a record.** If an implant deployed to a host and the
event was not written to the ledger, the tool treats that host as never deployed, and
every rate it computes inherits the omission. The percentage is only as good as the
input.

**Coverage is coverage by the rules you supplied.** `--hits` is a file of hit
events. The rate answers "of the hosts we deployed to, how many produced at least one
of these hits". It is not a statement about the detection stack's real recall, and it
cannot be, because nobody handed the tool the rules that did not fire.

**Pre/post depends on clock agreement.** The boundary is each host's own `deploy`
timestamp. Hosts with skewed clocks will misclassify hits near the boundary. This
tool does not correct skew.

**An unknown event kind shrinks the denominator, and the tool says so rather than
guessing.** Anything outside `{deploy, mine, scan}` is listed in `unknown_events`
and raises a `dwell.schema` partial. If your ledger uses a kind this version does
not know (`install`, `exploit`, `removed`), the coverage number is computed over
the hosts it did understand - read `hit_rate_all_hosts` next to it, and treat a
partial schema as "this denominator may be wrong" rather than "this rate is low".

**Hits on hosts that were never deployed are listed, not scored.** They appear in
`hits_unmatched`. A hit for an unknown host can mean a ledger with a missing
`deploy` row or a hit file built against a different fleet; either way it cannot
enter the coverage rate, and dropping it silently would leave its rule printed with a
count that no longer explains anything.

**Spans measure presence, not activity.** A span runs from deploy to the last event
seen for that host. Absence of later events is not proof that the implant stopped. It
may mean the ledger stopped.

## batch

**Features are a lossy projection.** Jaccard over extracted strings answers exactly
one question: do these two builds share more than 98% of their string set. Two builds
can sit at 0.90 and still be trivially clustered by control-flow shape, function
ordering, constant tables, or the order of their sections. This tool looks at none of
those.

**A low score is not evidence of unlinkability.** It is evidence that this
projection does not separate them. The claim "these two builds cannot be correlated"
requires an argument about every projection an analyst might use, and no single score
can carry it.

**The threshold is a convention, not a law.** 0.98 comes from reproducing a result
in the field: two builds of the same family at 0.96 to 0.98 were still clustered by
hand. Change the threshold and you change the verdict, so say which one you used.

**An empty feature set has no similarity at all.** Two empty sets are `skip`, not
`fail`: the ratio is undefined, and reporting 1.0 (the old behaviour) claimed the
two builds were identical when in fact neither extraction produced anything. One
empty set against a non-empty one is a genuine 0.0 and is scored.

## Exit codes

`0` pass, `1` partial, `2` fail, `3` skip, `4` tool failure. Four is not a
verdict: it means the tool could not run its checks (bad flag, unreadable input, a
crash). A gate that treats 4 as "something found" will page somebody for a typo, and
a gate that treats 4 as "clean" is worse. Check the code before the summary line.

## Platform

The claims hold on ext4. On APFS, directory mtime and inode allocation behave
differently, and there is an extra field, birthtime, that this tool does not read.
Running `trace` on a macOS host produces numbers. Whether they mean what they mean
on Linux is untested. L2 in the method document is the check that matters: the
fixtures run on a real ext4 guest with no network, and the verdict is compared
against the same golden values.

## What this tool is for

It replaces "we found nothing" with two statements: here is the layer at which we
would have found it, and here is the layer where we would not. The second statement
is the one that gets left out of incident reports. This file is where it goes.
