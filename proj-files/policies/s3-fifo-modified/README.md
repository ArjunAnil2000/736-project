# S4-FIFO: Cost-Weighted Probation for Heterogeneous Storage

S4-FIFO extends S3-FIFO with a second small (probationary) queue, so that each
storage device gets its own. When the small queues must give up a folio, the
slow device's queue is chosen only if its oldest folio has been waiting more
than *k* times longer than the fast device's oldest folio, where *k* is the
measured miss-cost ratio between the two devices. Slow folios therefore get a
proportionally longer chance to prove they will be reused before they are
evicted.

Files: `cache_ext_s4fifo.bpf.c` (eBPF policy), `cache_ext_s4fifo.c` (loader),
and `base_policy_s3fifo.{bpf.c,c}`, an unmodified, unbuilt copy of the
upstream policy it is based on, for comparison.

## Background

The Linux page cache evicts by recency and frequency, treating every page as
equally expensive to lose. On a host whose files live on devices of very
different speed, such as a SATA SSD (≈ 0.1 ms per 4 KiB random read) and an
HDD (several ms) [7], the cost of a miss depends on the device behind it, so
minimizing misses no longer minimizes I/O wait. Forney et al. showed for
storage-aware caching that weighting replacement decisions by per-device cost
reduces total wait time [3]. `cache_ext` [1] lets such policies run in the
kernel: eviction decisions are exposed as eBPF `struct_ops` hooks per memory
cgroup, and the policy manages kernel-maintained lists of folios.

A recurring observation in cache workloads is that many objects are accessed
once and never again ("one-hit wonders"). Policies that keep new objects
apart from proven ones outperform pure LRU on such workloads. 2Q is an early
example: new objects enter a FIFO, and only those re-referenced after leaving
it, while their identity is still remembered in a ghost queue, are admitted to
the main LRU [4]. S3-FIFO keeps objects that are re-accessed *during* a short
probation period instead, a principle Yang et al. call *quick demotion* [5]. Probation is exactly where a
storage-aware policy can act most cheaply: deciding how long a new folio may
stay on probation determines whether it gets the chance to be reused at all.

## Existing policy

S3-FIFO [2] uses three FIFO queues:

* a **small** queue S (about 10% of the cache) that every new object enters;
* a **main** queue M holding objects that proved their reuse;
* a **ghost** queue G that remembers the identities (not the data) of objects
  recently evicted from S.

Each object carries a small frequency counter (capped at 3) that is
incremented on access. When S must evict, the object at its head moves to M if
it was re-accessed while in S (the `cache_ext` port requires a counter above
1); otherwise it is evicted and its identity inserted in G. When M must evict, the head object is reinserted at
the tail with its counter decremented if the counter is non-zero (as in
CLOCK [6]), and evicted otherwise. An object that misses but is found in G is
inserted directly into M. The queue to evict from is chosen by size: S is
drained when it exceeds its share of the cache.

`cache_ext` ships an eBPF implementation (`cache_ext_s3fifo`) that keeps S
and M as `cache_ext` lists, G as a BPF LRU hash keyed by (file, offset), and
the counters in a per-folio hash map. Its sizing rule evicts from S when
`|S| >= cache_size / 15` or `|M| <= 2|S|`, and from M otherwise.

## Modifications made

Five changes relative to `cache_ext_s3fifo` (`base_policy_s3fifo.bpf.c`); the
first three are the device-aware design, the last two fix upstream bugs, so
`k = 1` is a corrected S3-FIFO port rather than the upstream one:

1. **Folios are tracked by device.** Upstream tracks the files under a
   `--watch_dir`. Here a folio's device is read from its file's superblock
   (`folio->mapping->host->i_sb->s_dev`) and looked up in `dev_idx_map`,
   which the loader fills with the device numbers of the fast and slow mount
   points (default `/mnt/fast`, `/mnt/slow`; see `common/`). The device index
   is stored in the folio's metadata. Folios on other devices are not tracked
   and are left to the kernel's default reclaim.
2. **One small queue per device.** S is split into `small[FAST]` and
   `small[SLOW]`, each with its own size counter. A new folio enters the small
   queue of its device, unless it is found in the ghost queue, in which case
   it enters M as in S3-FIFO. M and G are shared by both devices and
   unchanged, and the sizing rule is applied to the combined size of the two
   small queues.
3. **Age-weighted choice between the small queues.** Each folio records its
   insertion time. Whenever the sizing rule selects S, the policy peeks at
   the head of each small queue (the folio that has been on probation
   longest) and compares how long each has waited:

   ```
   evict from small[SLOW]  iff  age(head of small[SLOW]) > k · age(head of small[FAST])
   ```

   and otherwise from `small[FAST]`. If the chosen queue cannot supply enough
   evictable folios, the other small queue is scanned next. The scan of each
   queue is S3-FIFO's: folios accessed more than once are promoted to M, the
   rest are evicted into G.

   *k* is set by the loader (`--k`), and is the ratio of the slow device's
   miss cost to the fast device's, obtained by profiling the devices (e.g. the
   ratio of their mean 4 KiB random-read latencies at queue depth 1). In
   steady state a slow folio stays on probation about *k* times longer than a
   fast folio, i.e. the time budget each folio gets to be reused is
   proportional to what its miss would cost. The rule is a two-class,
   FIFO-ordered form of cost-aware Hyperbolic caching, which multiplies an
   object's priority (hits over time in cache) by its miss cost [10]: with
   equal hit counts at the two heads it reduces exactly to this test. It is
   related only loosely to GreedyDual [8, 9], whose cost credit is additive.

   `k = 1` compares the two heads by age alone, which makes the pair of small
   queues behave like S3-FIFO's single small queue (always evict the folio
   inserted earliest). `k = 0` is a special setting, not the formula evaluated
   at `k = 0` (which would always pick the slow queue): it evicts from
   `small[FAST]` whenever it is non-empty, the `k → ∞` limit. This *strict
   fast-first* variant is kept as an ablation; the loader maps any
   `k < 0.0005` to it.
4. **Fix: a per-call eviction budget** (`common/hetero_iter.bpf.h`). The
   kernel's list iterator selects victims until its 32-entry array is full,
   whatever the kernel asked for, and the kernel reclaims all of them, so the
   upstream port evicted about 8× more folios than requested. Scans now stop
   once the request is met, and a scan that wraps around the list stops at
   (or, in M's repeated passes, skips) folios this call already chose.
5. **Fix: queue-size accounting.** Folios that the small-queue scan moves to
   M because they are dirty or under writeback are now marked as being in M,
   and the clamps that keep the size counters non-negative test the updated
   value (upstream tested the value before the update, so a negative size was
   never clamped). The counters drive the sizing rule, so both errors changed
   which queue was evicted from.

The `debug_*` validation counters (see `common/hetero_debug.bpf.h`) are
compiled in only with `make debug`; they never change the policy's decisions.

Build with `make` in `proj-files/policies/`; run with

```bash
sudo ./cache_ext_s4fifo.out --cgroup_path /sys/fs/cgroup/<cgroup> \
     --cgroup_size <bytes> --k <ratio>
```

`--cgroup_size` is the cgroup's memory limit, as upstream. MGLRU must be disabled and the cgroup name must start with
`cache_ext`. `five-minute-rule/profile_devices.sh` measures the devices and
prints a suggested *k*. On a host with more than one NUMA node, bind the
workload to node 0 (e.g. `numactl --cpunodebind=0 --membind=0`): the
`cache_ext` kernel registers a policy's lists on node 0 but looks them up by
the NUMA node of each folio, so page cache allocated on another node can never
be added to a list. With `make debug`, the validation counters can be read
with `sudo bpftool map dump name debug_map`.

## Expected behaviour

* **Fewer one-hit-wonder evictions of the wrong kind.** Fast folios are
  demoted quickly, as in S3-FIFO; slow folios are given *k* times longer to
  receive a second access. Slow folios that are reused should be promoted to
  M more often than under S3-FIFO, reducing expensive misses, while fast
  one-hit wonders still leave the cache quickly.
* **Graceful in the cost gap.** As *k* → 1 the policy converges to the
  (corrected) `cache_ext` S3-FIFO port;
  larger *k* shifts probation time towards the slow device in proportion to
  its cost, rather than by a fixed bias.
* **Strict fast-first should be worse.** With `k = 0`, fast folios have
  essentially no probation whenever any are queued, so almost none reach M;
  `small[SLOW]` is drained only when `small[FAST]` is empty, so it fills with
  slow one-hit wonders. We expect lower total throughput than both S3-FIFO and
  the age-weighted variant, mirroring the preliminary result of the
  device-partitioned LRU with a fixed 75% bias, which over-protected slow
  folios and lost throughput at small cache sizes. The contrast between
  `k = 0` and the measured *k* is the main ablation for this policy.
* **The main queue is unchanged.** Once promoted, fast and slow folios are
  treated identically, so the policy's effect is concentrated on workloads
  where probation decisions matter, i.e. those with many single-access or
  rarely reused blocks.

On a host with a real SSD and HDD (CloudLab c220g5; 4 KiB random reads at
queue depth 1 take 0.16 ms and 3.8 ms, so the profiled *k* is 23.7), with two
1 GiB files read with zipf 0.9 by 8 threads in a 128 MiB cgroup (three
repeats): with `k = 1` the cache holds 49.5% HDD pages and throughput is within
1% of the kernel's default policy (2164 vs 2182 IOPS); with `k = 23.7` it holds
78.6% HDD pages, HDD folios are promoted to M about three times as often as SSD
folios, and throughput rises by 6.5% over the default (7.4% over `k = 1`). In
this workload M is never evicted from: promotions are rare enough that the
sizing rule always selects the small queues.

## Limitations

* **Only probation is cost-aware.** Evictions from M, which dominate when S
  is small, ignore the device. A natural extension is to apply the same
  age-weighted rule to per-device main queues.
* **Age is measured from insertion.** The age compared between the two heads
  is time spent in S, regardless of accesses. It only decides *which* small
  queue is scanned; whether a folio is promoted still depends on its access
  count alone, so a slow folio's extra probation time helps only if a second
  access actually arrives within it.
* **Approximate sizes.** As in S3-FIFO's `cache_ext` port, queue sizes are
  counted from the policy's own decisions rather than from what the kernel
  actually evicted, so the sizing rule is approximate.
* **Static *k*.** *k* is fixed at load time from offline profiling; device
  latency under load (queueing, contention) can differ from the profile.
  An online estimate of per-device miss latency would remove this parameter.
* **Peeking cost and races.** Each eviction from S peeks at both queue heads
  (two short list iterations under the read lock); concurrent evictions may
  see slightly stale heads.
* **Untracked folios.** Folios cached before the policy was attached are not
  on its lists and are reclaimed by the kernel's fallback path.

## References

[1] T. Zussman, I. Zarkadas, J. Carin, A. Cheng, H. Franke, J. Pfefferle,
A. Cidon. *cache_ext: Customizing the Page Cache with eBPF.* SOSP '25,
pp. 462–478. https://doi.org/10.1145/3731569.3764820

[2] J. Yang, Y. Zhang, Z. Qiu, Y. Yue, K. V. Rashmi. *FIFO Queues are All You
Need for Cache Eviction.* SOSP '23.

[3] B. C. Forney, A. C. Arpaci-Dusseau, R. H. Arpaci-Dusseau. *Storage-Aware
Caching: Revisiting Caching for Heterogeneous Storage Systems.* FAST '02,
pp. 61–74.

[4] T. Johnson, D. Shasha. *2Q: A Low Overhead High Performance Buffer
Management Replacement Algorithm.* VLDB '94.

[5] J. Yang, Z. Qiu, Y. Zhang, Y. Yue, K. V. Rashmi. *FIFO can be Better than
LRU: the Power of Lazy Promotion and Quick Demotion.* HotOS '23.

[6] F. J. Corbató. *A Paging Experiment with the Multics System.* In
H. Feshbach and K. U. Ingard (eds.), *In Honor of Philip M. Morse*, MIT Press,
1969.

[7] TechCompare. *SSD vs HDD: The 100x Latency Gap That Changed Computing.*
2026. https://www.techcompare.app/latency-visualizer/ssd-vs-hdd-speed

[8] N. Young. *The k-Server Dual and Loose Competitiveness for Paging.*
Algorithmica 11(6), 1994.

[9] P. Cao, S. Irani. *Cost-Aware WWW Proxy Caching Algorithms.* USITS '97.

[10] A. Blankstein, S. Sen, M. J. Freedman. *Hyperbolic Caching: Flexible
Caching for Web Applications.* USENIX ATC '17, pp. 499–511.
