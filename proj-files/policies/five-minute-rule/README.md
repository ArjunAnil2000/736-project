# Five-Minute-Rule Eviction with Per-Device Break-Even Intervals

A page-cache policy that evicts the folio furthest past its device's
*break-even interval*: the time beyond which keeping an idle page in memory
costs more than re-reading it from its device would. Each device gets its own
break-even interval, derived by profiling the device, so a folio on a slow
device may stay idle proportionally longer before it becomes the preferred
victim.

Files: `cache_ext_fmr.bpf.c` (eBPF policy), `cache_ext_fmr.c` (loader),
`fmr_stats.h` (per-device counters), `profile_devices.sh` (device profiling).

## Background

Gray and Putzolu's *five-minute rule* [2] answers the question "how long
should a page stay in memory?" by comparing the cost of the memory that holds
it with the cost of the disk accesses it saves. A page re-referenced every
*T* seconds saves 1/*T* disk accesses per second; keeping it is worthwhile
while that saving is worth more than the memory it occupies. In the form used
since the rule's ten-year revisit [3], the break-even reference interval is

```
BEI = (pages per MB of RAM / accesses per second per disk)
      × (price per disk drive / price per MB of RAM)
```

With 1987 prices and 1 KB pages this came to about five minutes, giving the
rule its name: keep a page in memory if it is referenced at least every five
minutes. The rule has been revisited as technology changed: ten years later
for larger pages and cheaper RAM [3], twenty years later with flash as an
intermediate tier [4], and thirty years later for the modern storage
hierarchy [5]. Each revision recomputes the interval for a *pair* of
technologies (memory and one storage device), and the interval differs
substantially between device types, because both their access rates and their
prices differ.

That makes the rule a natural basis for storage-aware caching. On a host with
an SSD and an HDD, the two devices have very different random-read rates
(≈ 0.1 ms vs several ms per 4 KiB read [9]), so their break-even intervals
differ too: an HDD-backed page earns its memory over a much longer idle
period than an SSD-backed one. Forney et al. showed that page caches which
account for such per-device cost differences reduce total I/O wait [6].
`cache_ext` [1] makes it possible to deploy such a policy in the Linux kernel:
eviction is exposed as eBPF `struct_ops` hooks per memory cgroup, and the
policy manages kernel-maintained lists of folios.

This five minute rule has since been reincarnated in modern literature in
various forms -- "The five-minute rule revisited after 10 years" -- and so on.

## Existing policy

The policy is built on `cache_ext`'s *sampling* policy (`cache_ext_sampling`).
It keeps a single `cache_ext` list of all tracked folios and per-folio
metadata in a BPF hash map. To evict, it calls
`bpf_cache_ext_list_sample`, which takes `request × n` folios from the head of
the list (n = 20), splits them into groups of n, and evicts the folio with the
lowest *score* in each group; the sampled folios are then returned to the tail
of the list. Upstream, the score is the folio's access count, which makes the
policy a sampled LFU. Sampled eviction approximates a global ranking at a
fraction of its cost and is a well-established technique [7]; it lets a
policy rank folios by an arbitrary function without maintaining a sorted
structure. Note that `cache_ext`'s sampler does not draw folios at random, as
the analysed schemes do: each group is a window of *consecutive* folios at the
list head, and the head sweeps the list like a clock hand.

## Modifications made

1. **Score: normalized idle time.** Each folio records the time of its
   insertion and then of each re-access. (In `cache_ext` the read that caused
   the miss also calls `folio_accessed`, but only when its I/O completes,
   about 11 ms later on the HDD than on the SSD; since a window's 20 folios
   are inserted within a few tens of milliseconds of each other, stamping
   that time made new HDD folios look younger than SSD folios inserted at the
   same moment and skewed the equal-BEI baseline to about 58% HDD pages. That
   first call is therefore ignored.) The score is

   ```
   overdue(f) = (now − last_access(f)) / BEI[device(f)]
   ```

   in fixed point, and the most overdue folio in each sample is evicted (the
   score function returns its negation, since the sampler evicts the minimum).
   Folios that cannot be evicted right now (dirty, under writeback, not up to
   date or not on the kernel's LRU) score `INT64_MAX` and are kept.
2. **Per-device break-even intervals.** `BEI[FAST]` and `BEI[SLOW]` are set
   by the loader (`--fast_bei_ms`, `--slow_bei_ms`). `profile_devices.sh`
   measures each device with a 4 KiB random-read `fio` job at queue depth 1
   (the cost of one page-cache miss) and suggests values in two ways:
   * **time-based:** `BEI[SLOW] = BEI[FAST] × (latency_slow / latency_fast)`,
     i.e. a slow folio may stay idle as many times longer as its re-read is
     slower;
   * **economic:** Gray and Putzolu's formula above, using the measured access
     rates and user-supplied prices for RAM and each device.
3. **From an admission rule to an ordering.** The original rule says whether a
   page *should* be cached. A page cache with a fixed memory budget must evict
   something whenever it is full, even if every resident page is within its
   break-even interval, so the policy uses the rule as an ordering: evict the
   folio that is furthest past (or closest to) its break-even point. Two
   consequences follow. First, with equal intervals the policy evicts the least
   recently used folio of each window of consecutive folios, a CLOCK-like
   approximation of LRU that is its built-in, device-oblivious baseline.
   Second, eviction order depends
   only on the *ratio* `BEI[SLOW] / BEI[FAST]`; the absolute values matter
   only for the statistics below and for admission control (see Limitations).
   This ordering is closely related to GreedyDual-style cost-aware
   replacement [8, 10], in which each object is credited with its miss cost
   and credits age uniformly, so costlier objects survive longer idle
   periods.
4. **Short-list fallback.** The sampler needs at least `request × n` folios on
   the list. Below that (e.g. right after the policy is attached) the policy
   evicts evictable folios from the head of the list instead.
5. **Device identification.** A folio's device is read from its file's
   superblock (`folio->mapping->host->i_sb->s_dev`) and looked up in
   `dev_idx_map`, which the loader fills with the device numbers of the fast
   and slow mount points (default `/mnt/fast`, `/mnt/slow`). Folios on other
   devices are not tracked and are left to the kernel's default reclaim.
6. **Per-device statistics.** For each device the loader prints, on exit,
   the number of folios added, re-accesses (the miss read itself is not
   counted), removals, and *removals within the break-even interval*: folios
   that had been idle for less than their device's BEI when they left the
   cache, i.e. evictions the five-minute rule would call premature. Removals
   are counted in `folio_evicted`, which fires for every page-cache removal,
   including truncation and invalidation, not only for the policy's own
   evictions; with absolute (economic) BEIs, this measures how often memory
   pressure forces the policy to violate the rule on each device.

Build with `make` in `proj-files/policies/`; profile and run with

```bash
./profile_devices.sh                     # prints suggested --fast_bei_ms / --slow_bei_ms
sudo ./cache_ext_fmr.out --cgroup_path /sys/fs/cgroup/<cgroup> \
     --fast_bei_ms <ms> --slow_bei_ms <ms>
```

MGLRU must be disabled and the cgroup name must start with `cache_ext`. On a
host with more than one NUMA node, bind the workload to node 0 (e.g. `numactl
--cpunodebind=0 --membind=0`): the `cache_ext` kernel registers a policy's
lists on node 0 but looks them up by the NUMA node of each folio, so page cache
allocated on another node can never be added to a list. Validation counters
(`debug_*`, see `common/hetero_debug.bpf.h`) can be read with
`sudo bpftool map dump name debug_map`.

## Expected behaviour

* **Recency within a device, cost across devices.** Among folios of the same
  device the policy behaves like (sampled) LRU. Across devices, a slow folio
  is evicted ahead of a fast folio only if it has been idle more than
  `BEI[SLOW] / BEI[FAST]` times longer.
* **Proportional rather than fixed bias.** Unlike a fixed probability of
  evicting from the fast device, the bias grows with the measured cost ratio
  and vanishes when the devices are equally fast, so the policy should not
  lose throughput when the cost gap is small.
* **Premature evictions measure memory pressure, not device bias.** Because
  victims on both devices are chosen at roughly the same overdue value, the
  fraction of evictions within the BEI (`evicted_in_bei / evicted`) should be
  similar for both devices; how high it is shows how far the cache is from
  being large enough to satisfy the rule. In absolute time, fast folios are
  evicted after shorter idle periods than slow ones, which is the intended
  trade of cheap misses for expensive ones.
* **Diminishing returns under scans.** A large sequential scan makes every
  scanned folio recent; like LRU, the policy offers no scan resistance.

On a host with a real SSD and HDD (CloudLab c220g5; 4 KiB random reads at
queue depth 1 take 0.16 ms and 3.8 ms, so the time-based BEI ratio is 23.7),
with two 1 GiB files read with zipf 0.9 by 8 threads in a 128 MiB cgroup
(three repeats): with equal BEIs the cache holds 50.1% HDD pages and
throughput is 4.9% below the kernel's default policy (2074 vs 2182 IOPS); with
the measured ratio (1000 ms / 23 704 ms) it holds 81.5% HDD pages and
throughput is 3.4% above the default (8.8% above equal BEIs).

## Limitations

* **Idle time is a one-sample estimate of the reuse interval.** The rule is
  about a page's re-reference interval, but the policy only knows the time
  since the last access. Policies that keep a short access history, such as
  LRU-K [11], estimate the interval more robustly at the cost of more metadata.
* **No admission control yet.** The rule's original use, not caching pages
  whose expected reuse interval exceeds the BEI, is not implemented.
  `cache_ext`'s `admit_folio` hook could implement it, for example for
  streaming reads, and that is where absolute BEI values would matter.
* **Static intervals.** BEIs are fixed at load time from an offline profile;
  device latency under load (queueing, contention, background work) can
  differ. An online per-device latency estimate would remove the parameter.
* **Time-based vs. economic BEI.** The time-based setting optimizes I/O wait
  for a fixed memory budget; the economic setting reflects provisioning
  cost. They can disagree, and the choice should be stated with any result.
  The profile measures IOPS at queue depth 1, which understates an SSD's
  random-read capacity and so inflates its economic BEI; at queue depth 1 the
  economic ratio reduces to the latency ratio times the price ratio.
* **Windows, not random samples.** Devices are compared only within a window
  of consecutive folios, so the realised bias is weaker than the BEI ratio
  when a window holds few folios of the other device, and every window yields
  a victim even if all of its folios are hot.
* **Sampling approximation and overhead.** Eviction quality depends on the
  sample size; every access updates a timestamp in a hash map.
* **Untracked folios.** Folios cached before the policy was attached are not
  on its list and are reclaimed by the kernel's fallback path.

## References

[1] T. Zussman, I. Zarkadas, J. Carin, A. Cheng, H. Franke, J. Pfefferle,
A. Cidon. *cache_ext: Customizing the Page Cache with eBPF.* SOSP '25,
pp. 462–478. https://doi.org/10.1145/3731569.3764820

[2] J. Gray, F. Putzolu. *The 5 Minute Rule for Trading Memory for Disc
Accesses and the 10 Byte Rule for Trading Memory for CPU Time.* SIGMOD '87.

[3] J. Gray, G. Graefe. *The Five-Minute Rule Ten Years Later, and Other
Computer Storage Rules of Thumb.* SIGMOD Record 26(4), 1997.

[4] G. Graefe. *The Five-Minute Rule Twenty Years Later, and How Flash Memory
Changes the Rules.* DaMoN '07.

[5] R. Appuswamy, R. Borovica-Gajic, G. Graefe, A. Ailamaki. *The Five-Minute
Rule Thirty Years Later and its Impact on the Storage Hierarchy.* ADMS '17.

[6] B. C. Forney, A. C. Arpaci-Dusseau, R. H. Arpaci-Dusseau. *Storage-Aware
Caching: Revisiting Caching for Heterogeneous Storage Systems.* FAST '02,
pp. 61–74.

[7] K. Psounis, B. Prabhakar. *A Randomized Web-Cache Replacement Scheme.*
INFOCOM '01.

[8] N. Young. *The k-Server Dual and Loose Competitiveness for Paging.*
Algorithmica 11(6), 1994.

[9] TechCompare. *SSD vs HDD: The 100x Latency Gap That Changed Computing.*
2026. https://www.techcompare.app/latency-visualizer/ssd-vs-hdd-speed

[10] P. Cao, S. Irani. *Cost-Aware WWW Proxy Caching Algorithms.* USITS '97.

[11] E. J. O'Neil, P. E. O'Neil, G. Weikum. *The LRU-K Page Replacement
Algorithm for Database Disk Buffering.* SIGMOD '93.
