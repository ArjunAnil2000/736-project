# Device-Aware Multi-Gen LRU

A device-aware variant of the Multi-Gen LRU (MGLRU) eviction policy, built on
`cache_ext`'s eBPF port of MGLRU. Every folio is tagged with the device its
file lives on, and folios from the slow device start their life in the page
cache one generation younger than MGLRU would place them, so they survive one
more aging cycle before they can be evicted.

Files: `cache_ext_mglru.bpf.c` (eBPF policy), `cache_ext_mglru.c` (loader),
and `base_policy_mglru.{bpf.c,c}`, an unmodified, unbuilt copy of the upstream
policy it is based on, for comparison.

## Background

Page-cache eviction in Linux is driven by recency and frequency: pages that
were used recently or often are kept, the rest are reclaimed [4, 5]. None of
the kernel's policies consider *where* a page would have to be re-read from.
On a host with both an SSD and an HDD, a 4 KiB random read costs roughly
0.1 ms on the SSD and several milliseconds on the HDD [6], so two misses can
differ in cost by one to two orders of magnitude. Minimizing the number of
misses is then no longer the same as minimizing the time applications wait on
I/O. Forney et al. argued for storage-aware caching on exactly these grounds
and showed in simulation that accounting for per-device cost reduces total
wait time [2]; TMO, which sizes memory offloading by its measured
performance impact, shows the same dependence on the offload device in
production [3].

`cache_ext` [1] exposes page-cache eviction to eBPF through `struct_ops`
hooks that a policy implements per memory cgroup (`folio_added`,
`folio_accessed`, `folio_evicted`, `evict_folios`), with kernel-managed folio
lists that the policy can populate and scan. Its authors re-implemented
several kernel and research policies on this interface, including MGLRU,
which makes MGLRU a natural starting point: it is a strong recency/frequency
baseline that ships with recent kernels (it is a build- and run-time option,
not the upstream default, and is enabled by several distributions) [4].

## Existing policy

MGLRU [4, 5] replaces the kernel's two-list (active/inactive) LRU with a
small number of *generations*. Each generation is identified by a sequence
number; `max_seq` is the youngest generation and `min_seq` the oldest. The
`cache_ext` port keeps a ring of four generation lists (three or four in use),
each a `cache_ext` list, and per-folio metadata `{accesses, gen}` in a BPF
hash map.

* **Insertion.** A new folio is placed by how likely it is to be reused: in
  the youngest generation if it is active, the second-youngest if it is dirty
  and being reclaimed, and otherwise in one of the two oldest generations
  (`min_seq` or `min_seq + 1`).
* **Access.** A file access only increments the folio's access count;
  folios do not move between lists on access. The count maps to a *tier*
  (roughly `log2(accesses)`), which is what makes MGLRU frequency-aware
  without per-access list operations.
* **Aging.** A new, empty youngest generation is created (`max_seq` is
  incremented) when fewer than three generations exist or, with exactly
  three, when the oldest holds less than a quarter of the pages outside the
  youngest generation (the port leaves the youngest generation out of this
  test; the kernel counts it). `min_seq` advances once the oldest generation
  holds at most four pages.
* **Eviction.** Only the oldest generation is scanned. A folio whose tier is
  above a *protection threshold* is promoted to the next generation instead of
  being evicted; dirty, locked or under-writeback folios are also moved on;
  everything else is evicted.
* **Feedback.** Evicted folios leave *ghost* entries (keyed by file and
  offset) so that later refaults can be detected. A proportional-integral
  controller compares the refault rate of each tier against that of tier 0 and
  chooses the protection threshold: the first tier that refaults more than
  twice as often as tier 0 (with at least 64 refaults), and every tier above
  it, are protected [5]. The port never resets a folio's access count when it
  protects it, so protection does not decay as it does in the kernel.

## Modifications made

### Implemented

Six changes relative to `cache_ext_mglru` (`base_policy_mglru.bpf.c`): two
device-aware changes and four fixes to the port.

1. **Device tagging.** When a folio is added, the policy reads the device of
   its file from the superblock (`folio->mapping->host->i_sb->s_dev`) and
   looks it up in `dev_idx_map`, which the loader fills by calling `stat()` on
   the fast and slow mount points (default `/mnt/fast`, `/mnt/slow`). The
   resulting index (`DEV_FAST` or `DEV_SLOW`) is stored in the folio's
   metadata (`folio_metadata.dev_idx`) and never recomputed, since a folio's
   device cannot change. Folios on other devices are not tracked and are left
   to the kernel's default reclaim. This replaces `cache_ext`'s directory
   watch-list, which identifies files by inode number alone and therefore
   cannot distinguish two files that share an inode number on different
   filesystems.
2. **Younger insertion for slow folios (`SLOW_GEN_BOOST`).** After MGLRU
   chooses a folio's starting generation, a slow-device folio is moved
   `SLOW_GEN_BOOST` (default 1) generations younger, capped at `max_seq`:

   ```c
   if (dev_idx == DEV_SLOW) {
       seq += SLOW_GEN_BOOST;
       if (seq > max_seq)
           seq = max_seq;
   }
   ```

   Because eviction only ever scans the oldest generation, a slow folio must
   age through at least one more generation before it becomes an eviction
   candidate, i.e. it gets roughly one extra aging cycle in which to be
   re-accessed and earn protection through its tier. Fast folios are placed
   exactly as in MGLRU. `SLOW_GEN_BOOST = 0` restores MGLRU's placement for
   both devices.
3. **Fix: insertion order.** The port added folios at the head of a
   generation and scanned from the head, so the newest folios were evicted
   first, and folios whose read was still in flight (locked) were moved to
   the next generation as if protected; since HDD reads stay in flight about
   75x longer, this alone kept more HDD folios. Folios are now added at the
   tail, so each generation is evicted oldest-first, as in the kernel.
4. **Fix: tier baseline.** In `cache_ext` the read that causes a miss also
   calls `folio_accessed`. The port started the count at 1 and used
   `floor(log2(accesses))`, so every folio was in tier 1 after its miss read
   and tier 0 never had any evictions or refaults; the controller's reference
   rate was a constant. The count now starts at 0 and the tier is
   `ceil(log2(accesses))`, which matches the kernel's `order_base_2(refs + 1)`
   for `refs` re-accesses.
5. **Fix: a per-call eviction budget** (`common/hetero_iter.bpf.h`). The
   kernel's list iterator selects victims until its 32-entry array is full,
   whatever the kernel asked for, and the kernel reclaims all of them; the
   port therefore evicted about 4x more folios than requested. The scan now
   stops once the request is met. Victims are moved to the tail of the list
   being scanned, so each folio also records the eviction call that chose it,
   and a scan that wraps around stops when it reaches one. When the first
   scan falls short and a second scan runs on a different generation, the
   per-generation page counts are updated against the generation actually
   scanned.

6. **Fix: retire an empty oldest generation.** The port advances `min_seq`
   only when the oldest generation's page *counter* is at most 4, and with
   all four generations in use `max_seq` cannot advance until `min_seq` does.
   The counter can drift from the list's contents, and a stale count of 5 or
   more on an empty oldest list then stalls eviction for good: every call
   scans that empty list, comes up short, and the kernel's default reclaim
   evicts the rest. One boost-1 run did this (the policy supplied 40% of the
   requested victims, none from the slow device). If a scan of the oldest
   generation visits no folio at all, the policy now advances `min_seq`
   regardless of the counter and resets the stale count, as the kernel does
   (it checks the list itself). This only acts in calls that already found
   nothing to evict, and it has not yet been observed firing: the six runs
   made after adding it did not stall (see the `debug_forced_min_seq`
   counter in `mglru_global_metadata_map` with `make debug`).

Fixes 3–6 apply with or without the boost, so `SLOW_GEN_BOOST = 0` is a
corrected MGLRU port rather than the upstream one. The `debug_*` validation
counters (see `common/hetero_debug.bpf.h`) are compiled in only with
`make debug`; they never change the policy's decisions.

Build with `make` in `proj-files/policies/`; run with
`sudo ./cache_ext_mglru.out --cgroup_path /sys/fs/cgroup/<cgroup>` (the
kernel's own MGLRU must be disabled, and the cgroup name must start with
`cache_ext`). `SLOW_GEN_BOOST` can be set at build time with
`-DSLOW_GEN_BOOST=N`. On a host with more than one NUMA node, bind the
workload to node 0 (e.g. `numactl --cpunodebind=0 --membind=0`): the
`cache_ext` kernel registers a policy's lists on node 0 but looks them up by
the NUMA node of each folio, so page cache allocated on another node can never
be added to a list. With `make debug`, the validation counters can be read
with `sudo bpftool map dump name debug_map`.

### Future work (not yet implemented)

* **Protect slow folios during the eviction scan.** Insertion is the only
  point at which (2) treats slow folios differently; once a slow folio
  reaches the oldest generation it competes on equal terms. Lowering the
  protection threshold for slow folios in the scan (e.g. protecting at
  `tier >= threshold` instead of `tier > threshold`), or granting them a
  single second chance, would extend the bias over their whole lifetime.
* **Cost-weighted refault feedback.** MGLRU's controller balances the *number*
  of refaults across tiers. Recording the device in each ghost entry and
  weighting each refault (and eviction) by the measured miss cost of its
  device would make the controller balance *time lost to refaults* instead,
  which is the quantity storage-aware caching aims to minimize [2]. The
  per-device costs would come from profiling the devices.
* **Per-device tiers.** Keeping separate refault statistics and a separate
  protection threshold per device is the MGLRU analogue of Forney et al.'s
  per-device cache partitions [2]: each device's folios would be protected
  according to their own reuse behaviour and miss cost.

## Expected behaviour

* **A one-time head start for slow folios.** Slow folios that are re-accessed
  within one extra aging cycle are promoted by tier and retained; slow folios
  that are never reused are still evicted, only later. Compared with MGLRU,
  more slow folios and fewer fast folios should be resident, and the miss
  mix should shift towards the cheaper device.
* **Scan resistance is preserved.** The boost does not make a single-use
  slow folio look hot: it delays its eviction by one generation but does not
  raise its tier.
* **Interaction with aging.** The aging test counts the pages in the oldest
  generation (outside the youngest). Moving slow folios out of the oldest
  generation shrinks that count, so the boost makes aging *more* frequent.
* **Bias-off ablation.** With `SLOW_GEN_BOOST = 0` both devices are placed as
  in the (corrected) port. Both mount points cannot be on one device: the
  loader refuses that, since their folios could not be told apart.

On a host with a real SSD and HDD (CloudLab c220g5; 4 KiB random reads at
queue depth 1 take 0.16 ms and 3.8 ms), with two 1 GiB files read with zipf
0.9 by 8 threads in a 128 MiB cgroup (three repeats), the boost raises
throughput by 1.6% over its own bias-off setting (2111 vs 2079 IOPS) and keeps
slightly more HDD pages cached (53% vs 50%). Both settings are below the
kernel's default policy (2182 IOPS). In this workload generations turn over
slowly (a few per run): new folios keep entering the oldest generation while
only three exist, so it seldom drains, and MGLRU behaves largely as a FIFO
over the oldest generation with tier protection.

## Limitations

* **The bias does not scale with the cost gap.** The boost is a fixed number
  of generations; it gives the same advantage whether the slow device is
  1.5× or 50× slower. The future-work items above tie the bias to measured
  costs.
* **Coarse granularity.** With at most four generations (three or four in
  use), a boost of one generation is a large step, and a boost of two or more
  always places slow folios in the youngest generation, which makes every new
  slow folio look as young as freshly protected data.
* **Depends on generation turnover.** The boost buys time only if
  generations advance. When they turn over slowly, boosted slow folios can
  wait in a younger generation for a long time before the scan reaches them.
* **Protection never decays.** The port never resets a folio's access count
  when it protects it, so a slow folio that reaches a protected tier during its
  boosted window stays protected while the threshold allows.
* **Insertion-time only.** See the first future-work item.
* **Untracked folios.** Folios cached before the policy was attached are not
  on the policy's lists and are reclaimed by the kernel's fallback path.
* **Two devices only.** The device index generalizes to more devices, but
  the boost would then need a per-device value.

## References

[1] T. Zussman, I. Zarkadas, J. Carin, A. Cheng, H. Franke, J. Pfefferle,
A. Cidon. *cache_ext: Customizing the Page Cache with eBPF.* SOSP '25,
pp. 462–478. https://doi.org/10.1145/3731569.3764820

[2] B. C. Forney, A. C. Arpaci-Dusseau, R. H. Arpaci-Dusseau. *Storage-Aware
Caching: Revisiting Caching for Heterogeneous Storage Systems.* FAST '02,
pp. 61–74.

[3] J. Weiner, N. Agarwal, D. Schatzberg, L. Yang, H. Wang, B. Sanouillet,
B. Sharma, T. Heo, M. Jain, C. Tang, D. Skarlatos. *TMO: Transparent Memory
Offloading in Datacenters.* ASPLOS '22, pp. 609–621.
https://doi.org/10.1145/3503222.3507731

[4] Linux kernel documentation. *Multi-Gen LRU.*
https://docs.kernel.org/mm/multigen_lru.html

[5] Linux kernel documentation. *Multi-Gen LRU (admin guide).*
https://docs.kernel.org/admin-guide/mm/multigen_lru.html

[6] TechCompare. *SSD vs HDD: The 100x Latency Gap That Changed Computing.*
2026. https://www.techcompare.app/latency-visualizer/ssd-vs-hdd-speed
