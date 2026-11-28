# Device-Partitioned LRU with Biased Eviction

A two-list LRU page-cache policy for `cache_ext` that keeps one LRU list per
storage device and, on each eviction, evicts from the fast device's list
first with a fixed probability (75%). It is the simplest way to make the page
cache prefer losing pages whose misses are cheap, and it serves as the
baseline device-aware policy against which the other candidates are compared.

Files: `cache_ext_fifo.bpf.c` (eBPF policy), `cache_ext_fifo.c` (loader),
and `base_policy_fifo.{bpf.c,c}`, an unmodified, unbuilt copy of the upstream
policy it is based on, for comparison.
The `fifo` names are historical: the policy started from `cache_ext`'s FIFO
example, but with move-to-tail on access it is an LRU.

## Background

The Linux page cache decides which file pages to keep in memory using recency
and frequency alone. The classic implementation keeps an active and an
inactive list per memory cgroup [5]; the newer Multi-Gen LRU (MGLRU) keeps
several generations [6]. Both treat every page as equally expensive to lose:
the goal is implicitly to minimize the *number* of misses (the hit ratio).
When all pages live on the same kind of device, minimizing misses also
minimizes the time applications spend waiting on I/O.

That equivalence breaks on a host whose files are spread over devices with
different performance, such as an SSD and an HDD. A 4 KiB random read takes on
the order of 0.1 ms on a SATA SSD and several milliseconds on a 7.2K–10K RPM
HDD [7], so a miss on an HDD-backed page can cost tens of times more than a
miss on an SSD-backed one. A policy that minimizes misses will routinely trade
a cheap SSD miss for an expensive HDD miss. Forney et al. made this
observation for storage-aware caching in 2002 and showed, in simulation, that
caches which account for per-device cost reduce total I/O wait [2]; Meta's TMO
sizes how much memory to offload by measuring its performance impact, which
depends on the offload device [3].

`cache_ext` [1] makes it possible to test such policies in the real kernel:
it exposes the page cache's eviction decisions as eBPF `struct_ops` hooks
(`folio_added`, `folio_accessed`, `folio_evicted`, `evict_folios`) that a
policy implements per memory cgroup, with kernel-managed lists of folios the
policy can add to, move within and scan.

## Existing policy

LRU itself is the oldest recency policy: on every access a page moves to the
most-recently-used end of a list, and the victim is taken from the other end
[4]. `cache_ext` ships a FIFO example policy (`cache_ext_fifo`) that keeps a
single list: folios are appended on insertion and the eviction callback walks
the list from its head, selecting every folio that is up to date, on the LRU,
clean and not under writeback. The FIFO example ignores accesses, so it is
insertion-ordered.

## Modifications made

Five changes relative to `cache_ext_fifo` (`base_policy_fifo.bpf.c`):

1. **Folios are tracked by device.** Upstream tracks the files under a
   `--watch_dir`, by inode number only, so it cannot distinguish files on two
   filesystems. Here a folio's device is read from its file's superblock,
   `folio->mapping->host->i_sb->s_dev`, and looked up in a map
   (`dev_idx_map`) that the loader fills by calling `stat()` on the fast and
   slow mount points (default `/mnt/fast` and `/mnt/slow`; see `common/`).
   The device numbers are therefore not hard-coded and the policy works
   unchanged across nodes whose disks enumerate differently. Folios on any
   other device are not tracked and are left to the kernel's default reclaim.
2. **Per-device lists.** The policy creates two `cache_ext` lists, `fast_list`
   and `slow_list`, instead of one. On `folio_added`, a folio is appended to
   the list of the device its file lives on.
3. **LRU order.** On `folio_accessed` (a hook upstream does not implement),
   the folio is moved to the tail of its list
   (`bpf_cache_ext_list_move(..., tail=true)`), turning each FIFO list into an
   LRU list. Eviction scans from the head, so the least recently used folio of
   the chosen list goes first.
4. **Biased choice of victim list.** On each `evict_folios` call the policy
   draws a random number and, with probability 3/4, scans `fast_list` first,
   otherwise `slow_list` first:

   ```c
   bool prefer_fast = (bpf_get_prandom_u32() & 3U) != 0;   // true 75% of the time
   ```

   If the first list cannot supply as many evictable folios as the kernel
   requested, the remainder comes from the other list.
5. **Fix: victims capped at the request.** The kernel's list iterator selects
   victims until its 32-entry array is full, whatever the kernel asked for,
   and the kernel reclaims all of them. Upstream returns them all; here the
   number of victims returned is capped at the kernel's request.

The `debug_*` validation counters (see `common/hetero_debug.bpf.h`) are
compiled in only with `make debug`; they never change the policy's decisions.

Build with `make` in `proj-files/policies/`; run with
`sudo ./cache_ext_fifo.out --cgroup_path /sys/fs/cgroup/<cgroup>` (MGLRU must
be disabled, and the cgroup name must start with `cache_ext`). On a host with
more than one NUMA node, bind the workload to node 0 (e.g. `numactl
--cpunodebind=0 --membind=0`): the `cache_ext` kernel registers a policy's
lists on node 0 but looks them up by the NUMA node of each folio, so page cache
allocated on another node can never be added to a list. With `make debug`,
the validation counters can be read while the policy is loaded with
`sudo bpftool map dump name debug_map`.

## Expected behaviour

* **Slow folios survive longer.** Three out of four eviction batches come from
  the fast list, so in steady state the cache holds proportionally more
  slow-device folios than a device-oblivious LRU would. Hits move from the
  fast device to the slow device.
* **Whether this helps depends on the cost ratio.** The benefit is the slow
  misses avoided times their cost, minus the extra fast misses times theirs.
  The 75% bias is fixed, so it is right for only one particular ratio of
  device costs and working-set split; with a small cost gap it over-protects
  slow folios and total I/O wait can *increase*.
* **Bias-off ablation.** Setting the probability to 1/2 removes the bias, but
  the policy is then two independent per-device LRUs, not one global LRU. (Both
  lists cannot be placed on the same device: the loader refuses two mount points
  on one device, since their folios could not be told apart.)

> **Old host (superseded).** This run was on the earlier test node, before
> the real SSD + HDD host below was used.
>
> A preliminary toy run (two 512 MiB files, one per device, zipf-skewed 4 KiB
> random reads, the slow device emulated with `dm-delay` on the same disk,
> cgroups of 64–256 MiB) illustrates the cost-ratio point. Compared with the
> kernel default and MGLRU, this policy cached far more of the slow file
> (5–35% vs 3–22%) and almost none of the fast file (≤ 8% vs 3–22%), but
> delivered *lower* throughput at the two smaller cache sizes (517 vs 683–723
> IOPS at 64 MiB, 647 vs 901–911 at 128 MiB) and similar throughput at 256
> MiB. Under the default policy, the measured per-read cost gap in that setup
> was only about 1.6× (≈ 18 ms vs ≈ 29 ms under load), too small to repay a
> 3:1 bias. These numbers are from a single exploratory iteration and are not
> an evaluation.

On a host with a real SSD and HDD (CloudLab c220g5: Intel S3510 SATA SSD and
10K RPM SAS HDD; 4 KiB random reads at queue depth 1 take 0.16 ms and 3.8 ms,
a 23.7x gap), the same kind of workload (two 1 GiB files, zipf 0.9, 8 threads,
128 MiB cgroup, three repeats) gives the opposite result: the policy keeps
99.7% HDD-backed pages in the cache and raises throughput by 6.3% over the
kernel's default policy (2320 vs 2182 IOPS). With a large cost gap, trading
cheap SSD misses for expensive HDD misses pays off, even with a fixed bias.

## Limitations

* **The bias is not derived from device costs.** 75% is a constant; nothing
  ties it to measured latencies or to the working set on each device. The
  other candidate policies (S4-FIFO, five-minute rule) replace it with a
  parameter derived from profiling.
* **Batch-level, not page-level, choice.** The coin is flipped once per
  eviction call, and a call can select up to 32 folios, so each batch comes
  entirely from one list. Over many calls the split approaches 75/25 only if
  both lists always have enough evictable folios.
* **No frequency or scan resistance.** As an LRU it is vulnerable to large
  sequential scans, which flush both lists.
* **Folios cached before the policy was attached** are not on either list until
  their next access, which moves (and so adopts) them onto their device's list;
  until then they can only be reclaimed by the kernel's fallback path.
* **Two devices only.** The design generalizes to N lists, but the eviction
  rule would need a principled way to choose among them.

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

[4] L. A. Belady. *A Study of Replacement Algorithms for a Virtual-Storage
Computer.* IBM Systems Journal 5(2), 1966.

[5] M. Gorman. *Understanding the Linux Virtual Memory Manager.* Prentice
Hall, 2004. Chapter 10, "Page Frame Reclamation".

[6] Linux kernel documentation. *Multi-Gen LRU.*
https://docs.kernel.org/mm/multigen_lru.html

[7] TechCompare. *SSD vs HDD: The 100x Latency Gap That Changed Computing.*
2026. https://www.techcompare.app/latency-visualizer/ssd-vs-hdd-speed
