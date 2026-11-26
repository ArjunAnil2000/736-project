---
title: Two-device page-cache workload (fio)
author: Sayali Kulkarni
---

# What this is

`hetero_fio.py` runs one fio job over **two files**: `hetero_fast.dat` on the
fast device and `hetero_slow.dat` on the dm-delay (slow) device. Every 4 KB read
picks one of the two files at random (50/50) and a zipf-skewed block in it
(`zipf:0.9:0`: one hot set shared by all threads). The job runs inside a single
cgroup v2 whose `memory.max` is smaller than both files together, so the
cgroup's eviction policy (the kernel default, MGLRU, or a cache_ext policy) has
to choose between fast and slow pages.

`plot_hetero_fio.py` turns the results into a CSV summary and three charts.

# Setup on the node

Needs the cache_ext kernel and the partitions from `../setup/README.md`
(fast partition on `/mnt/fast`, dm-delay device on `/mnt/slow`).

```bash
sudo apt-get install -y fio python3-matplotlib tmux
```

Check the slow side really goes through the delay device:

```bash
findmnt /mnt/slow        # SOURCE should be /dev/mapper/...
sudo dmsetup table       # should show a "delay" target
```

Build the cache_ext policies (only needed for policy runs):

```bash
cd ~/736-project/proj-files/cache_ext && ./build_policies.sh
ls policies/*.out
```

# Running

Run inside tmux (`tmux new -s runs`): a full sweep takes ~14 minutes per policy.
The node must be otherwise idle, because `/proc/diskstats` counts every process.

```bash
cd ~/736-project/proj-files/scripts/workloads
PD=~/736-project/proj-files/cache_ext/policies
Q="--fast-dir /mnt/fast --slow-dir /mnt/slow --file-size 512M --cgroup-sizes 64M,128M,256M --iterations 1 --warmup 240 --runtime 30 --numjobs 8 --watch-dir /mnt"

# baselines (no eBPF policy)
sudo python3 hetero_fio.py $Q --label default --mglru off
sudo python3 hetero_fio.py $Q --label mglru   --mglru on

# a cache_ext policy (MGLRU must be off)
sudo python3 hetero_fio.py $Q --label mru --mglru off --policy-loader $PD/cache_ext_mru.out

# charts + summary (list only the labels you want, in plot order)
sudo chown -R $USER results
python3 plot_hetero_fio.py results/hetero_fio.jsonl --labels default,mglru,mru
```

The sizes above are for the 2 GB-RAM node (two 512 MB files, cache 1/16 to 1/4
of the data). On a bigger node scale `--file-size` and `--cgroup-sizes` together,
and keep the warmup long enough to replace the whole cache at least once
(roughly `cgroup pages / misses per second`).

# What one data point does

1. Drop the page cache.
2. Create the cgroup and set `memory.max`.
3. Start the policy loader (if any) and wait 10 s. Its stdin is a pipe: cache_ext
   loaders exit on any keypress.
4. **Prefill**: read `memory.max` worth of data sequentially (1 MB reads),
   alternating 8 MB chunks between the two files, so the cache is full and
   evicting immediately without favouring either file.
5. **Warmup** (`--warmup`, not measured): the real workload, so the cache ends up
   holding what the policy chooses rather than what the prefill loaded.
6. **Measure** (`--runtime`): counters are read before and after; the difference
   is the result.
7. Record how much of each file is cached, unload the policy, delete the cgroup,
   append one JSON line to `results/hetero_fio.jsonl`.

# What gets recorded (one JSON line per run)

| field | source |
|---|---|
| `fio.iops`, `fio.lat_p50/p99/p999_us` | fio JSON output |
| `devices.{fast,slow}.reads`, `read_bytes`, `avg_read_ms` | `/proc/diskstats` delta for the partition / dm device (= page-cache misses per device) |
| `devices.{fast,slow}.resident_bytes` | `mincore` on each file after the run |
| `cgroup_used_bytes.start` | `memory.current` when measurement starts ("cgroup full" in the output) |
| `psi_us.io`, `psi_us.memory` | cgroup `io.pressure` / `memory.pressure` delta |
| `memory_stat_delta.workingset_refault_file` etc. | cgroup `memory.stat` delta |
| `cgroup_name` | which cgroup the run used (only present in runs after the naming fix) |

Sanity checks worth looking at:

* **cgroup full** should be ~85-100%; lower means the cache was not evicting.
* `read_bytes / reads` should be 4096: one page per miss, i.e. no readahead.
* Default and MGLRU should cache the two files about equally (50/50).
* **Hits = fio reads - disk reads.** The disk is saturated (~340 misses/s on the
  2 GB node), so IOPS mostly tracks the hit rate.
* fast + slow disk read time adds up to about `numjobs x runtime` for every
  policy (the threads are always waiting on the disk), so compare policies by
  IOPS and hits, not by total wait time.

# Charts (`plot_hetero_fio.py`)

* `hetero_fio_policies.png`: IOPS per policy (change vs the first label) and
  the share of cached pages that belong to the slow file. The main chart.
* `hetero_fio.png`: throughput, p99 latency, disk time per device, and % of
  each file cached.
* `hetero_fio_wait.png`: disk read time per device for the first label.

# Gotchas (each of these cost us a run)

* **The cgroup name must start with `cache_ext`.** The cache_ext kernel only
  enables policy hooks for cgroups with that prefix (`mem_cgroup_css_online` in
  `mm/memcontrol.c`). Elsewhere the loader attaches and `init` runs, but
  `folio_added` / `folio_accessed` / `evict_folios` are never called, so the
  kernel's default eviction does everything and results match the default.
  The script uses `cache_ext_hetero` with `--policy-loader` and
  `baseline_hetero` otherwise, and refuses other names with a policy.
* **Check a policy is really running**: `sudo sysctl -w kernel.bpf_stats_enabled=1`,
  then during warmup `sudo bpftool prog show | grep -A1 <policy>_`. Every hook
  should show a `run_cnt`. Turn stats off afterwards.
* **Policy name clash**: Aidan's policy in `../../policies/LRU_test/` is named
  `cache_ext_fifo`, the same as cache_ext's FIFO. Build it under another name:
  ```bash
  cd ~/736-project/proj-files/cache_ext/policies
  cp ../../policies/LRU_test/cache_ext_fifo.bpf.c cache_ext_hetero_lru.bpf.c
  sed 's/cache_ext_fifo/cache_ext_hetero_lru/g' ../../policies/LRU_test/cache_ext_fifo.c > cache_ext_hetero_lru.c
  make cache_ext_hetero_lru.out
  ```
  Its fast/slow device numbers are hard-coded; check them with `lsblk` on a new node.
* **Leftover IDE backends** (e.g. a CLion remote session) can eat most of the
  node's RAM and make it swap. Check `free -m` and `vmstat 1 5` (si/so ~0) first.
* Files in `results/` are written by root (the benchmark runs under sudo):
  `sudo chown -R $USER results` before plotting.
* cache_ext policies leaked from runs with the wrong cgroup name stay
  registered (`sudo bpftool struct_ops list`) until the node reboots.

# Results so far (2 GB node, 1 iteration per point)

| memory.max | default IOPS | MGLRU IOPS | 75% LRU (`hetero_lru_v2`) IOPS | slow-file share of cache (75% LRU) |
|---|---|---|---|---|
| 64 MB | 683 | 723 | 517 (-24%) | 98% |
| 128 MB | 901 | 911 | 647 (-28%) | 99% |
| 256 MB | 1255 | 1245 | 1205 (-4%) | 81% |

Default and MGLRU split the cache 50/50 between the devices. Measured read
latency: fast ~18 ms, slow ~29 ms (both partitions share one disk, so the gap is
only ~1.6x). The 75% policy gives the slow file almost all of the cache, evicts
the fast file's hot pages, and loses about half its hits at 64-128 MB.
Runs of the 75% policy from before the cgroup-name fix were dropped from
`results/hetero_fio.jsonl`; `mru_check` is the 64 MB MRU sanity run (365 IOPS).
