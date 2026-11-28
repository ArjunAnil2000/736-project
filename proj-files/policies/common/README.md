> [!NOTE]
> This README is AI generated.
> The code is human written with debugging and suggestions from AI, so still might have bugs.

# Shared headers for the device-aware policies

Code shared by the four policies in this directory: tagging folios by the device
that backs them, a per-call eviction budget, and the `debug_*` validation
counters. Everything here is a header. The Makefile adds `-Icommon` and rebuilds
every policy when any of these files changes.

| File | Side | Used by | Purpose |
|---|---|---|---|
| `hetero_dev_ids.h` | BPF + loader | all | Device indices `DEV_FAST = 0`, `DEV_SLOW = 1`, `MAX_NR_DEVS` |
| `hetero_dev.bpf.h` | BPF | all | `dev_idx_map` and `folio_dev_idx()` |
| `hetero_dev.h` | loader | all | Resolves `--fast_dir` and `--slow_dir` and fills `dev_idx_map` |
| `hetero_iter.bpf.h` | BPF | MGLRU-dev, S4-FIFO | Eviction budget for `bpf_cache_ext_list_iterate_extended()` scans |
| `hetero_debug.bpf.h` | BPF | all | `debug_map` validation counters |

FMR picks victims by sampling (`bpf_cache_ext_list_sample`), not with an
iterator, so it does not need `hetero_iter.bpf.h`.

## Device tagging (`hetero_dev_ids.h`, `hetero_dev.bpf.h`, `hetero_dev.h`)

Policies only ever compare the two indices in `enum folio_device`. The loader
decides which mounted filesystem is fast and which is slow, and tells the BPF
side through `dev_idx_map`:

1. **Resolve.** `hetero_resolve_devs(fast_dir, slow_dir, devs)` runs before the
   BPF object is loaded, so a bad path fails early. It `stat()`s each
   directory and converts `st_dev` into the kernel's `dev_t` encoding,
   `(MAJOR << 20) | MINOR`, which is what the BPF side reads from `sb->s_dev`.
   This is not glibc's userspace `st_dev` encoding. It refuses two directories
   on the same device, because the policy could not tell their folios apart.
   The defaults are `/mnt/fast` and `/mnt/slow`.
2. **Fill.** `hetero_fill_dev_map(map_fd, devs)` writes kernel dev → index into
   `dev_idx_map`, a hash map with 8 entries. It runs after load and before the
   policy is attached.
3. **Look up.** `folio_dev_idx(folio)` walks
   folio → `mapping` → `host` inode → `i_sb` → `s_dev` and looks that up in
   `dev_idx_map`. It returns the index, or −1 if the folio has no mapping or
   is on a device that isn't in the map. Policies ignore untracked folios and
   leave them to the kernel's default reclaim. A folio's device never changes,
   so MGLRU-dev, S4-FIFO and FMR call this once, on insertion, and keep the
   result in their per-folio metadata. The two-list LRU has no per-folio
   metadata and calls it again each time it needs to choose a list.

`hetero_dev.h` also defines `HETERO_WATCH_DIR_OPTION` / `HETERO_WATCH_DIR_KEY`.
The upstream cache_ext loaders take `--watch_dir` and the workload scripts
always pass it. These policies track folios by device, not by directory, so
each loader accepts the option, hides it from `--help`, and ignores it.

## Eviction budget (`hetero_iter.bpf.h`)

The cache_ext iterators keep selecting victims until the 32-entry eviction
array is full or the list ends, whatever the kernel asked for, and the kernel
reclaims every folio it is given. Without a budget, a policy evicts up to 32
folios even when the kernel asked for a handful. Before this header was added,
S4-FIFO over-evicted about 8× and MGLRU-dev about 4.3×. Also,
`iterate_extended()` moves each victim to the tail of the list it is scanning,
so a scan that wraps around reaches the same victims again and would propose
them twice.

`struct iter_call { id, remaining }` lives in a per-CPU array. The scan
callback runs synchronously on the CPU of the `evict_folios` call that started
the scan, so per-CPU state is safe. The API:

| Call | Where | Effect |
|---|---|---|
| `iter_call_begin()` | once per `evict_folios` | Assigns a new, globally unique call id |
| `iter_call_budget(ctx)` | before each scan | `remaining = request_nr_folios_to_evict − nr_folios_to_evict` |
| `iter_call_get()` | in the callback | Returns the current call state |
| `iter_call_take(c, &meta->victim_call)` | when returning `CACHE_EXT_EVICT_NODE` | Stamps the folio with the call id and decrements `remaining` |

In the callback, return `CACHE_EXT_STOP_ITER` when `remaining == 0`. Skip a
folio whose `victim_call` equals `c->id`, because it is already a victim of
this call. Each policy that uses the budget needs a `__u64 victim_call` field
in its per-folio metadata.

## Debug counters (`hetero_debug.bpf.h`)

The counters only observe what the hooks do. They are not part of any policy's
logic, and everything is named `debug_*` so it is easy to find. They are
compiled in only when `HETERO_DEBUG` is defined:

```
make            # default: no debug counters
make debug      # clean rebuild with -DHETERO_DEBUG (same as make clean; make DEBUG=1)
```

Without `HETERO_DEBUG`, every `DEBUG_*` macro and `debug_after_evict()` is a
no-op, `debug_map` and `debug_seen_map` do not exist, and the policies' few
inline debug blocks (and MGLRU-dev's `debug_insert_ns` metadata field) are
removed by `#ifdef HETERO_DEBUG`. Run `make clean` when switching modes: the
objects don't record which mode built them.

Include the header after `hetero_dev.bpf.h`, which supplies `MAX_NR_DEVS` and
`folio_dev_idx()`. With a debug build loaded, read the counters with:

```
sudo bpftool map dump name debug_map
```

`struct debug_counters`, a single-entry array:

| Field | Meaning |
|---|---|
| `debug_added[dev]` / `debug_accessed[dev]` / `debug_evicted[dev]` | `folio_added`, `folio_accessed` and `folio_evicted` calls on tracked folios, per device |
| `debug_proposed[dev]` | Victims returned by `evict_folios`, per device |
| `debug_evict_calls` | `evict_folios` invocations |
| `debug_requested` / `debug_returned` | Sums of `request_nr_folios_to_evict` and `nr_folios_to_evict` |
| `debug_short_calls` | Calls that returned fewer victims than requested |
| `debug_dup_victims` | A folio proposed twice in the same call; this should be 0 |
| `debug_policy[8]` / `debug_aux[8]` | Policy-specific event counts and sums; the slots are listed at the top of each policy's `.bpf.c` |

The helpers:

- `DEBUG_ADD(field, val)`: an atomic add.
- `DEBUG_DEV_INC(field, dev)`: a per-device increment. It ignores `dev < 0`.
- `DEBUG_POLICY_INC(slot)` and `DEBUG_AUX_ADD(slot, val)`: bounds-checked slot
  updates.
- `debug_after_evict(ctx)`: call at the end of `evict_folios`. It records the
  call, request and return totals, short calls, and per-device proposals. It
  detects duplicates through `debug_seen_map`, an LRU hash with 8192 entries
  that maps each folio to the id of the last call that proposed it, because a
  nested loop over the batch exceeded the verifier's limits.

The index masks (`& 1`, `& (DEBUG_NR_POLICY_SLOTS - 1)`) exist so the verifier
can prove the array accesses are in bounds. `& 1` assumes exactly two devices,
so `DEBUG_DEV_INC` needs changing if `MAX_NR_DEVS` grows.

### Sanity checks

The test harness uses a debug build and relies on these checks:

- `sum(debug_added)` is at least about 95% of the disk reads during the run.
  If it is lower, folios are not reaching the policy's lists. On the
  two-socket test host this happened when fio ran on NUMA node 1; see the
  NUMA note in the policy READMEs.
- `debug_returned ≤ debug_requested`, which the budget guarantees, and
  normally `debug_returned` is at least 90% of `debug_requested`.
- `debug_dup_victims == 0`.
