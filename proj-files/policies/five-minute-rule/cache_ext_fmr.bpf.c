/*
 * Five-minute-rule policy: evict the folio that is furthest past its device's
 * break-even interval.
 *
 * Based on cache_ext/policies/cache_ext_sampling.bpf.c (one list, sampled
 * eviction with a score function). The score is changed from access count
 * (LFU) to normalized idle time:
 *
 *   overdue(folio) = (now - last_access) / BEI[dev(folio)]
 *
 * where BEI[dev] is the break-even interval of the folio's device (set by the
 * loader from device profiling). Among each sample, the folio with the
 * largest overdue value is evicted. Samples are windows of consecutive folios
 * at the list head, so with equal BEIs this is a CLOCK-like windowed LRU sweep
 * (not uniformly random sampling);
 * a larger BEI for the slow device lets its folios stay idle proportionally
 * longer before they become the preferred victims.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "hetero_dev.bpf.h"  // enum folio_device, dev_idx_map, folio_dev_idx()
#include "hetero_debug.bpf.h" // debug_* counters (validation only)
// debug_policy slots: 0 = sampled evictions, 1 = sampling failed,
//                     3/4 = sampled fast/slow folios that were not evictable,
//                     5/6 = sampled fast/slow folios (all).
// debug_aux: 0/1 = sum of idle time at eviction (us), fast/slow;
//            2/3 = sum of intervals between accesses (us), fast/slow.

char _license[] SEC("license") = "GPL";

#define INT64_MAX (9223372036854775807LL)

// Fixed-point scale for overdue = idle / BEI (1.0 == OVERDUE_SCALE).
#define OVERDUE_SCALE 1024

// Same sample size as cache_ext_sampling: the victim is the most overdue of
// every SAMPLE_SIZE folios taken from the head of the list.
#define SAMPLE_SIZE 20

// Break-even interval per device, in ns. Set by the loader.
// (__u64, not u64: the skeleton copies the type name into userspace.)
const volatile __u64 bei_ns[MAX_NR_DEVS] = { 1000000000ULL, 1000000000ULL };

struct folio_metadata {
	u64 last_access_ns;  // insertion or most recent re-access
	u32 dev_idx;         // enum folio_device, fixed for the folio's lifetime
	bool miss_read_seen; // the read that caused the miss has been reported
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

static u64 sampling_list;

static inline u64 dev_bei_ns(u32 dev)
{
	if (dev >= MAX_NR_DEVS)
		return 1;
	u64 bei = bei_ns[dev];
	return bei ? bei : 1;  // never divide by zero
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fmr_init, struct mem_cgroup *memcg)
{
	sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (sampling_list == 0) {
		bpf_printk("cache_ext: fmr: Failed to create sampling_list\n");
		return -1;
	}
	bpf_printk("cache_ext: fmr: BEI fast %llu ns, slow %llu ns\n",
		   bei_ns[DEV_FAST], bei_ns[DEV_SLOW]);
	return 0;
}

static inline bool folio_evictable_now(struct folio *folio)
{
	if (!folio_test_uptodate(folio) || !folio_test_lru(folio))
		return false;
	if (folio_test_dirty(folio) || folio_test_writeback(folio))
		return false;
	return true;
}

/*
 * Lower score = evicted first (bpf_cache_ext_list_sample picks the minimum),
 * so return the negated overdue value. Folios that can't be evicted right
 * now get INT64_MAX.
 */
static s64 fmr_score_fn(struct cache_ext_list_node *a)
{
#ifdef HETERO_DEBUG
	int debug_dev = folio_dev_idx(a->folio);
	if (debug_dev >= 0 && debug_dev < MAX_NR_DEVS)
		DEBUG_POLICY_INC(5 + debug_dev);
	if (!folio_evictable_now(a->folio) && debug_dev >= 0 && debug_dev < MAX_NR_DEVS)
		DEBUG_POLICY_INC(3 + debug_dev);
#endif
	if (!folio_evictable_now(a->folio))
		return INT64_MAX;

	u64 key = (u64)a->folio;
	struct folio_metadata *meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta)
		return INT64_MAX;

	u64 now = bpf_ktime_get_ns();
	u64 last = meta->last_access_ns;
	u64 idle = now > last ? now - last : 0;
	u64 overdue = idle * OVERDUE_SCALE / dev_bei_ns(meta->dev_idx);
	if (overdue > (u64)INT64_MAX)
		overdue = INT64_MAX;
	return -(s64)overdue;
}

void BPF_STRUCT_OPS(fmr_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	struct sampling_options opts = {
		.sample_size = SAMPLE_SIZE,
	};
	if (bpf_cache_ext_list_sample(memcg, sampling_list, fmr_score_fn, &opts,
				      eviction_ctx) == 0)
		DEBUG_POLICY_INC(0);
	else
		DEBUG_POLICY_INC(1);
	debug_after_evict(eviction_ctx);
}

void BPF_STRUCT_OPS(fmr_folio_added, struct folio *folio)
{
	int dev_idx = folio_dev_idx(folio);
	if (dev_idx < 0)
		return;  // not on the fast or slow device
	u32 dev = dev_idx;

	u64 key = (u64)folio;
	struct folio_metadata meta = {
		.last_access_ns = bpf_ktime_get_ns(),
		.dev_idx = dev,
	};
	if (bpf_map_update_elem(&folio_metadata_map, &key, &meta, BPF_ANY)) {
		bpf_printk("cache_ext: fmr: Failed to create folio metadata\n");
		return;
	}

	if (bpf_cache_ext_list_add_tail(sampling_list, folio)) {
		bpf_map_delete_elem(&folio_metadata_map, &key);
		bpf_printk("cache_ext: fmr: Failed to add folio to sampling_list\n");
		return;
	}

	DEBUG_DEV_INC(debug_added, (int)dev);
}

void BPF_STRUCT_OPS(fmr_folio_accessed, struct folio *folio)
{
	u64 key = (u64)folio;
	struct folio_metadata *meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta)
		return;  // not tracked (other device, or added before attach)

#ifdef HETERO_DEBUG
	{
		u64 debug_now = bpf_ktime_get_ns();
		u64 debug_prev = meta->last_access_ns;
		if (debug_now > debug_prev)
			DEBUG_AUX_ADD(2 + (meta->dev_idx & 1), (debug_now - debug_prev) / 1000);
	}
#endif
	// The read that caused the miss reports its access only when its I/O
	// completes, ~11 ms later on the HDD than on the SSD. Stamping that
	// time would make every new HDD folio look younger than SSD folios
	// inserted at the same moment, which decides most windows (a window's
	// 20 consecutive folios are inserted within a few tens of ms). Keep
	// the insertion time instead; only re-accesses update the timestamp.
	if (!meta->miss_read_seen) {
		meta->miss_read_seen = true;
		return;
	}
	WRITE_ONCE(meta->last_access_ns, bpf_ktime_get_ns());
	DEBUG_DEV_INC(debug_accessed, (int)meta->dev_idx);
}

void BPF_STRUCT_OPS(fmr_folio_evicted, struct folio *folio)
{
	u64 key = (u64)folio;
	struct folio_metadata *meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta)
		return;  // not tracked by this policy

#ifdef HETERO_DEBUG
	DEBUG_DEV_INC(debug_evicted, (int)meta->dev_idx);
	{
		u64 debug_now = bpf_ktime_get_ns();
		if (debug_now > meta->last_access_ns)
			DEBUG_AUX_ADD(meta->dev_idx & 1, (debug_now - meta->last_access_ns) / 1000);
	}
#endif
	bpf_map_delete_elem(&folio_metadata_map, &key);
}

SEC(".struct_ops.link")
struct cache_ext_ops fmr_ops = {
	.init = (void *)fmr_init,
	.evict_folios = (void *)fmr_evict_folios,
	.folio_accessed = (void *)fmr_folio_accessed,
	.folio_evicted = (void *)fmr_folio_evicted,
	.folio_added = (void *)fmr_folio_added,
};
