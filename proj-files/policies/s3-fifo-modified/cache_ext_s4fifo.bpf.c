/*
 * S4-FIFO: S3-FIFO with one small (probationary) queue per device.
 *
 * Based on cache_ext/policies/cache_ext_s3fifo.bpf.c. The main queue, the
 * ghost queue, the frequency counter and the small/main sizing rule are
 * unchanged. What changes is the small queue: it is split into a fast-device
 * queue and a slow-device queue, and when the policy evicts from the small
 * queues it picks between them by age:
 *
 *   evict from small[SLOW]  iff  age(head of small[SLOW]) > k * age(head of small[FAST])
 *
 * where age is the time since the head folio was inserted and k is the
 * measured miss-cost ratio slow/fast (slow_age_ratio_milli = k * 1000).
 * k = 1 makes the two queues behave like the single S3-FIFO small queue
 * (always evict the older head); k = 0 is the "strict fast-first" ablation
 * (always evict from small[FAST] while it is non-empty).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "hetero_dev.bpf.h"  // enum folio_device, dev_idx_map, folio_dev_idx()
#include "hetero_debug.bpf.h" // debug_* counters (validation only)
#include "hetero_iter.bpf.h"  // per-call eviction budget
// debug_policy slots: 0 = evictions from the small queues, 1 = from M,
//                     2 = the second small queue was also scanned.

char _license[] SEC("license") = "GPL";

#define ENOENT		2  /* include/uapi/asm-generic/errno-base.h */
#define INT64_MAX	(9223372036854775807LL)

// Set from userspace. In terms of number of pages.
const volatile size_t cache_size = 0;

// k * 1000, where k is the slow/fast miss-cost ratio. Set from userspace.
// 1000 (k = 1) ~ unmodified S3-FIFO; 0 = strict fast-first ablation.
// (__u64, not u64: the skeleton copies the type name into userspace.)
const volatile __u64 slow_age_ratio_milli = 1000;

struct folio_metadata {
	s64 freq;
	u64 insert_ns;  // bpf_ktime_get_ns() when the folio entered its queue
	u32 dev_idx;    // enum folio_device, fixed for the folio's lifetime
	bool in_main;
	u64 victim_call; // id of the evict_folios call that last chose it (hetero_iter.bpf.h)
};

struct ghost_entry {
	u64 address_space;
	u64 offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

// max_entries is set by the loader to the cache size, as in S3-FIFO.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ghost_entry);
	__type(value, u8);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);  // Per-CPU LRU eviction logic
} ghost_map SEC(".maps");

// Head insertion time of a small queue, filled by peek_head_fn. Per-CPU so
// concurrent evictions on different CPUs don't overwrite each other.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} peek_map SEC(".maps");

static u64 main_list;
static u64 small_list[MAX_NR_DEVS];

/*
 * Approximate sizes, based on what we choose to evict, not what is actually
 * evicted (as in S3-FIFO).
 */
static s64 small_list_size[MAX_NR_DEVS];
static s64 main_list_size = 0;

static inline struct folio_metadata *get_folio_metadata(struct folio *folio) {
	u64 key = (u64)folio;
	return bpf_map_lookup_elem(&folio_metadata_map, &key);
}

/*
 * Check if a folio is in the ghost map and delete the ghost entry.
 * We only check if an element is in the ghost map on inserting into the cache.
 * Relies on bpf_map_delete_elem() returning -ENOENT if the element is not found.
 */
static inline bool folio_in_ghost(struct folio *folio) {
	struct ghost_entry key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};
	return bpf_map_delete_elem(&ghost_map, &key) != -ENOENT;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(s4fifo_init, struct mem_cgroup *memcg)
{
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: init: Failed to create main_list\n");
		return -1;
	}

	for (int dev = 0; dev < MAX_NR_DEVS; dev++) {
		u64 list = bpf_cache_ext_ds_registry_new_list(memcg);
		if (list == 0) {
			bpf_printk("cache_ext: init: Failed to create small_list[%d]\n", dev);
			return -1;
		}
		small_list[dev] = list;
	}
	bpf_printk("cache_ext: s4fifo: main_list %llu, small_list fast %llu slow %llu\n",
		   main_list, small_list[DEV_FAST], small_list[DEV_SLOW]);

	return 0;
}

/////////////////////////
// Small-queue scanning //
/////////////////////////

/*
 * Every folio this returns CONTINUE for is moved to the main queue by the
 * iterate helper (continue_list = main_list), including folios skipped
 * because they are dirty / under writeback / not up to date, exactly as in
 * S3-FIFO. Unlike S3-FIFO, all of them are marked in_main so the per-queue
 * size counters stay consistent when they are later evicted.
 */
static int bpf_s4fifo_score_small_fn(int idx, struct cache_ext_list_node *a)
{
	struct folio_metadata *data = get_folio_metadata(a->folio);
	if (!data) {
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n");
		return CACHE_EXT_CONTINUE_ITER;
	}

	// Stop once the kernel's request is met, or when the scan wraps around
	// to a folio this call already chose (victims move to this list's tail).
	struct iter_call *call = iter_call_get();
	if (!call || call->remaining == 0 || data->victim_call == call->id)
		return CACHE_EXT_STOP_ITER;

	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio) ||
	    folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) {
		data->in_main = true;
		return CACHE_EXT_CONTINUE_ITER;
	}

	// Move to main list if freq > 1 (accessed at least twice while in small)
	if (data->freq > 1) {
		data->in_main = true;
		return CACHE_EXT_CONTINUE_ITER;
	}

	// Else, evict
	iter_call_take(call, &data->victim_call);
	return CACHE_EXT_EVICT_NODE;
}

/*
 * Peek at the head of a small queue: record its insertion time in peek_map
 * and stop. Uses the plain iterate helper (read lock, no list changes).
 */
static int peek_head_fn(int idx, struct cache_ext_list_node *a)
{
	struct folio_metadata *data = get_folio_metadata(a->folio);
	if (!data)
		return CACHE_EXT_CONTINUE_ITER;  // skip folios we can't age

	u32 zero = 0;
	u64 *slot = bpf_map_lookup_elem(&peek_map, &zero);
	if (slot)
		*slot = data->insert_ns;
	return CACHE_EXT_STOP_ITER;
}

/*
 * Insertion time of the head of small[dev], or 0 if the queue is (or looks)
 * empty. peek_head_fn never selects anything for eviction, so the eviction
 * context is left untouched.
 */
static u64 small_head_insert_ns(struct mem_cgroup *memcg,
				struct cache_ext_eviction_ctx *eviction_ctx, u32 dev)
{
	u32 zero = 0;
	u64 *slot = bpf_map_lookup_elem(&peek_map, &zero);
	if (!slot || dev >= MAX_NR_DEVS)
		return 0;
	*slot = 0;
	bpf_cache_ext_list_iterate(memcg, small_list[dev], peek_head_fn, eviction_ctx);
	return *slot;
}

/*
 * Decide which small queue to evict from first.
 *
 * Age-weighted rule: evict from the slow queue only if its head has waited
 * more than k times longer than the fast queue's head. A slow folio thus
 * stays on probation k times longer than a fast one, in proportion to how
 * much more a miss on it costs. k = 0 -> always the fast queue if non-empty.
 */
static u32 pick_small_queue(struct mem_cgroup *memcg,
			    struct cache_ext_eviction_ctx *eviction_ctx)
{
	u64 fast_ns = small_head_insert_ns(memcg, eviction_ctx, DEV_FAST);
	u64 slow_ns = small_head_insert_ns(memcg, eviction_ctx, DEV_SLOW);

	if (fast_ns == 0)
		return DEV_SLOW;
	if (slow_ns == 0)
		return DEV_FAST;
	if (slow_age_ratio_milli == 0)
		return DEV_FAST;  // strict fast-first ablation

	u64 now = bpf_ktime_get_ns();
	u64 fast_age = now > fast_ns ? now - fast_ns : 0;
	u64 slow_age = now > slow_ns ? now - slow_ns : 0;

	// slow_age > k * fast_age, with k in thousandths. Written as a division
	// so it cannot overflow: k * fast_age overflowed 64 bits after ~5 h at
	// k = 1 (slow_age * 1000 only overflows after ~213 days).
	if (fast_age == 0)
		return DEV_SLOW;
	if (slow_age * 1000 / fast_age > slow_age_ratio_milli)
		return DEV_SLOW;
	return DEV_FAST;
}

static void evict_small(struct cache_ext_eviction_ctx *eviction_ctx,
			struct mem_cgroup *memcg, u32 dev)
{
	/*
	 * Iterate from head. If freq > 1, move to main list, otherwise evict.
	 * (When evicting, move to tail in the meantime).
	 */
	if (dev >= MAX_NR_DEVS)
		return;

	struct cache_ext_iterate_opts opts = {
		.continue_list = main_list,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};

	iter_call_budget(eviction_ctx);
	if (bpf_cache_ext_list_iterate_extended(memcg, small_list[dev], bpf_s4fifo_score_small_fn,
						&opts, eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate small_list[%d]\n", dev);
		return;
	}

	// Test the updated values (the old code tested the value before the
	// update, so a negative size was never clamped).
	if (__sync_sub_and_fetch(&small_list_size[dev], opts.nr_folios_continue) < 0)
		small_list_size[dev] = 0;

	if (__sync_add_and_fetch(&main_list_size, opts.nr_folios_continue) < 0)
		main_list_size = opts.nr_folios_continue;
}

static void evict_small_queues(struct cache_ext_eviction_ctx *eviction_ctx,
			       struct mem_cgroup *memcg)
{
	u32 first = pick_small_queue(memcg, eviction_ctx);
	u32 second = first == DEV_FAST ? DEV_SLOW : DEV_FAST;

	evict_small(eviction_ctx, memcg, first);
	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		DEBUG_POLICY_INC(2);
		evict_small(eviction_ctx, memcg, second);
	}
}

////////////////////////
// Main-queue scanning //
////////////////////////

#define MAIN_ITER_FN(pass) 								\
static int bpf_s4fifo_score_main_iter_fn_##pass(int idx, struct cache_ext_list_node *a) 	\
{ 											\
	/* Stop once the kernel's request is met. */ 					\
	struct iter_call *call = iter_call_get(); 					\
	if (!call || call->remaining == 0) 						\
		return CACHE_EXT_STOP_ITER; 						\
 											\
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) 		\
		return CACHE_EXT_CONTINUE_ITER; 					\
 											\
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) 		\
		return CACHE_EXT_CONTINUE_ITER; 					\
 											\
	struct folio_metadata *data = get_folio_metadata(a->folio); 			\
	if (!data) { 									\
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n"); 		\
		return CACHE_EXT_CONTINUE_ITER; 					\
	} 										\
 											\
	/* A later pass over M reaches this call's earlier victims: skip them. */ 	\
	if (data->victim_call == call->id) 						\
		return CACHE_EXT_CONTINUE_ITER; 					\
 											\
	s64 freq = __sync_sub_and_fetch(&data->freq, 1); 				\
	if (freq < pass) { 								\
		iter_call_take(call, &data->victim_call); 				\
		return CACHE_EXT_EVICT_NODE; 						\
	} 										\
 											\
	return CACHE_EXT_CONTINUE_ITER; 						\
}

MAIN_ITER_FN(0)
MAIN_ITER_FN(1)
MAIN_ITER_FN(2)
MAIN_ITER_FN(3)

static void evict_main_iter(struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	/*
	 * Iterate from head. If freq > 0, move to tail, freq--.
	 * Otherwise, evict. (When evicting, move to tail in the meantime).
	 */

	struct cache_ext_iterate_opts opts = {
		.continue_list = CACHE_EXT_ITERATE_SELF,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};

	iter_call_budget(eviction_ctx);
	if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s4fifo_score_main_iter_fn_0, &opts,
						eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
		return;
	}

	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		iter_call_budget(eviction_ctx);
		if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s4fifo_score_main_iter_fn_1, &opts,
							eviction_ctx) < 0) {
			bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
			return;
		}
	} else {
		return;
	}

	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		iter_call_budget(eviction_ctx);
		if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s4fifo_score_main_iter_fn_2, &opts,
							eviction_ctx) < 0) {
			bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
			return;
		}
	} else {
		return;
	}

	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		iter_call_budget(eviction_ctx);
		if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s4fifo_score_main_iter_fn_3, &opts,
							eviction_ctx) < 0) {
			bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
			return;
		}
	}
}

///////////
// Hooks //
///////////

void BPF_STRUCT_OPS(s4fifo_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	// Same sizing rule as S3-FIFO, applied to the combined small queues.
	s64 small_total = small_list_size[DEV_FAST] + small_list_size[DEV_SLOW];
	iter_call_begin();
	if (small_total >= (s64)(cache_size / 15) || main_list_size <= 2 * small_total) {
		DEBUG_POLICY_INC(0);
		evict_small_queues(eviction_ctx, memcg);
	} else {
		DEBUG_POLICY_INC(1);
		evict_main_iter(eviction_ctx, memcg);
	}
	debug_after_evict(eviction_ctx);
}

void BPF_STRUCT_OPS(s4fifo_folio_accessed, struct folio *folio) {
	struct folio_metadata *data = get_folio_metadata(folio);
	if (!data)
		return;  // not tracked (other device, or added before attach)
	DEBUG_DEV_INC(debug_accessed, (int)data->dev_idx);

	// Cap frequency at 3
	if (__sync_add_and_fetch(&data->freq, 1) > 3)
		data->freq = 3;
}

void BPF_STRUCT_OPS(s4fifo_folio_evicted, struct folio *folio) {
	u64 key = (u64)folio;

	struct folio_metadata *data = get_folio_metadata(folio);
	if (!data)
		return;  // not tracked by this policy

	u32 dev = data->dev_idx;
	if (dev >= MAX_NR_DEVS)
		dev = DEV_FAST;
	DEBUG_DEV_INC(debug_evicted, (int)dev);

	struct ghost_entry ghost_key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};
	u8 ghost_val = 0;
	// Don't return early, we want to delete the folio metadata regardless
	if (bpf_map_update_elem(&ghost_map, &ghost_key, &ghost_val, BPF_ANY))
		bpf_printk("cache_ext: evicted: Failed to add to ghost_map\n");

	if (data->in_main)
		__sync_fetch_and_sub(&main_list_size, 1);
	else
		__sync_fetch_and_sub(&small_list_size[dev], 1);

	bpf_map_delete_elem(&folio_metadata_map, &key);
}

/*
 * If folio is in the ghost map, add to tail of main list, otherwise add to tail
 * of its device's small list.
 */
void BPF_STRUCT_OPS(s4fifo_folio_added, struct folio *folio) {
	int dev_idx = folio_dev_idx(folio);
	if (dev_idx < 0)
		return;  // not on the fast or slow device
	u32 dev = dev_idx;
	if (dev >= MAX_NR_DEVS)
		return;
	DEBUG_DEV_INC(debug_added, (int)dev);

	u64 key = (u64)folio;
	struct folio_metadata new_meta = {
		.freq = 0,
		.insert_ns = bpf_ktime_get_ns(),
		.dev_idx = dev,
	};

	u64 list_to_add;
	if (folio_in_ghost(folio)) {
		list_to_add = main_list;
		new_meta.in_main = true;
		__sync_fetch_and_add(&main_list_size, 1);
	} else {
		list_to_add = small_list[dev];
		new_meta.in_main = false;
		__sync_fetch_and_add(&small_list_size[dev], 1);
	}

	if (bpf_cache_ext_list_add_tail(list_to_add, folio)) {
		bpf_printk("cache_ext: added: Failed to add folio to list\n");
		return;
	}

	if (bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY)) {
		bpf_cache_ext_list_del(folio);
		bpf_printk("cache_ext: added: Failed to create folio metadata\n");
		return;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops s4fifo_ops = {
	.init = (void *)s4fifo_init,
	.evict_folios = (void *)s4fifo_evict_folios,
	.folio_accessed = (void *)s4fifo_folio_accessed,
	.folio_evicted = (void *)s4fifo_folio_evicted,
	.folio_added = (void *)s4fifo_folio_added,
};
