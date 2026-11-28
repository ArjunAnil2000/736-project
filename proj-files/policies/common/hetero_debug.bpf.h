/*
 * Debug counters for validating the device-aware policies on a node.
 *
 * Everything here is named debug_* and is NOT part of any policy's logic: the
 * counters only observe what the hooks do. They are compiled in only when
 * HETERO_DEBUG is defined (`make DEBUG=1`); otherwise every DEBUG_* macro
 * and debug_after_evict() is a no-op and debug_map does not exist. With
 * them compiled in, read them while a policy is loaded with
 *
 *     sudo bpftool map dump name debug_map
 *
 * Include after hetero_dev.bpf.h (needs MAX_NR_DEVS and folio_dev_idx()).
 */
#ifndef HETERO_DEBUG_BPF_H
#define HETERO_DEBUG_BPF_H

#ifdef HETERO_DEBUG

#define DEBUG_NR_POLICY_SLOTS 8

struct debug_counters {
	__u64 debug_added[MAX_NR_DEVS];     /* folio_added on tracked folios      */
	__u64 debug_accessed[MAX_NR_DEVS];  /* folio_accessed on tracked folios   */
	__u64 debug_evicted[MAX_NR_DEVS];   /* folio_evicted on tracked folios    */
	__u64 debug_proposed[MAX_NR_DEVS];  /* victims returned by evict_folios   */
	__u64 debug_evict_calls;            /* evict_folios invocations           */
	__u64 debug_requested;              /* sum of request_nr_folios_to_evict  */
	__u64 debug_returned;               /* sum of nr_folios_to_evict          */
	__u64 debug_short_calls;            /* calls returning < requested        */
	__u64 debug_dup_victims;            /* repeated folio within one batch    */
	__u64 debug_policy[DEBUG_NR_POLICY_SLOTS]; /* policy-specific, see policy */
	__u64 debug_aux[DEBUG_NR_POLICY_SLOTS];    /* policy-specific sums, see policy */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct debug_counters);
} debug_map SEC(".maps");

static __always_inline struct debug_counters *debug_get(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&debug_map, &key);
}

#define DEBUG_ADD(field, val)                                         \
	do {                                                          \
		struct debug_counters *__d = debug_get();             \
		if (__d)                                              \
			__sync_fetch_and_add(&__d->field, (val));     \
	} while (0)

/* Per-device counter; ignores untracked folios (dev < 0). */
#define DEBUG_DEV_INC(field, dev)                                     \
	do {                                                          \
		int __dev = (dev);                                    \
		if (__dev >= 0 && __dev < MAX_NR_DEVS)                \
			DEBUG_ADD(field[__dev & 1], 1);               \
	} while (0)

/* The mask keeps the index provably in bounds for the verifier. */
#define DEBUG_POLICY_INC(slot)                                        \
	do {                                                          \
		__u32 __s = (__u32)(slot);                            \
		if (__s < DEBUG_NR_POLICY_SLOTS)                      \
			DEBUG_ADD(debug_policy[__s & (DEBUG_NR_POLICY_SLOTS - 1)], 1); \
	} while (0)

#define DEBUG_AUX_ADD(slot, val)                                      \
	do {                                                          \
		__u32 __s = (__u32)(slot);                            \
		if (__s < DEBUG_NR_POLICY_SLOTS)                      \
			DEBUG_ADD(debug_aux[__s & (DEBUG_NR_POLICY_SLOTS - 1)], (val)); \
	} while (0)

/*
 * Call at the end of evict_folios: records the request, the victims proposed
 * per device, short batches, and folios that appear more than once in the
 * batch (which the kernel would try to reclaim twice).
 */
/* Last eviction call that proposed each folio, to spot duplicates. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);    /* folio pointer */
	__type(value, __u64);  /* debug call id */
} debug_seen_map SEC(".maps");

static __u64 debug_call_seq;

static __always_inline void
debug_after_evict(struct cache_ext_eviction_ctx *ctx)
{
	struct debug_counters *d = debug_get();
	if (!d)
		return;

	__u64 req = ctx->request_nr_folios_to_evict;
	__u64 nr = ctx->nr_folios_to_evict;
	if (nr > 32)
		nr = 32;

	__sync_fetch_and_add(&d->debug_evict_calls, 1);
	__sync_fetch_and_add(&d->debug_requested, req);
	__sync_fetch_and_add(&d->debug_returned, nr);
	if (nr < req)
		__sync_fetch_and_add(&d->debug_short_calls, 1);

	/* Unique id for this call (calls on different CPUs never share one). */
	__u64 call = __sync_fetch_and_add(&debug_call_seq, 1) + 1;

	for (int i = 0; i < 32; i++) {
		if (i >= nr)
			break;
		struct folio *folio = ctx->folios_to_evict[i];
		int dev = folio_dev_idx(folio);
		if (dev >= 0 && dev < MAX_NR_DEVS)
			__sync_fetch_and_add(&d->debug_proposed[dev], 1);

		__u64 key = (__u64)folio;
		__u64 *last = bpf_map_lookup_elem(&debug_seen_map, &key);
		if (last && *last == call)
			__sync_fetch_and_add(&d->debug_dup_victims, 1);
		else
			bpf_map_update_elem(&debug_seen_map, &key, &call, BPF_ANY);
	}
}

#else /* !HETERO_DEBUG */

#define DEBUG_ADD(field, val)		do { } while (0)
#define DEBUG_DEV_INC(field, dev)	do { } while (0)
#define DEBUG_POLICY_INC(slot)		do { } while (0)
#define DEBUG_AUX_ADD(slot, val)	do { } while (0)

static __always_inline void
debug_after_evict(struct cache_ext_eviction_ctx *ctx)
{
}

#endif /* HETERO_DEBUG */

#endif /* HETERO_DEBUG_BPF_H */
