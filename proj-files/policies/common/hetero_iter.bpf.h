/*
 * Per-call eviction budget for policies that scan with
 * bpf_cache_ext_list_iterate_extended().
 *
 * The kernel's iterators keep selecting victims until the 32-entry eviction
 * array is full or the list ends, regardless of how many folios the kernel
 * asked for, and the kernel reclaims every folio it is given. Without a
 * budget a policy therefore evicts up to 32 folios per call even when the
 * kernel asked for a handful. Also, iterate_extended() moves each victim to
 * the tail of the list it scans (evict_list = SELF), so a scan that wraps
 * around the list reaches the same victims again and would propose them
 * twice.
 *
 * Usage, in evict_folios:
 *     iter_call_begin();                  // once per call: new call id
 *     iter_call_budget(eviction_ctx);     // before each scan
 * and in the scan callback:
 *     struct iter_call *c = iter_call_get();
 *     if (!c || c->remaining == 0) return CACHE_EXT_STOP_ITER;
 *     if (meta->victim_call == c->id) ...   // already a victim of this call
 *     ...
 *     iter_call_take(c, &meta->victim_call);  // when returning EVICT_NODE
 *
 * The state is per CPU: a callback runs synchronously on the CPU of the
 * evict_folios call that started the scan.
 */
#ifndef HETERO_ITER_BPF_H
#define HETERO_ITER_BPF_H

struct iter_call {
	__u64 id;         /* unique id of the current evict_folios call */
	__u64 remaining;  /* victims still wanted by this call */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct iter_call);
} iter_call_map SEC(".maps");

static __u64 iter_call_seq;

static __always_inline struct iter_call *iter_call_get(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&iter_call_map, &key);
}

/* Start a new evict_folios call: ids are global, so never shared. */
static __always_inline void iter_call_begin(void)
{
	struct iter_call *c = iter_call_get();
	if (c)
		c->id = __sync_fetch_and_add(&iter_call_seq, 1) + 1;
}

/* Set the budget to what the kernel still wants. */
static __always_inline void
iter_call_budget(struct cache_ext_eviction_ctx *ctx)
{
	struct iter_call *c = iter_call_get();
	if (!c)
		return;
	__u64 req = ctx->request_nr_folios_to_evict;
	__u64 nr = ctx->nr_folios_to_evict;
	c->remaining = req > nr ? req - nr : 0;
}

/* Record that the callback is selecting this folio as a victim. */
static __always_inline void iter_call_take(struct iter_call *c, __u64 *victim_call)
{
	*victim_call = c->id;
	if (c->remaining)
		c->remaining--;
}

#endif /* HETERO_ITER_BPF_H */
