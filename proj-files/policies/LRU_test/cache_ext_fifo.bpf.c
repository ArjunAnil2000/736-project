#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "hetero_dev.bpf.h"  // enum folio_device, dev_idx_map, folio_dev_idx()

char _license[] SEC("license") = "GPL";

// #define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

static u64 fast_list;
static u64 slow_list;

enum storage_speed {
	UNKNOWN_SPEED = -1,
	SLOW_SPEED = 0,
	FAST_SPEED = 1
};

static inline int get_folio_device_speed(struct folio *folio) {
	// The device is found by walking folio->mapping->host->i_sb->s_dev:
	// 1. folio: the page-cache page
	// 2. mapping: the file the page belongs to, representing the contents of a cacheable mappable object,
	//    see linux-cache-ext: include/linux/mm_types.h, and linux-cache-ext: include/linux/fs.h
	// 3. host: the owner, which is either an inode or a block device, see linux-cache-ext: include/linux/fs.h
	// 4. i_sb: the superblock of the filesystem that the inode belongs to, representing the mounted filesystem instance,
	//    see https://kernel-internals.org/vfs/vfs-objects/
	// 5. s_dev: the device identifier
	// The loader maps the device numbers of /mnt/fast and /mnt/slow to
	// DEV_FAST / DEV_SLOW in dev_idx_map (see common/hetero_dev.bpf.h), so
	// nothing here depends on a particular node's device numbering.
	switch (folio_dev_idx(folio)) {
		case DEV_FAST:
			return FAST_SPEED;
		case DEV_SLOW:
			return SLOW_SPEED;
		default:
			return UNKNOWN_SPEED;
	}
}

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return get_folio_device_speed(folio) != UNKNOWN_SPEED;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fifo_init, struct mem_cgroup *memcg)
{
	fast_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (fast_list == 0) {
		bpf_printk("cache_ext: init: Failed to create fast_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created fast_list: %llu\n", fast_list);

	slow_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (slow_list == 0) {
		bpf_printk("cache_ext: init: Failed to create slow_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created slow_list: %llu\n", slow_list);

	return 0;
}

static int bpf_lru_evict_cb(int idx, struct cache_ext_list_node *a)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(fifo_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg) {

	bool prefer_fast = (bpf_get_prandom_u32() & 3U) != 0;
	u64 primary_list = prefer_fast ? fast_list : slow_list;
	u64 fallback_list = prefer_fast ? slow_list : fast_list;

	int ret = bpf_cache_ext_list_iterate(memcg, primary_list, bpf_lru_evict_cb, eviction_ctx);

	if (ret < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate primary list: %d\n", ret);
	}

	if (eviction_ctx->nr_folios_to_evict >= eviction_ctx->request_nr_folios_to_evict) {
		// Limit the number of selected eviction candidates to the kernel's requested count
		eviction_ctx->nr_folios_to_evict = eviction_ctx->request_nr_folios_to_evict;
		return;
	}
	ret = bpf_cache_ext_list_iterate(memcg, fallback_list, bpf_lru_evict_cb, eviction_ctx);

	if (ret < 0) {
	    bpf_printk("cache_ext: evict: Failed to iterate fallback list: %d\n", ret);
	}

	if (eviction_ctx->nr_folios_to_evict > eviction_ctx->request_nr_folios_to_evict) {
		eviction_ctx->nr_folios_to_evict = eviction_ctx->request_nr_folios_to_evict;
	}
}

void BPF_STRUCT_OPS(fifo_folio_evicted, struct folio *folio) {
	// if (bpf_cache_ext_list_del(folio)) {
	// 	bpf_printk("cache_ext: Failed to delete folio from list\n");
	// 	return;
	// }
}

void BPF_STRUCT_OPS(fifo_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	switch (get_folio_device_speed(folio)) {
	case SLOW_SPEED:
		if (bpf_cache_ext_list_add_tail(slow_list, folio)) {
			bpf_printk("cache_ext: added: Failed to add folio to slow_list\n");
		}
		return;
	case FAST_SPEED:
		if (bpf_cache_ext_list_add_tail(fast_list, folio)) {
			bpf_printk("cache_ext: added: Failed to add folio to fast_list\n");
		}
		return;
	default:
		bpf_printk("cache_ext: added: Folio targeting unknown device\n");
	}
}

void BPF_STRUCT_OPS(fifo_folio_accessed, struct folio *folio) {
	int ret;

	if (!is_folio_relevant(folio)) {
		return;
	}

	switch (get_folio_device_speed(folio)) {
	case SLOW_SPEED:
		ret = bpf_cache_ext_list_move(slow_list, folio, true);
		if (ret != 0) {
			bpf_printk("cache_ext: Failed to move folio to slow_list tail\n");
		}
		return;
	case FAST_SPEED:
		ret = bpf_cache_ext_list_move(fast_list, folio, true);
		if (ret != 0) {
			bpf_printk("cache_ext: Failed to move folio to fast_list tail\n");
		}
		return;
	default:
		bpf_printk("cache_ext: accessed: Folio targeting unknown device\n");
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops fifo_ops = {
	.init = (void *)fifo_init,
	.evict_folios = (void *)fifo_evict_folios,
	.folio_accessed = (void *)fifo_folio_accessed,
	.folio_evicted = (void *)fifo_folio_evicted,
	.folio_added = (void *)fifo_folio_added,
};
