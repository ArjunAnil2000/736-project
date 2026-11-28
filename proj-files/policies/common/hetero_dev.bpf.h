/*
 * BPF side of device tagging: which device does a folio's file live on?
 *
 * Include this after vmlinux.h and bpf_helpers.h, once per policy.
 */
#ifndef HETERO_DEV_BPF_H
#define HETERO_DEV_BPF_H

#include "hetero_dev_ids.h"

/*
 * Kernel dev_t of a filesystem's device (sb->s_dev, encoded as
 * (MAJOR << 20) | MINOR) -> enum folio_device. Filled by the loader from
 * stat() on each mount point before the policy is attached. Folios on
 * devices that are not in this map are not tracked by the policy and are
 * left to the kernel's default reclaim.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 8);
} dev_idx_map SEC(".maps");

/*
 * Device index (enum folio_device) of the filesystem holding this folio's
 * file, or -1 if the folio is not a file page on a device in dev_idx_map.
 *
 * Walks folio -> address_space -> owning inode -> superblock -> s_dev. A
 * folio's device never changes, so policies call this once (on insertion)
 * and keep the result in their per-folio metadata.
 */
static __always_inline int folio_dev_idx(struct folio *folio)
{
	if (!folio || !folio->mapping || !folio->mapping->host)
		return -1;

	u32 dev = folio->mapping->host->i_sb->s_dev;
	u32 *idx = bpf_map_lookup_elem(&dev_idx_map, &dev);
	if (!idx || *idx >= MAX_NR_DEVS)
		return -1;
	return *idx;
}

#endif /* HETERO_DEV_BPF_H */
