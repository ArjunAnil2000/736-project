/*
 * Device indices shared by the BPF policies and their userspace loaders.
 *
 * The loader decides which mounted filesystem is "fast" and which is "slow"
 * and tells the policy through dev_idx_map (see hetero_dev.bpf.h /
 * hetero_dev.h). Policies only ever compare these indices.
 */
#ifndef HETERO_DEV_IDS_H
#define HETERO_DEV_IDS_H

enum folio_device {
	DEV_FAST = 0,
	DEV_SLOW = 1,
	MAX_NR_DEVS,
};

#endif /* HETERO_DEV_IDS_H */
