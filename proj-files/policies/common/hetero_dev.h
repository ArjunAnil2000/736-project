/*
 * Userspace side of device tagging, shared by the policy loaders.
 *
 * Resolves the fast/slow mount points to kernel device numbers and fills the
 * policy's dev_idx_map (see hetero_dev.bpf.h).
 */
#ifndef HETERO_DEV_H
#define HETERO_DEV_H

#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include "hetero_dev_ids.h"

/* Mount points created by scripts/setup (or mounted by hand on the node). */
#define DEFAULT_FAST_DIR "/mnt/fast"
#define DEFAULT_SLOW_DIR "/mnt/slow"

static const char *hetero_dev_names[MAX_NR_DEVS] = { "fast", "slow" };

/*
 * cache_ext's upstream loaders take --watch_dir, and the workload scripts
 * always pass it. These policies track folios by device instead, so the
 * option is accepted (hidden from --help) and ignored. Add
 * HETERO_WATCH_DIR_OPTION to the argp options and handle HETERO_WATCH_DIR_KEY
 * with a no-op.
 */
#define HETERO_WATCH_DIR_KEY 'w'
#define HETERO_WATCH_DIR_OPTION \
	{ "watch_dir", HETERO_WATCH_DIR_KEY, "DIR", OPTION_HIDDEN, \
	  "Ignored: folios are tracked by device, not by directory" }

/*
 * Kernel dev_t of the filesystem holding `dir`, in the encoding the BPF side
 * reads from sb->s_dev: (MAJOR << 20) | MINOR. This is NOT st_dev itself,
 * which uses glibc's userspace encoding.
 */
static int hetero_dir_kernel_dev(const char *dir, __u32 *kdev)
{
	struct stat st;
	if (stat(dir, &st) == -1) {
		fprintf(stderr, "stat(%s): %s\n", dir, strerror(errno));
		return -1;
	}
	if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr, "Not a directory: %s\n", dir);
		return -1;
	}
	*kdev = (major(st.st_dev) << 20) | minor(st.st_dev);
	printf("%s: device %u:%u\n", dir, major(st.st_dev), minor(st.st_dev));
	return 0;
}

/*
 * Resolve both directories before loading the BPF object, so bad paths fail
 * early. Refuses two directories on the same device: the policy could not
 * tell their folios apart.
 */
static int hetero_resolve_devs(const char *fast_dir, const char *slow_dir,
			       __u32 devs[MAX_NR_DEVS])
{
	if (hetero_dir_kernel_dev(fast_dir, &devs[DEV_FAST]) ||
	    hetero_dir_kernel_dev(slow_dir, &devs[DEV_SLOW]))
		return -1;
	if (devs[DEV_FAST] == devs[DEV_SLOW]) {
		fprintf(stderr, "%s and %s are on the same device; the policy "
				"could not tell their folios apart\n",
			fast_dir, slow_dir);
		return -1;
	}
	return 0;
}

/* Fill dev_idx_map. Call after load and before attaching the policy. */
static int hetero_fill_dev_map(int map_fd, const __u32 devs[MAX_NR_DEVS])
{
	for (__u32 idx = 0; idx < MAX_NR_DEVS; idx++) {
		if (bpf_map_update_elem(map_fd, &devs[idx], &idx, BPF_ANY)) {
			fprintf(stderr, "Failed to add %s device to dev_idx_map: %s\n",
				hetero_dev_names[idx], strerror(errno));
			return -1;
		}
	}
	return 0;
}

#endif /* HETERO_DEV_H */
