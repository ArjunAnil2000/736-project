#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "hetero_dev.h"
#include "cache_ext_s4fifo.skel.h"

char *USAGE = "Usage: ./cache_ext_s4fifo --cgroup_path <path> --cgroup_size <bytes> "
	      "[--k <ratio>] [--fast_dir <dir>] [--slow_dir <dir>]\n";
struct cmdline_args {
	uint64_t cgroup_size;
	char *cgroup_path;
	char *fast_dir;
	char *slow_dir;
	double k;
};

static struct argp_option options[] = {
	{ "cgroup_size", 'S', "SIZE", 0, "Size of the cgroup, in bytes" },
	{ "cgroup_path", 'c', "PATH", 0, "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
	{ "k", 'k', "RATIO", 0,
	  "Slow/fast miss-cost ratio: evict the slow small queue only if its head is k "
	  "times older than the fast one's (default 1 = S3-FIFO-like; 0 = strict fast-first)" },
	{ "fast_dir", 'f', "DIR", 0, "Directory on the fast device (default: " DEFAULT_FAST_DIR ")" },
	{ "slow_dir", 's', "DIR", 0, "Directory on the slow device (default: " DEFAULT_SLOW_DIR ")" },
	HETERO_WATCH_DIR_OPTION,
	{ 0 },
};

static const uint64_t page_size = 4096;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	char *end;
	switch (key) {
	case 'S':
		errno = 0;
		args->cgroup_size = strtoull(arg, &end, 10);
		if (errno || *end != '\0')
			args->cgroup_size = 0;
		break;
	case 'c':
		args->cgroup_path = arg;
		break;
	case 'k':
		errno = 0;
		args->k = strtod(arg, &end);
		if (errno || *end != '\0' || !isfinite(args->k) || args->k < 0 || args->k > 1e6)
			argp_error(state, "invalid --k: %s (want a number in [0, 1e6])", arg);
		break;
	case 'f':
		args->fast_dir = arg;
		break;
	case 's':
		args->slow_dir = arg;
		break;
	case HETERO_WATCH_DIR_KEY:
		break;  // ignored, see hetero_dev.h
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int parse_args(int argc, char **argv, struct cmdline_args *args) {
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, args);

	if (args->cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n%s", USAGE);
		return 1;
	}

	if (args->cgroup_size == 0) {
		fprintf(stderr, "Missing or invalid argument: cgroup_size\n%s", USAGE);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv) {
	struct cmdline_args args = {
		.fast_dir = DEFAULT_FAST_DIR,
		.slow_dir = DEFAULT_SLOW_DIR,
		.k = 1.0,
	};
	struct cache_ext_s4fifo_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	__u32 devs[MAX_NR_DEVS];
	int cgroup_fd = -1;
	int ret = 1;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	if (parse_args(argc, argv, &args))
		return 1;

	// Resolve which device each directory lives on
	if (hetero_resolve_devs(args.fast_dir, args.slow_dir, devs))
		return 1;

	// Open cgroup directory early
	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	skel = cache_ext_s4fifo_bpf__open();
	if (!skel) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	// Set cache size in terms of number of pages. Assumes uniform page size.
	skel->rodata->cache_size = args.cgroup_size / page_size;
	skel->rodata->slow_age_ratio_milli = (__u64)llround(args.k * 1000.0);
	fprintf(stderr, "Cgroup size: %lu bytes (%lu pages)\n", args.cgroup_size,
		skel->rodata->cache_size);
	if (args.k == 0)
		fprintf(stderr, "k = 0: strict fast-first small-queue eviction (ablation)\n");
	else
		fprintf(stderr, "k = %.3f: evict small[slow] when its head is > k x older\n", args.k);

	// Resize ghost_map to the cache size, as in S3-FIFO
	if (bpf_map__set_max_entries(skel->maps.ghost_map, skel->rodata->cache_size)) {
		perror("Failed to resize ghost_map");
		goto cleanup;
	}

	if (cache_ext_s4fifo_bpf__load(skel)) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Tell the policy which device is which, before it sees any folio
	if (hetero_fill_dev_map(bpf_map__fd(skel->maps.dev_idx_map), devs))
		goto cleanup;

	link = bpf_map__attach_cache_ext_ops(skel->maps.s4fifo_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();
	ret = 0;

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_s4fifo_bpf__destroy(skel);
	return ret;
}
