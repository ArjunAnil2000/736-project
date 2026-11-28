#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "hetero_dev.h"
#include "cache_ext_fmr.skel.h"

char *USAGE = "Usage: ./cache_ext_fmr --cgroup_path <path> [--fast_bei_ms <ms>] "
	      "[--slow_bei_ms <ms>] [--fast_dir <dir>] [--slow_dir <dir>]\n";
struct cmdline_args {
	char *cgroup_path;
	char *fast_dir;
	char *slow_dir;
	double bei_ms[MAX_NR_DEVS];
};

// Equal BEIs make the policy a windowed LRU sweep (the least recently used
// folio of each window of 20 consecutive folios at the list head is evicted);
// profile_devices.sh suggests device-specific values.
#define DEFAULT_BEI_MS 1000.0

static struct argp_option options[] = {
	{ "cgroup_path", 'c', "PATH", 0, "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
	{ "fast_bei_ms", 'F', "MS", 0, "Break-even interval of the fast device, in ms (default 1000)" },
	{ "slow_bei_ms", 'L', "MS", 0, "Break-even interval of the slow device, in ms (default 1000)" },
	{ "fast_dir", 'f', "DIR", 0, "Directory on the fast device (default: " DEFAULT_FAST_DIR ")" },
	{ "slow_dir", 's', "DIR", 0, "Directory on the slow device (default: " DEFAULT_SLOW_DIR ")" },
	HETERO_WATCH_DIR_OPTION,
	{ 0 }
};

static double parse_ms(struct argp_state *state, const char *name, const char *arg)
{
	char *end;
	errno = 0;
	double v = strtod(arg, &end);
	if (errno || *end != '\0' || !isfinite(v) || v <= 0 || v > 1e9)
		argp_error(state, "invalid --%s: %s (want milliseconds > 0)", name, arg);
	return v;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'c':
		args->cgroup_path = arg;
		break;
	case 'F':
		args->bei_ms[DEV_FAST] = parse_ms(state, "fast_bei_ms", arg);
		break;
	case 'L':
		args->bei_ms[DEV_SLOW] = parse_ms(state, "slow_bei_ms", arg);
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

int main(int argc, char **argv)
{
	int ret = 1;
	struct cache_ext_fmr_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	__u32 devs[MAX_NR_DEVS];
	int cgroup_fd = -1;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = {
		.fast_dir = DEFAULT_FAST_DIR,
		.slow_dir = DEFAULT_SLOW_DIR,
		.bei_ms = { DEFAULT_BEI_MS, DEFAULT_BEI_MS },
	};
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	if (args.cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n%s", USAGE);
		return 1;
	}

	// Resolve which device each directory lives on
	if (hetero_resolve_devs(args.fast_dir, args.slow_dir, devs))
		return 1;

	// Open cgroup directory early
	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	skel = cache_ext_fmr_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	for (int dev = 0; dev < MAX_NR_DEVS; dev++) {
		skel->rodata->bei_ns[dev] = (__u64)llround(args.bei_ms[dev] * 1e6);
		printf("BEI %s: %.3f ms\n", hetero_dev_names[dev], args.bei_ms[dev]);
	}
	if (args.bei_ms[DEV_FAST] == args.bei_ms[DEV_SLOW])
		printf("Equal BEIs: the policy evicts the least recently used folio of each window (device-oblivious). "
		       "See profile_devices.sh for device-specific values.\n");

	if (cache_ext_fmr_bpf__load(skel)) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Tell the policy which device is which, before it sees any folio
	if (hetero_fill_dev_map(bpf_map__fd(skel->maps.dev_idx_map), devs))
		goto cleanup;

	link = bpf_map__attach_cache_ext_ops(skel->maps.fmr_ops, cgroup_fd);
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
	cache_ext_fmr_bpf__destroy(skel);
	return ret;
}
