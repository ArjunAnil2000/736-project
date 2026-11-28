#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cache_ext_mglru.skel.h"
#include "hetero_dev.h"

char *USAGE = "Usage: ./cache_ext_mglru --cgroup_path <path> [--fast_dir <dir>] "
	      "[--slow_dir <dir>]\n";
struct cmdline_args {
	char *fast_dir;
	char *slow_dir;
	char *cgroup_path;
};

static struct argp_option options[] = {
	{ "fast_dir", 'f', "DIR", 0,
	  "Directory on the fast device (default: " DEFAULT_FAST_DIR ")" },
	{ "slow_dir", 's', "DIR", 0,
	  "Directory on the slow device (default: " DEFAULT_SLOW_DIR ")" },
	{ "cgroup_path", 'c', "PATH", 0,
	  "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
	HETERO_WATCH_DIR_OPTION,
	{ 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'f':
		args->fast_dir = arg;
		break;
	case 's':
		args->slow_dir = arg;
		break;
	case 'c':
		args->cgroup_path = arg;
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
	struct cache_ext_mglru_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	__u32 devs[MAX_NR_DEVS];
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = {
		.fast_dir = DEFAULT_FAST_DIR,
		.slow_dir = DEFAULT_SLOW_DIR,
	};
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	// Validate arguments
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

	// Open skel
	skel = cache_ext_mglru_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	// Load programs
	if (cache_ext_mglru_bpf__load(skel)) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Tell the policy which device is which, before it sees any folio
	if (hetero_fill_dev_map(bpf_map__fd(skel->maps.dev_idx_map), devs))
		goto cleanup;

	// Attach cache_ext_ops to the specific cgroup
	link = bpf_map__attach_cache_ext_ops(skel->maps.mglru_ops, cgroup_fd);
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
	cache_ext_mglru_bpf__destroy(skel);
	return ret;
}
