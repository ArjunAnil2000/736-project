#!/bin/bash
# profile_devices.sh — measure the fast and slow devices and suggest
# break-even intervals (BEIs) for cache_ext_fmr.
#
# Run on the node, with /mnt/fast and /mnt/slow mounted:
#
#   ./profile_devices.sh                       # time-based BEIs (see below)
#   FAST_BEI_MS=500 ./profile_devices.sh       # pick the fast device's BEI
#   DRAM_USD_PER_GB=3 FAST_DEV_USD=60 SLOW_DEV_USD=40 ./profile_devices.sh
#                                              # also print Gray's economic BEIs
#
# For each device it runs a 4 KiB random-read fio job with O_DIRECT and
# queue depth 1 (one outstanding miss, i.e. what a page-cache miss costs),
# and reports mean latency and IOPS.
#
# Suggested BEIs:
#   * time-based (always printed): the slow device's BEI is the fast device's
#     BEI scaled by the measured latency ratio, so a slow page may stay idle
#     as many times longer as its re-read is slower. Only this ratio affects
#     eviction order; FAST_BEI_MS (default 1000) only sets the absolute scale.
#   * economic (Gray & Putzolu, 1987), if prices are given:
#       BEI = (pages per MB of RAM / accesses per second per device)
#             * (price per device / price per MB of RAM)
#     with 4 KiB pages (256 pages per MB) and the measured IOPS.
#
# Options (environment): FAST_DIR, SLOW_DIR (default /mnt/fast, /mnt/slow),
# RUNTIME (s, default 30), SIZE (default 1G), FAST_BEI_MS (default 1000),
# DRAM_USD_PER_GB, FAST_DEV_USD, SLOW_DEV_USD (all three for economic BEIs).

set -euo pipefail

FAST_DIR="${FAST_DIR:-/mnt/fast}"
SLOW_DIR="${SLOW_DIR:-/mnt/slow}"
RUNTIME="${RUNTIME:-30}"
SIZE="${SIZE:-1G}"
FAST_BEI_MS="${FAST_BEI_MS:-1000}"

command -v fio >/dev/null || { echo "fio not installed (sudo apt-get install -y fio)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not installed" >&2; exit 1; }

# fio JSON for one directory -> "mean_lat_ms iops"
profile() {
    local dir="$1" name="$2"
    [[ -d "$dir" ]] || { echo "Not a directory: $dir" >&2; exit 1; }
    echo "Profiling $name ($dir, $(findmnt -no SOURCE --target "$dir")) for ${RUNTIME}s..." >&2
    fio --name="profile-$name" --directory="$dir" --filename=fmr-profile.dat \
        --rw=randread --bs=4k --size="$SIZE" --direct=1 \
        --ioengine=psync --iodepth=1 --numjobs=1 \
        --time_based --runtime="$RUNTIME" --ramp_time=5 \
        --output-format=json \
    | python3 -c 'import json,sys; r=json.load(sys.stdin)["jobs"][0]["read"]; print(r["clat_ns"]["mean"]/1e6, r["iops"])'
    rm -f "$dir/fmr-profile.dat"
}

read -r FAST_LAT FAST_IOPS < <(profile "$FAST_DIR" fast)
read -r SLOW_LAT SLOW_IOPS < <(profile "$SLOW_DIR" slow)

python3 - "$FAST_LAT" "$FAST_IOPS" "$SLOW_LAT" "$SLOW_IOPS" "$FAST_BEI_MS" \
    "${DRAM_USD_PER_GB:-}" "${FAST_DEV_USD:-}" "${SLOW_DEV_USD:-}" <<'EOF'
import sys
fl, fi, sl, si, fast_bei = map(float, sys.argv[1:6])
dram_gb, fast_usd, slow_usd = sys.argv[6:9]
ratio = sl / fl
print()
print(f"{'device':8}{'mean lat (ms)':>15}{'IOPS':>12}")
print(f"{'fast':8}{fl:>15.3f}{fi:>12.1f}")
print(f"{'slow':8}{sl:>15.3f}{si:>12.1f}")
print(f"\nlatency ratio slow/fast: {ratio:.2f}")
print("\nTime-based BEIs (eviction order depends only on their ratio):")
print(f"  ./cache_ext_fmr.out --fast_bei_ms {fast_bei:.0f} --slow_bei_ms {fast_bei * ratio:.0f} --cgroup_path <cg>")
print(f"  (same ratio for S4-FIFO: --k {ratio:.2f})")
if dram_gb and fast_usd and slow_usd:
    usd_per_mb = float(dram_gb) / 1024
    pages_per_mb = 256  # 4 KiB pages
    def bei_s(iops, dev_usd):
        return (pages_per_mb / iops) * (float(dev_usd) / usd_per_mb)
    bf, bs = bei_s(fi, fast_usd), bei_s(si, slow_usd)
    print("\nEconomic BEIs (Gray & Putzolu):")
    print(f"  fast {bf:.1f} s, slow {bs:.1f} s (ratio {bs / bf:.2f})")
    print(f"  ./cache_ext_fmr.out --fast_bei_ms {bf * 1000:.0f} --slow_bei_ms {bs * 1000:.0f} --cgroup_path <cg>")
EOF
