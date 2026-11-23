#!/usr/bin/env python3
"""
hetero_fio.py - Two-device page-cache workload for the heterogeneous cache_ext project.

One fio job reads from TWO files, one on the fast device and one on the slow
(dm-delay) device, picking a file at random for every I/O. The job runs inside
a single cgroup-v2 whose memory.max is smaller than the two files together, so
the kernel (or a cache_ext policy attached to that cgroup) has to choose whose
pages to evict.

For every (cgroup size, policy) point it records:
  * fio: IOPS, bandwidth, completion-latency percentiles (p50/p99/p99.9)
  * /proc/diskstats deltas per device: reads from disk (= page-cache misses
    that reached the device), bytes read, avg device read latency
  * the cgroup's io.pressure / memory.pressure (PSI) deltas: time stalled on I/O
  * the cgroup's memory.stat deltas: workingset_refault_file etc.
  * fincore at the end of the run: how much of each file is still cached

Must run as root on the node (it writes to /sys/fs/cgroup and drop_caches).

Typical use (baseline kernel policy, sweep cgroup sizes):

  sudo python3 hetero_fio.py \
      --fast-dir /mnt/hetero/fast --slow-dir /mnt/hetero/slow \
      --file-size 4G --cgroup-sizes 1G,2G,4G,6G \
      --label default --results results/hetero_fio.jsonl

With a cache_ext policy attached to the cgroup (on the cache_ext kernel):

  sudo python3 hetero_fio.py ... --label mru \
      --policy-loader ~/736-project/proj-files/cache_ext/policies/cache_ext_mru.out \
      --watch-dir /mnt/hetero --mglru off

--watch-dir must be a directory that contains BOTH files (e.g. the common parent
of the two mount points). The cache_ext loaders walk it recursively and only
manage pages of files they found there.
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime

CGROUP_ROOT = "/sys/fs/cgroup"
UNITS = {"K": 2**10, "M": 2**20, "G": 2**30, "T": 2**40}


# ---------------------------------------------------------------- helpers
def parse_size(s: str) -> int:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*", s, re.I)
    if not m:
        raise argparse.ArgumentTypeError(f"bad size: {s}")
    return int(float(m.group(1)) * UNITS.get(m.group(2).upper(), 1))


def fmt_size(n: int) -> str:
    for u in "TGMK":
        if n >= UNITS[u] and n % UNITS[u] == 0:
            return f"{n // UNITS[u]}{u}"
    return str(n)


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw).stdout


def write(path, val):
    with open(path, "w") as f:
        f.write(str(val))


def read(path):
    with open(path) as f:
        return f.read()


# ---------------------------------------------------------------- devices
def block_dev_of(path: str):
    """Return (name, 'MAJ:MIN') of the block device backing `path`.

    Uses the partition / dm device itself, not the parent disk, so that a
    fast partition and a dm-delay device built on the same physical disk
    stay separate in /proc/diskstats."""
    st = os.stat(path)
    majmin = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    uevent = f"/sys/dev/block/{majmin}/uevent"
    name = None
    if os.path.exists(uevent):
        for line in read(uevent).splitlines():
            if line.startswith("DEVNAME="):
                name = line.split("=", 1)[1]
    return name, majmin


def diskstats():
    """name -> (reads_completed, sectors_read, ms_reading)."""
    out = {}
    for line in read("/proc/diskstats").splitlines():
        p = line.split()
        out[p[2]] = (int(p[3]), int(p[5]), int(p[6]))
    return out


def disk_delta(before, after, name):
    if name not in before or name not in after:
        return None
    r0, s0, t0 = before[name]
    r1, s1, t1 = after[name]
    reads = r1 - r0
    return {
        "reads": reads,
        "read_bytes": (s1 - s0) * 512,
        "read_ms_total": t1 - t0,
        "avg_read_ms": (t1 - t0) / reads if reads else 0.0,
    }


def fincore(path):
    """Bytes of `path` currently in the page cache (mmap + mincore)."""
    import ctypes
    import mmap

    size = os.path.getsize(path)
    if size == 0:
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
    page = mmap.PAGESIZE
    npages = (size + page - 1) // page
    fd = os.open(path, os.O_RDONLY)
    try:
        addr = libc.mmap(None, size, mmap.PROT_READ, mmap.MAP_SHARED, fd, 0)
        if addr in (None, ctypes.c_void_p(-1).value):
            return None
        try:
            vec = ctypes.create_string_buffer(npages)
            if libc.mincore(ctypes.c_void_p(addr), size, vec) != 0:
                return None
            return sum(b & 1 for b in vec.raw) * page
        finally:
            libc.munmap(ctypes.c_void_p(addr), size)
    finally:
        os.close(fd)


# ---------------------------------------------------------------- cgroup
class Cgroup:
    def __init__(self, name):
        self.name = name
        self.path = os.path.join(CGROUP_ROOT, name)

    def create(self, mem_bytes):
        self.destroy()
        ctl = read(os.path.join(CGROUP_ROOT, "cgroup.subtree_control"))
        for c in ("memory", "io"):
            if c not in ctl.split():
                write(os.path.join(CGROUP_ROOT, "cgroup.subtree_control"), f"+{c}")
        os.mkdir(self.path)
        write(os.path.join(self.path, "memory.max"), mem_bytes)
        if os.path.exists(os.path.join(self.path, "memory.swap.max")):
            write(os.path.join(self.path, "memory.swap.max"), 0)

    def destroy(self):
        if not os.path.isdir(self.path):
            return
        procs = os.path.join(self.path, "cgroup.procs")
        for pid in read(procs).split():
            try:
                os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        for _ in range(50):
            try:
                os.rmdir(self.path)
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"could not remove {self.path}")

    def wrap(self, cmd):
        """Command that moves itself into this cgroup, then execs `cmd`."""
        procs = os.path.join(self.path, "cgroup.procs")
        return ["sh", "-c", f'echo $$ > {procs} && exec "$@"', "sh", *cmd]

    def memory_current(self):
        return int(read(os.path.join(self.path, "memory.current")))

    def memory_stat(self):
        out = {}
        for line in read(os.path.join(self.path, "memory.stat")).splitlines():
            k, v = line.split()
            out[k] = int(v)
        return out

    def pressure(self, res):
        """PSI totals in microseconds: {'some': .., 'full': ..}."""
        out = {}
        try:
            text = read(os.path.join(self.path, f"{res}.pressure"))
        except OSError:  # PSI off (CONFIG_PSI_DEFAULT_DISABLED without psi=1)
            return out
        for line in text.splitlines():
            kind = line.split()[0]
            total = int(re.search(r"total=(\d+)", line).group(1))
            out[kind] = total
        return out


class NoCgroup(Cgroup):
    """Debug stand-in: runs unconfined, collects no cgroup stats."""

    def __init__(self):
        super().__init__("none")

    def create(self, mem_bytes):
        pass

    def destroy(self):
        pass

    def wrap(self, cmd):
        return cmd

    def memory_stat(self):
        return {}

    def memory_current(self):
        return None

    def pressure(self, res):
        return {}


# ---------------------------------------------------------------- policy
class Policy:
    def __init__(self, loader, watch_dir, cgroup):
        self.loader, self.watch_dir, self.cgroup = loader, watch_dir, cgroup
        self.proc = None

    def start(self, mem_bytes):
        if not self.loader:
            return
        cmd = [self.loader, "--watch_dir", self.watch_dir,
               "--cgroup_path", self.cgroup.path]
        if os.path.basename(self.loader) == "cache_ext_s3fifo.out":
            cmd += ["--cgroup_size", str(mem_bytes)]
        log(f"starting policy: {' '.join(cmd)}")
        # stdin is a pipe: cache_ext loaders exit on any keypress (getchar), so
        # they must not share the terminal. Closing the pipe or SIGINT stops them.
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        time.sleep(10)  # same settle time cache_ext's bench_lib uses
        if self.proc.poll() is not None:
            raise RuntimeError("policy loader exited: " + self.proc.stderr.read())

    def stop(self):
        if not self.proc:
            return
        self.proc.send_signal(signal.SIGINT)
        try:
            out, err = self.proc.communicate(input="\n", timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, err = self.proc.communicate()
        self.proc = None
        return out, err


def set_mglru(mode):
    path = "/sys/kernel/mm/lru_gen/enabled"
    if mode == "keep" or not os.path.exists(path):
        return read(path).strip() if os.path.exists(path) else "n/a"
    write(path, "y" if mode == "on" else "n")
    return read(path).strip()


# ---------------------------------------------------------------- fio
def ensure_file(path, size):
    if os.path.exists(path) and os.path.getsize(path) == size:
        return
    log(f"creating {fmt_size(size)} file {path} (random data, one-time)")
    bs = 2**20
    subprocess.run(["dd", "if=/dev/urandom", f"of={path}", f"bs={bs}",
                    f"count={size // bs}", "status=none"], check=True)
    os.sync()


def fio_cmd(args, files, runtime, name):
    # fio uses ':' to separate filenames; escape any in the paths.
    fname = ":".join(f.replace(":", "\\:") for f in files)
    return [
        "fio", f"--name={name}", f"--filename={fname}",
        "--file_service_type=random",          # pick a file at random per I/O
        f"--rw={args.rw}", f"--bs={args.bs}",
        f"--random_distribution={args.dist}",
        "--direct=0", "--invalidate=0",        # buffered I/O, keep the warm cache
        "--ioengine=psync", f"--numjobs={args.numjobs}",
        "--time_based", f"--runtime={runtime}",
        "--group_reporting", "--randrepeat=0",
        "--output-format=json",
    ]


def summarize_fio(js):
    j = js["jobs"][0]["read"]
    pct = j.get("clat_ns", {}).get("percentile", {})

    def p(k):
        v = pct.get(k)
        return v / 1e3 if v is not None else None  # -> microseconds

    return {
        "iops": j["iops"],
        "bw_MiBps": j["bw_bytes"] / 2**20,
        "ios": j["total_ios"],
        "lat_mean_us": j["clat_ns"]["mean"] / 1e3,
        "lat_p50_us": p("50.000000"),
        "lat_p99_us": p("99.000000"),
        "lat_p999_us": p("99.900000"),
    }


def drop_caches():
    os.sync()
    write("/proc/sys/vm/drop_caches", 3)


# ---------------------------------------------------------------- main
def run_point(args, cg, policy, mem_bytes, it, files, devs):
    log(f"=== {args.label}: cgroup {fmt_size(mem_bytes)}, iteration {it}")
    drop_caches()
    cg.create(mem_bytes)
    try:
        policy.start(mem_bytes)

        if args.prefill:
            # Fill the cgroup quickly with large sequential reads, half from each
            # file, so evictions start right away. Random 4k misses alone would
            # take minutes to fill it, and a cache that is not full evicts nothing.
            # Chunks alternate between the files so neither file's pages are
            # all newer than the other's (that would bias LRU-style eviction).
            t0 = time.time()
            mib = max(1, mem_bytes // 2 // 2**20)
            chunk = 8
            for off in range(0, mib, chunk):
                n = min(chunk, mib - off)
                for f in files:
                    subprocess.run(cg.wrap(["dd", f"if={f}", "of=/dev/null", "bs=1M",
                                            f"skip={off}", f"count={n}", "status=none"]),
                                   check=True)
            log(f"prefill {2 * mib} MiB in {time.time() - t0:.0f}s")

        if args.warmup > 0:
            log(f"warmup {args.warmup}s")
            subprocess.run(cg.wrap(fio_cmd(args, files, args.warmup, "warmup")),
                           check=True, capture_output=True)

        if policy.proc and policy.proc.poll() is not None:
            raise RuntimeError("policy loader died during warmup: " + policy.proc.stderr.read())
        cur0 = cg.memory_current()
        d0, m0 = diskstats(), cg.memory_stat()
        io0, mp0 = cg.pressure("io"), cg.pressure("memory")
        log(f"measure {args.runtime}s")
        out = subprocess.run(cg.wrap(fio_cmd(args, files, args.runtime, "measure")),
                             check=True, capture_output=True, text=True).stdout
        d1, m1 = diskstats(), cg.memory_stat()
        cur1 = cg.memory_current()
        io1, mp1 = cg.pressure("io"), cg.pressure("memory")
        resident = {role: fincore(f) for role, f in zip(("fast", "slow"), files)}
        if policy.proc and policy.proc.poll() is not None:
            raise RuntimeError("policy loader died during measurement: " + policy.proc.stderr.read())
    finally:
        policy.stop()
        cg.destroy()

    rec = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "label": args.label,
        "kernel": os.uname().release,
        "mglru": args.mglru_state,
        "policy_loader": os.path.basename(args.policy_loader) if args.policy_loader else None,
        "cgroup_bytes": mem_bytes,
        "file_bytes": args.file_size,
        "cgroup_name": args.cgroup_name,
        "cgroup_used_bytes": {"start": cur0, "end": cur1},
        "iteration": it,
        "workload": {"rw": args.rw, "bs": args.bs, "dist": args.dist,
                     "numjobs": args.numjobs, "runtime": args.runtime,
                     "warmup": args.warmup},
        "fio": summarize_fio(json.loads(out[out.index("{"):])),
        "devices": {},
        "psi_us": {"io": {k: io1[k] - io0[k] for k in io1},
                   "memory": {k: mp1[k] - mp0[k] for k in mp1}},
        "memory_stat_delta": {k: m1[k] - m0.get(k, 0) for k in
                              ("workingset_refault_file", "workingset_activate_file",
                               "pgmajfault", "pgscan", "pgsteal") if k in m1},
    }
    for role, (name, majmin) in devs.items():
        rec["devices"][role] = {"name": name, "majmin": majmin,
                                "resident_bytes": resident[role],
                                **(disk_delta(d0, d1, name) or {})}
    return rec


def full(r):
    """Share of memory.max in use when measurement started."""
    used = (r.get("cgroup_used_bytes") or {}).get("start")
    return f"{used / r['cgroup_bytes']:.0%}" if used is not None else "-"


def print_row(r):
    f, dv = r["fio"], r["devices"]

    def g(role, k, fmt="{:.0f}"):
        v = dv[role].get(k)
        return fmt.format(v) if v is not None else "-"

    res = lambda role: (f"{dv[role]['resident_bytes'] / r['file_bytes']:.0%}"
                        if dv[role].get("resident_bytes") is not None else "-")
    print(f"  {r['label']:<10} cg={fmt_size(r['cgroup_bytes']):<5} "
          f"iops={f['iops']:>9.0f}  p99={f['lat_p99_us'] or 0:>9.0f}us  "
          f"disk reads fast={g('fast', 'reads'):>8} slow={g('slow', 'reads'):>8}  "
          f"cached fast={res('fast'):>4} slow={res('slow'):>4}  "
          f"io.some={r['psi_us']['io'].get('some', 0) / 1e6:.1f}s  "
          f"cgroup full={full(r)}", flush=True)
    for role in ("fast", "slow"):
        v = dv[role].get("avg_read_ms")
        if v is not None:
            print(f"      {role}: {dv[role].get('reads', 0)} disk reads, "
                  f"avg {v:.2f} ms each", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fast-dir", required=True)
    ap.add_argument("--slow-dir", required=True)
    ap.add_argument("--file-size", type=parse_size, default=parse_size("4G"),
                    help="size of EACH file (default 4G)")
    ap.add_argument("--cgroup-sizes", default="1G,2G,4G,6G",
                    help="comma-separated memory.max values to sweep")
    ap.add_argument("--iterations", type=int, default=3)
    ap.add_argument("--runtime", type=int, default=60, help="measured seconds")
    ap.add_argument("--warmup", type=int, default=60, help="unmeasured warmup seconds")
    ap.add_argument("--no-prefill", dest="prefill", action="store_false",
                    help="skip filling the cgroup with sequential reads before warmup")
    ap.add_argument("--numjobs", type=int, default=8)
    ap.add_argument("--rw", default="randread")
    ap.add_argument("--bs", default="4k")
    ap.add_argument("--dist", default="zipf:0.9:0",
                    help="fio random_distribution. zipf:THETA:0 pins the hot set so all threads share it (default zipf:0.9:0; YCSB uses 0.99)")
    ap.add_argument("--label", default="default", help="name for this policy/config")
    ap.add_argument("--policy-loader", default="", help="cache_ext loader (*.out)")
    ap.add_argument("--watch-dir", default="", help="dir containing both files")
    ap.add_argument("--mglru", choices=["on", "off", "keep"], default="keep")
    ap.add_argument("--cgroup-name", default="",
                    help="default: cache_ext_hetero with --policy-loader, else baseline_hetero. "
                         "The cache_ext kernel only runs policy hooks in cgroups whose name "
                         "starts with 'cache_ext' (mm/memcontrol.c, mem_cgroup_css_online)")
    ap.add_argument("--results", default="results/hetero_fio.jsonl")
    ap.add_argument("--no-cgroup", action="store_true",
                    help="debug only: run without a cgroup (no memory limit)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("run as root (sudo): needs /sys/fs/cgroup and drop_caches")
    if not shutil.which("fio"):
        sys.exit("fio not found (sudo apt-get install -y fio)")
    if args.policy_loader and not args.watch_dir:
        sys.exit("--policy-loader needs --watch-dir (a dir containing both files)")
    if not args.cgroup_name:
        args.cgroup_name = "cache_ext_hetero" if args.policy_loader else "baseline_hetero"
    if args.policy_loader and not args.cgroup_name.startswith("cache_ext"):
        sys.exit("with --policy-loader the cgroup name must start with 'cache_ext', "
                 "or the kernel never calls the policy")

    files = [os.path.join(args.fast_dir, "hetero_fast.dat"),
             os.path.join(args.slow_dir, "hetero_slow.dat")]
    for f in files:
        ensure_file(f, args.file_size)
    if args.watch_dir:
        wd = os.path.realpath(args.watch_dir)
        for f in files:
            if not os.path.realpath(f).startswith(wd + os.sep):
                sys.exit(f"{f} is not under --watch-dir {wd}; the policy would ignore it")

    devs = {"fast": block_dev_of(args.fast_dir), "slow": block_dev_of(args.slow_dir)}
    log(f"fast dev={devs['fast']}  slow dev={devs['slow']}")
    if devs["fast"] == devs["slow"]:
        log("WARNING: both dirs are on the same block device; per-device numbers will be identical")

    args.mglru_state = set_mglru(args.mglru)
    log(f"MGLRU: {args.mglru_state}   kernel: {os.uname().release}")

    cg = NoCgroup() if args.no_cgroup else Cgroup(args.cgroup_name)
    policy = Policy(args.policy_loader, args.watch_dir, cg)
    os.makedirs(os.path.dirname(os.path.abspath(args.results)), exist_ok=True)

    sizes = [parse_size(s) for s in args.cgroup_sizes.split(",")]
    for mem in sizes:
        if mem >= 2 * args.file_size:
            log(f"note: cgroup {fmt_size(mem)} >= both files; expect ~no eviction")
        for it in range(1, args.iterations + 1):
            rec = run_point(args, cg, policy, mem, it, files, devs)
            with open(args.results, "a") as f:
                f.write(json.dumps(rec) + "\n")
            print_row(rec)
    log(f"done -> {args.results}")


if __name__ == "__main__":
    main()
