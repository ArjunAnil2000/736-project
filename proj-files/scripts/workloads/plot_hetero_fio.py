#!/usr/bin/env python3
"""
plot_hetero_fio.py - Summarise and plot results from hetero_fio.py.

  python3 plot_hetero_fio.py results/hetero_fio.jsonl            # -> .csv + .png
  python3 plot_hetero_fio.py results/hetero_fio.jsonl --labels default,mru

Every point is the mean over iterations; error bars show min..max.
Four panels share the x axis (cgroup memory.max):
  1. throughput (IOPS)            - one line per policy label
  2. p99 read latency             - one line per policy label
  3. reads that reached each disk - solid = slow device, dashed = fast device
  4. % of each file still cached  - solid = slow file,   dashed = fast file
"""

import argparse
import csv
import json
import os
from collections import defaultdict
from statistics import mean

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# Fixed categorical order: a label keeps its colour no matter which subset is plotted.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"]
INK, MUTED, GRID = "#1a1a19", "#6b6a63", "#e4e3dd"
GiB = 2**30


def load(path, labels):
    recs = [json.loads(l) for l in open(path) if l.strip()]
    if labels:
        recs = [r for r in recs if r["label"] in labels]
    return recs


def metrics(r):
    d = r["devices"]

    def res(role):
        b = d[role].get("resident_bytes")
        return 100 * b / r["file_bytes"] if b is not None else None

    return {
        "iops": r["fio"]["iops"],
        "p99_ms": (r["fio"]["lat_p99_us"] or 0) / 1e3,
        "mean_ms": r["fio"]["lat_mean_us"] / 1e3,
        "reads_fast": d["fast"].get("reads"),
        "reads_slow": d["slow"].get("reads"),
        "disk_ms_fast": d["fast"].get("read_ms_total"),
        "disk_ms_slow": d["slow"].get("read_ms_total"),
        "wait_s_fast": (d["fast"].get("read_ms_total") or 0) / 1e3,
        "wait_s_slow": (d["slow"].get("read_ms_total") or 0) / 1e3,
        "avg_ms_fast": d["fast"].get("avg_read_ms"),
        "avg_ms_slow": d["slow"].get("avg_read_ms"),
        "cached_fast_pct": res("fast"),
        "cached_slow_pct": res("slow"),
        "io_some_s": r["psi_us"]["io"].get("some", 0) / 1e6 if r["psi_us"]["io"] else None,
        "refaults": r["memory_stat_delta"].get("workingset_refault_file"),
    }


def aggregate(recs):
    groups = defaultdict(list)
    for r in recs:
        groups[(r["label"], r["cgroup_bytes"])].append(metrics(r))
    rows = []
    for (label, cg), ms in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        row = {"label": label, "cgroup_GiB": cg / GiB, "cgroup_MiB": cg / 2**20, "n": len(ms)}
        for k in ms[0]:
            vals = [m[k] for m in ms if m[k] is not None]
            row[k] = mean(vals) if vals else None
            row[k + "_min"] = min(vals) if vals else None
            row[k + "_max"] = max(vals) if vals else None
        rows.append(row)
    return rows


def write_csv(rows, path):
    keys = ["label", "cgroup_MiB", "n", "iops", "p99_ms", "mean_ms", "reads_fast",
            "reads_slow", "avg_ms_fast", "avg_ms_slow", "wait_s_fast", "wait_s_slow",
            "cached_fast_pct",
            "cached_slow_pct", "io_some_s", "refaults"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items()})


def style(ax, title, ylabel):
    ax.set_title(title, loc="left", fontsize=11, color=INK, pad=8)
    ax.set_ylabel(ylabel, color=MUTED, fontsize=9)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=8)
    ax.set_ylim(bottom=0)


def line(ax, rows, key, color, ls="-", label=None):
    rows = [r for r in rows if r.get(key) is not None]
    if not rows:
        return
    x = [r["cgroup_MiB"] for r in rows]
    y = [r[key] for r in rows]
    lo = [r[key] - r[key + "_min"] for r in rows]
    hi = [r[key + "_max"] - r[key] for r in rows]
    ax.errorbar(x, y, yerr=[lo, hi], color=color, linestyle="none",
                capsize=3, elinewidth=1)
    ax.plot(x, y, color=color, linestyle=ls, linewidth=2, marker="o",
            markersize=5, label=label)
    ax.set_xscale("log", base=2)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{v:g}" for v in x])
    ax.minorticks_off()


def plot(rows, out_png, title):
    labels = list(dict.fromkeys(r["label"] for r in rows))
    color = {l: SERIES[i % len(SERIES)] for i, l in enumerate(labels)}
    by = {l: [r for r in rows if r["label"] == l] for l in labels}

    fig, axes = plt.subplots(2, 2, figsize=(13, 7.5), sharex=True)
    (a1, a2), (a3, a4) = axes
    for l in labels:
        line(a1, by[l], "iops", color[l], label=l)
        line(a2, by[l], "p99_ms", color[l], label=l)
        line(a3, by[l], "wait_s_slow", color[l], "-", f"{l} · slow dev")
        line(a3, by[l], "wait_s_fast", color[l], "--", f"{l} · fast dev")
        line(a4, by[l], "cached_slow_pct", color[l], "-", f"{l} · slow file")
        line(a4, by[l], "cached_fast_pct", color[l], "--", f"{l} · fast file")

    style(a1, "Throughput", "IOPS")
    style(a2, "p99 read latency", "ms")
    style(a3, "Time spent on page-cache misses, per device", "disk read time (s)")
    style(a4, "Share of each file still in page cache at end", "% cached")
    a4.set_ylim(0, 105)
    for ax in (a3, a4):
        ax.set_xlabel("cgroup memory.max (MiB)", color=MUTED, fontsize=9)
    for ax in (a1, a2):
        ax.legend(frameon=False, fontsize=8, labelcolor=INK, loc="lower right")
    for ax in (a3, a4):
        ax.legend(frameon=False, fontsize=8, labelcolor=INK, loc="upper left",
                  bbox_to_anchor=(1.0, 1.0), handlelength=3.5)
    a4.text(0.02, 0.95, "where a policy's fast and slow lines overlap, it caches both files equally",
            transform=a4.transAxes, fontsize=8, color=MUTED, va="top")
    fig.suptitle(title, x=0.01, ha="left", fontsize=13, color=INK)
    fig.tight_layout()
    fig.savefig(out_png, dpi=160)
    print(f"wrote {out_png}")


def plot_wait(rows, out_png, label):
    """One bar chart for a slide: disk read time per device, one policy."""
    rows = [r for r in rows if r["label"] == label]
    if not rows:
        return
    import numpy as np
    x = np.arange(len(rows))
    w = 0.38
    fast = [r["wait_s_fast"] for r in rows]
    slow = [r["wait_s_slow"] for r in rows]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    b1 = ax.bar(x - w / 2 - 0.01, fast, w, color=SERIES[0], label="fast device")
    b2 = ax.bar(x + w / 2 + 0.01, slow, w, color=SERIES[1], label="slow device (dm-delay)")
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 2, f"{b.get_height():.0f} s",
                    ha="center", va="bottom", fontsize=9, color=INK)
    for i, r in enumerate(rows):
        share = r["wait_s_slow"] / (r["wait_s_fast"] + r["wait_s_slow"])
        ax.text(i, -0.16, f"slow = {share:.0%} of wait", transform=ax.get_xaxis_transform(),
                ha="center", fontsize=9, color=MUTED)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{r['cgroup_MiB']:g} MiB" for r in rows])
    style(ax, f"Disk read time per device during a 30 s run ({label} policy)", "seconds")
    ax.set_ylim(0, max(slow) * 1.3)
    ax.legend(frameon=False, fontsize=9, labelcolor=INK, loc="upper left", ncol=2)
    fig.tight_layout()
    fig.savefig(out_png, dpi=160)
    print(f"wrote {out_png}")


def plot_policies(rows, out_png, labels):
    """Meeting chart: IOPS per policy (change vs the first label) and how much
    of the cache each policy gives to the slow file."""
    import numpy as np
    sizes = sorted({r["cgroup_MiB"] for r in rows})
    get = {(r["label"], r["cgroup_MiB"]): r for r in rows}
    n = len(labels)
    w = 0.8 / n
    x = np.arange(len(sizes))
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 4.8))
    for i, l in enumerate(labels):
        c = SERIES[i % len(SERIES)]
        xs = x - 0.4 + w / 2 + i * w
        iops = [get[(l, m)]["iops"] if (l, m) in get else 0 for m in sizes]
        bars = a1.bar(xs, iops, w * 0.94, color=c, label=l)
        for j, b in enumerate(bars):
            base = get.get((labels[0], sizes[j]))
            txt = f"{b.get_height():.0f}"
            if i > 0 and base and b.get_height():
                txt += f"\n{(b.get_height() / base['iops'] - 1):+.0%}"
            a1.text(b.get_x() + b.get_width() / 2, b.get_height() + 15, txt,
                    ha="center", va="bottom", fontsize=8, color=INK)
        share = []
        for m in sizes:
            r = get.get((l, m))
            f, sl = (r or {}).get("cached_fast_pct"), (r or {}).get("cached_slow_pct")
            share.append(100 * sl / (f + sl) if r and f is not None and (f + sl) > 0 else 0)
        bars = a2.bar(xs, share, w * 0.94, color=c, label=l)
        for b in bars:
            a2.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.5, f"{b.get_height():.0f}%",
                    ha="center", va="bottom", fontsize=8, color=INK)
    for ax in (a1, a2):
        ax.set_xticks(x)
        ax.set_xticklabels([f"{m:g} MiB" for m in sizes])
        ax.set_xlabel("cgroup memory.max", color=MUTED, fontsize=9)
    style(a1, f"Throughput (change vs {labels[0]})", "IOPS")
    a1.set_ylim(0, max(r["iops"] for r in rows) * 1.25)
    style(a2, "Share of cached pages that belong to the slow file", "% of cached pages")
    a2.set_ylim(0, 115)
    a2.axhline(50, color=GRID, linewidth=1, linestyle="--")
    a1.legend(frameon=False, fontsize=9, labelcolor=INK, loc="upper left", ncol=n)
    fig.tight_layout()
    fig.savefig(out_png, dpi=160)
    print(f"wrote {out_png}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", help="jsonl written by hetero_fio.py")
    ap.add_argument("--labels", default="", help="comma-separated subset, in plot order")
    ap.add_argument("--out", default="", help="output prefix (default: next to results)")
    ap.add_argument("--title", default="Two-device fio: fast file + dm-delay file, one cgroup")
    args = ap.parse_args()

    labels = [l for l in args.labels.split(",") if l]
    recs = load(args.results, labels)
    if not recs:
        raise SystemExit("no matching records")
    if labels:  # keep the requested order (and therefore colours)
        recs.sort(key=lambda r: labels.index(r["label"]))
    rows = aggregate(recs)
    if labels:
        rows.sort(key=lambda r: (labels.index(r["label"]), r["cgroup_MiB"]))

    prefix = args.out or os.path.splitext(args.results)[0]
    write_csv(rows, prefix + "_summary.csv")
    print(f"wrote {prefix}_summary.csv")
    w = max(len(r["label"]) for r in rows)
    print(f"{'label':<{w}}  cg(MiB)   IOPS      p99(ms)  reads fast/slow     cached fast/slow")
    for r in rows:
        cf = f"{r['cached_fast_pct']:.0f}%" if r["cached_fast_pct"] is not None else "-"
        cs = f"{r['cached_slow_pct']:.0f}%" if r["cached_slow_pct"] is not None else "-"
        print(f"{r['label']:<{w}}  {r['cgroup_MiB']:>6.0f}  {r['iops']:>9.0f}  {r['p99_ms']:>8.2f}  "
              f"{r['reads_fast'] or 0:>8.0f}/{r['reads_slow'] or 0:<8.0f}  {cf:>5}/{cs}")
    plot(rows, prefix + ".png", args.title)
    plot_wait(rows, prefix + "_wait.png", labels[0] if labels else rows[0]["label"])
    plot_policies(rows, prefix + "_policies.png",
                  labels or list(dict.fromkeys(r["label"] for r in rows)))


if __name__ == "__main__":
    main()
