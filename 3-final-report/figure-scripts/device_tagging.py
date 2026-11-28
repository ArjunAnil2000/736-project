import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Polygon

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 7})

W, H = 7.0, 3.0
fig, ax = plt.subplots(figsize=(W, H))
ax.set_xlim(0, W)
ax.set_ylim(-0.22, H)
ax.axis("off")

C_USER = "#dbe9f6"   # userspace loader
C_BPF = "#fde7c8"    # our eBPF policy code
C_KERN = "#e8e8e8"   # cache_ext kernel
EDGE = "#444444"


def box(x, y, w, h, text, color, bold=False):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.05",
                       fc=color, ec=EDGE, lw=0.7)
    ax.add_patch(p)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=6.6, fontweight="bold" if bold else "normal", linespacing=1.25)
    return (x, y, w, h)


def diamond(cx, cy, w, h, text, color):
    pts = [(cx - w / 2, cy), (cx, cy + h / 2), (cx + w / 2, cy), (cx, cy - h / 2)]
    ax.add_patch(Polygon(pts, closed=True, fc=color, ec=EDGE, lw=0.7))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=6.4, linespacing=1.2)


def arrow(x1, y1, x2, y2, label=None, dashed=False, lx=0, ly=0.06):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", lw=0.7, color=EDGE,
                                linestyle=(0, (3, 2)) if dashed else "-",
                                mutation_scale=7, shrinkA=0, shrinkB=0))
    if label:
        ax.text((x1 + x2) / 2 + lx, (y1 + y2) / 2 + ly, label, ha="center",
                va="bottom", fontsize=6, style="italic")


def lane(y, h, title):
    ax.add_patch(FancyBboxPatch((0.02, y), W - 0.04, h, boxstyle="square,pad=0",
                                fc="none", ec="#bbbbbb", lw=0.5, ls=(0, (2, 2))))
    ax.text(0.1, y + h / 2, title, rotation=90, ha="center", va="center",
            fontsize=6.6, fontweight="bold", color="#333333")


bh = 0.42
# ---------------- Lane 1: loader -----------------
y1 = 2.42
lane(2.30, 0.66, "Loader")
b11 = box(0.30, y1, 1.30, bh, "stat(/mnt/fast)\nstat(/mnt/slow)", C_USER)
b12 = box(1.85, y1, 1.75, bh, "st_dev → kernel dev_t;\nreject if same device", C_USER)
b13 = box(3.85, y1, 1.45, bh, "fill dev_idx_map\nfast → 0, slow → 1", C_USER, bold=True)
b14 = box(5.55, y1, 1.35, bh, "attach struct_ops to\ncgroup \"cache_ext*\"", C_USER)
for a, b in [(b11, b12), (b12, b13), (b13, b14)]:
    arrow(a[0] + a[2], y1 + bh / 2, b[0], y1 + bh / 2)

# ---------------- Lane 2: insertion -----------------
y2 = 1.42
lane(1.18, 1.06, "Insertion")
b21 = box(0.30, y2, 1.10, bh, "read() miss:\nfolio added to\npage cache", C_KERN)
b22 = box(1.65, y2, 0.95, bh, "folio_added\nhook", C_BPF)
b23 = box(2.80, y2, 2.10, bh, "folio_dev_idx():\nmapping→host→i_sb→s_dev,\nlook up in dev_idx_map", C_BPF)
b24 = box(5.25, y2 + 0.30, 1.65, 0.38, "DEV_FAST / DEV_SLOW:\nmetadata + device list(s)", C_BPF)
b25 = box(5.25, y2 - 0.22, 1.65, 0.34, "not found: untracked\n(no metadata, no list)", C_KERN)
arrow(b21[0] + b21[2], y2 + bh / 2, b22[0], y2 + bh / 2)
arrow(b22[0] + b22[2], y2 + bh / 2, b23[0], y2 + bh / 2)
arrow(b23[0] + b23[2], y2 + bh / 2 + 0.06, b24[0], b24[1] + b24[3] / 2, "0 / 1", ly=0.09, lx=-0.12)
arrow(b23[0] + b23[2], y2 + bh / 2 - 0.06, b25[0], b25[1] + b25[3] / 2, "−1", ly=-0.15, lx=-0.05)
# map used by lookup
arrow(b13[0] + b13[2] / 2 - 0.25, y1, b23[0] + b23[2] / 2 + 0.25, y2 + bh, dashed=True)
ax.text(0.30, 1.25, "The miss read then calls folio_mark_accessed() → folio_accessed hook",
        fontsize=6, style="italic", color="#333333")

# ---------------- Lane 3: reclaim -----------------
y3 = 0.36
lane(0.04, 1.08, "Reclaim")
b31 = box(0.30, y3, 1.10, bh, "cgroup over\nmemory.max:\nshrink_lruvec", C_KERN)
b32 = box(1.65, y3, 1.20, bh, "evict_folios hook:\n≤ 32 candidates\nper batch", C_BPF)
b33 = box(3.12, y3, 1.15, bh, "kernel validates,\nisolates, reclaims;\nfolio_evicted", C_KERN)
dcx, dcy = 4.98, y3 + bh / 2
diamond(dcx, dcy, 0.95, 0.74, "reclaimed\n> 80%?", C_KERN)
b35 = box(5.62, y3 + 0.44, 1.28, 0.28, "done", C_KERN)
b36 = box(5.62, y3 - 0.27, 1.28, 0.46, "classic active/\ninactive scan of all\nfolios (device-blind)", C_KERN)
arrow(b31[0] + b31[2], y3 + bh / 2, b32[0], y3 + bh / 2)
arrow(b32[0] + b32[2], y3 + bh / 2, b33[0], y3 + bh / 2)
arrow(b33[0] + b33[2], y3 + bh / 2, dcx - 0.475, dcy)
arrow(dcx + 0.24, dcy + 0.18, b35[0], b35[1] + b35[3] / 2, "yes", ly=0.0)
arrow(dcx + 0.24, dcy - 0.18, b36[0], b36[1] + b36[3] / 2, "no", ly=-0.12)

# ---------------- legend -----------------
lx = 3.55
for i, (c, t) in enumerate([(C_USER, "userspace loader"), (C_BPF, "our eBPF policy"),
                            (C_KERN, "cache_ext kernel")]):
    ax.add_patch(FancyBboxPatch((lx + i * 1.15, -0.17), 0.12, 0.09, boxstyle="square,pad=0",
                                fc=c, ec=EDGE, lw=0.5))
    ax.text(lx + i * 1.15 + 0.16, -0.125, t, va="center", fontsize=5.8)

fig.savefig(sys.argv[1], dpi=300, bbox_inches="tight", pad_inches=0.02)
