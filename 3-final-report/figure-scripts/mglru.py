import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams.update({"font.family": "DejaVu Sans"})

W, H = 3.4, 2.35
fig, ax = plt.subplots(figsize=(W, H))
ax.set_xlim(0, W)
ax.set_ylim(0, H)
ax.axis("off")

EDGE = "#444444"
C_GEN = "#e8e8e8"
C_OLD = "#f3d6d6"
C_DEV = "#d9822b"   # MGLRU-dev overlay colour
DASH = (0, (3, 2))


def box(x, y, w, h, text, fc="white", ec=EDGE, fs=5.4, bold=False, ls="-", tc="black"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.01,rounding_size=0.04",
                                fc=fc, ec=ec, lw=0.6, ls=ls))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", linespacing=1.2, color=tc)


def arrow(p1, p2, color=EDGE, ls="-", rad=0.0, lw=0.6):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-|>", mutation_scale=6, lw=lw,
                                 color=color, linestyle=ls,
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=0, shrinkB=0))


def note(x, y, text, ha="left", va="center", fs=5.0, color="#333333", style="normal"):
    ax.text(x, y, text, ha=ha, va=va, fontsize=fs, color=color, linespacing=1.2, style=style)


# generation lists (oldest left)
gy, gh, gw = 1.20, 0.38, 0.76
xs = [0.04, 0.88, 1.72, 2.56]
labels = ["min_seq\n(oldest)", "min_seq+1", "min_seq+2", "max_seq\n(youngest)"]
cx = [x + gw / 2 for x in xs]
for i, (x, t) in enumerate(zip(xs, labels)):
    box(x, gy, gw, gh, t, C_OLD if i == 0 else C_GEN, bold=(i == 0))

# insertion: unmodified port vs HDD folios under MGLRU-dev
top = 1.96
box(0.04, top, 1.48, 0.32, "new folio (accesses = 1): oldest\ngen (3 gens) or second-oldest (4)", fs=4.9)
arrow((cx[0] - 0.10, top), (cx[0] - 0.10, gy + gh))
arrow((cx[1] - 0.12, top), (cx[1] - 0.12, gy + gh))
box(1.62, top, 1.74, 0.32, "MGLRU-dev: new HDD folio goes\nSLOW_GEN_BOOST (1) gen younger", fs=5.0,
    fc="#fdebd6", ec=C_DEV, ls=DASH, tc="#7a3d00")
arrow((1.80, top), (cx[1] + 0.14, gy + gh), color=C_DEV, ls=DASH, lw=0.8)
arrow((cx[2], top), (cx[2], gy + gh), color=C_DEV, ls=DASH, lw=0.8)

# aging (right, under the lists)
note(W - 0.04, gy - 0.10, "aging: max_seq++ (new gen);\nmin_seq++ at ≤ 4 pages left",
     ha="right", va="top")

# eviction from the oldest generation only
arrow((cx[0] - 0.18, gy), (cx[0] - 0.18, 0.66))
box(0.04, 0.34, 0.86, 0.32, "evict; ghost map\nrecords its tier", fs=5.0)
arrow((cx[0] + 0.22, gy), (cx[1] - 0.20, gy), rad=0.9)
note(0.62, 0.94, "protect if tier > threshold\nor dirty/locked → next gen", ha="left", va="center", fs=4.9)

# access / tiers / threshold
box(0.98, 0.02, 2.38, 0.44,
    "on access: accesses++ (no list move)\n"
    "tier = ⌊log₂ accesses⌋ (max 3)\n"
    "threshold: protect tiers refaulting > 2× tier 0", fs=4.9)
arrow((0.47, 0.34), (0.98, 0.18), rad=0.25)
note(0.40, 0.12, "refaults", ha="center", fs=4.8, style="italic")

fig.savefig(sys.argv[1], dpi=300, bbox_inches="tight", pad_inches=0.02)
