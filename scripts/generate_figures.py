"""
Generate evaluation figures for the thesis writeup.

Run from the repo root after entering the nix dev shell:
    python scripts/generate_figures.py

Outputs three PDFs to writeup/figures/:
    scenario_scores.pdf    — attack scenario A-I suspicion scores vs threshold
    scenario_h_progression.pdf — incremental compromise score over 3 scans
    fleet_boost_f12.pdf    — fleet correlation threshold-crossing (F12)
"""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

OUT = Path("writeup/figures")
OUT.mkdir(parents=True, exist_ok=True)

THRESHOLD = 3.0

# ---------------------------------------------------------------------------
# Shared style
# ---------------------------------------------------------------------------

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 150,
})

DETECTED_COLOR = "#2c7bb6"
MISSED_COLOR = "#d7191c"
THRESHOLD_COLOR = "#888888"
FLEET_BEFORE = "#fdae61"
FLEET_AFTER = "#2c7bb6"

# ---------------------------------------------------------------------------
# Figure 1: Attack scenario scores A–I
# ---------------------------------------------------------------------------

scenarios = [
    ("A\nIP Spoofing",              5.0,  True),
    ("B\nService Backdoor",         4.0,  True),
    ("C\nMAC Spoofing",             4.5,  True),
    ("D\nIdentity Conflict",        1.5,  True),   # detected via fleet in F12
    ("E\nOS Spoof (neg.)",          2.0,  False),  # below threshold — by design
    ("F\nMulti-Port Takeover",      8.0,  True),
    ("G\nIoT Botnet",               3.0,  True),
    ("H\nIncremental Compromise",   6.5,  True),
    ("I\nService Mimicry (neg.)",   0.0,  False),  # undetected — by design
]

labels = [s[0] for s in scenarios]
scores = [s[1] for s in scenarios]
detected = [s[2] for s in scenarios]
colors = [DETECTED_COLOR if d else MISSED_COLOR for d in detected]

fig, ax = plt.subplots(figsize=(8, 4.2))
bars = ax.barh(labels, scores, color=colors, height=0.55, zorder=2)

ax.axvline(THRESHOLD, color=THRESHOLD_COLOR, linestyle="--", linewidth=1.2,
           label=f"Investigation threshold ({THRESHOLD})", zorder=3)

# Annotate score values
for bar, score in zip(bars, scores):
    if score > 0:
        ax.text(score + 0.12, bar.get_y() + bar.get_height() / 2,
                f"{score:.1f}", va="center", ha="left", fontsize=8.5)

ax.set_xlabel("Suspicion score")
ax.set_xlim(0, 10)
ax.set_title("Suspicion scores for attack scenarios A–I\n(post-warmup, single tick)", pad=10)
ax.grid(axis="x", linestyle=":", alpha=0.5, zorder=1)

detected_patch = mpatches.Patch(color=DETECTED_COLOR, label="Detected (score ≥ 3.0)")
missed_patch = mpatches.Patch(color=MISSED_COLOR, label="Not detected (by design)")
threshold_line = plt.Line2D([0], [0], color=THRESHOLD_COLOR, linestyle="--",
                             label=f"Threshold = {THRESHOLD}")
ax.legend(handles=[detected_patch, missed_patch, threshold_line],
          loc="lower right", framealpha=0.85, fontsize=8.5)

fig.tight_layout()
path = OUT / "scenario_scores.pdf"
fig.savefig(path, bbox_inches="tight")
print(f"Saved: {path}")
plt.close(fig)

# ---------------------------------------------------------------------------
# Figure 2: Scenario H — incremental compromise score progression
# ---------------------------------------------------------------------------

scan_labels = ["Warmup\n(scans 1–6)", "Scan 7\nOS shift", "Scan 8\nPort change", "Scan 9\nBackdoor"]
scan_scores = [0.0, 2.0, 2.5, 6.5]

fig, ax = plt.subplots(figsize=(5.5, 3.8))

bar_colors = []
for s in scan_scores:
    if s == 0.0:
        bar_colors.append("#cccccc")
    elif s >= THRESHOLD:
        bar_colors.append(DETECTED_COLOR)
    else:
        bar_colors.append(FLEET_BEFORE)

bars = ax.bar(scan_labels, scan_scores, color=bar_colors, width=0.5, zorder=2)
ax.axhline(THRESHOLD, color=THRESHOLD_COLOR, linestyle="--", linewidth=1.2,
           label=f"Threshold = {THRESHOLD}", zorder=3)

# Annotate
for bar, score in zip(bars, scan_scores):
    if score > 0:
        ax.text(bar.get_x() + bar.get_width() / 2, score + 0.12,
                f"{score:.1f}", ha="center", va="bottom", fontsize=9)

ax.set_ylabel("Suspicion score")
ax.set_title("Scenario H — incremental compromise\nscore progression across scans", pad=10)
ax.set_ylim(0, 8.0)
ax.grid(axis="y", linestyle=":", alpha=0.5, zorder=1)

warmup_patch = mpatches.Patch(color="#cccccc", label="Warmup (no scoring)")
below_patch = mpatches.Patch(color=FLEET_BEFORE, label="Below threshold")
above_patch = mpatches.Patch(color=DETECTED_COLOR, label="Above threshold")
ax.legend(handles=[warmup_patch, below_patch, above_patch,
                   plt.Line2D([0], [0], color=THRESHOLD_COLOR, linestyle="--",
                              label=f"Threshold = {THRESHOLD}")],
          loc="upper left", framealpha=0.85, fontsize=8.5)

fig.tight_layout()
path = OUT / "scenario_h_progression.pdf"
fig.savefig(path, bbox_inches="tight")
print(f"Saved: {path}")
plt.close(fig)

# ---------------------------------------------------------------------------
# Figure 3: Fleet boost F12 — threshold crossing via fleet correlation
# ---------------------------------------------------------------------------

# Scenario D/F12: two peers both score ~1.5 individually.
# Fleet pattern identity_sweep fires (+2.0 each) → both cross 3.0.
peer_labels = ["Peer 1\n(MAC-A / IP-B)", "Peer 2\n(MAC-B / IP-A)"]
before_scores = [1.5, 1.5]
after_scores = [3.5, 3.5]

x = np.arange(len(peer_labels))
width = 0.32

fig, ax = plt.subplots(figsize=(5.0, 3.8))

b1 = ax.bar(x - width / 2, before_scores, width, color=FLEET_BEFORE,
            label="Before fleet correlation", zorder=2)
b2 = ax.bar(x + width / 2, after_scores, width, color=FLEET_AFTER,
            label="After fleet correlation (+2.0 boost)", zorder=2)

ax.axhline(THRESHOLD, color=THRESHOLD_COLOR, linestyle="--", linewidth=1.2,
           label=f"Threshold = {THRESHOLD}", zorder=3)

for bar, score in zip(list(b1) + list(b2), before_scores + after_scores):
    ax.text(bar.get_x() + bar.get_width() / 2, score + 0.06,
            f"{score:.1f}", ha="center", va="bottom", fontsize=9)

ax.set_xticks(x)
ax.set_xticklabels(peer_labels)
ax.set_ylabel("Suspicion score")
ax.set_ylim(0, 5.0)
ax.set_title("F12 — fleet correlation tips both peers\nabove investigation threshold", pad=10)
ax.grid(axis="y", linestyle=":", alpha=0.5, zorder=1)
ax.legend(framealpha=0.85, fontsize=8.5, loc="upper left")

fig.tight_layout()
path = OUT / "fleet_boost_f12.pdf"
fig.savefig(path, bbox_inches="tight")
print(f"Saved: {path}")
plt.close(fig)

print("All figures generated.")
