#!/usr/bin/env python3
"""Generate README visuals for the OpenBSD_netcat_REA repo.

Reads the REA/Ghidra artifacts in ./files and writes PNGs to ./assets.
Requires: matplotlib, plus graphviz `dot` on PATH for the graphs.
"""
import json, os, subprocess, textwrap

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = os.path.join(ROOT, "files")
ASSETS = os.path.join(ROOT, "assets")
os.makedirs(ASSETS, exist_ok=True)

BG = "#0d1117"
FG = "#c9d1d9"
DIM = "#8b949e"
GRID = "#21262d"
BLUE = "#58a6ff"
GREEN = "#3fb950"
ORANGE = "#f0883e"
PURPLE = "#bc8cff"
PINK = "#ff7b72"

plt.rcParams.update({
    "figure.facecolor": BG, "axes.facecolor": BG, "savefig.facecolor": BG,
    "text.color": FG, "axes.labelcolor": FG, "axes.edgecolor": GRID,
    "xtick.color": DIM, "ytick.color": DIM, "font.family": "DejaVu Sans",
})


def load(name):
    with open(os.path.join(FILES, name)) as f:
        return json.load(f)


# ---------------------------------------------------------------- section chart
def section_chart():
    d = load("rea-inspect-binary-layout.json")["raw_result"]
    rows = []
    for s in d["sections"]:
        nm = s["name"]["display"]
        if not nm or s["type"] == "SHT_NOBITS":
            continue
        size = int(s["size"], 16)
        if size <= 0:
            continue
        rows.append((nm, size))
    rows.sort(key=lambda r: r[1], reverse=True)
    rows = rows[:14]
    names = [n for n, _ in rows][::-1]
    vals = [v for _, v in rows][::-1]
    fig, ax = plt.subplots(figsize=(10, 6.2), dpi=160)
    colors = [BLUE if n.startswith(".text") else PURPLE if n.startswith(".rodata")
              else ORANGE if "plt" in n else DIM for n in names]
    bars = ax.barh(names, vals, color=colors, height=0.62)
    for b, v in zip(bars, vals):
        ax.text(v + max(vals) * 0.01, b.get_y() + b.get_height() / 2,
                f"{v:,}", va="center", ha="left", color=FG, fontsize=9)
    ax.set_title("ELF section sizes (bytes) - nc / netcat-openbsd 1.234-1",
                 color=FG, fontsize=13, pad=14)
    ax.set_xlim(0, max(vals) * 1.16)
    ax.tick_params(axis="y", labelsize=10)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.xaxis.grid(True, color=GRID, lw=0.7)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(os.path.join(ASSETS, "sections.png"))
    plt.close(fig)


# ---------------------------------------------------------------- segment map
def segment_map():
    """Render the ELF file<->memory mapping as a unified-diff terminal card.

    A plain "segments" chart hides the interesting part: the RW PT_LOAD is the
    only one whose virtual address differs from its file offset, and it carries
    a huge non-file-backed .bss tail. A diff makes both obvious.
    """
    d = load("rea-inspect-binary-layout.json")["raw_result"]
    labels = {0x0: ".interp  .dynsym  .dynstr  .rela",
              0x2000: ".init  .plt  .plt.sec  .text  .fini",
              0x7000: ".rodata (strings, banner)",
              0x8b98: ".data  .got"}
    segs = []
    for s in d["segments"]:
        if s["type"] != "PT_LOAD":
            continue
        off = int(s["offset"], 16)
        vaddr = int(s["virtual_address"], 16)
        fsz = int(s["file_size"], 16)
        msz = int(s["memory_size"], 16)
        flags = int(s["flags"], 16)
        perm = ("R" if flags & 4 else "-") + ("W" if flags & 2 else "-") + \
               ("X" if flags & 1 else "-")
        segs.append((off, vaddr, fsz, msz, perm))
    segs.sort()

    def rng(start, size):
        return f"0x{start:06x} - 0x{start + size - 1:06x}"

    body = []  # (kind, text)
    moved = 0
    for off, vaddr, fsz, msz, perm in segs:
        label = labels.get(off, "")
        if off == vaddr and fsz == msz:
            body.append(("ctx", f"   {perm}   {rng(vaddr, fsz)}    {label}"))
        else:
            moved += 1
            body.append(("del", f"-  {perm}   {rng(off, fsz)}    {label}"
                                f"   [file: 0x{fsz:x} bytes]"))
            body.append(("add", f"+  {perm}   {rng(vaddr, fsz)}    {label}"
                                f"   [moved +0x{vaddr - off:x}]"))
            body.append(("add", f"+  {perm}   {rng(vaddr + fsz, msz - fsz)}"
                                f"    .bss   [0x{msz - fsz:x} = {msz - fsz:,} bytes,"
                                f" not file-backed]"))

    ctx = len(segs) - moved
    header = [
        ("hdr", "diff --no-index  a/nc.file  b/nc.memory"),
        ("minus", "--- a/nc   (file offsets)"),
        ("plus", "+++ b/nc   (virtual addresses, PIE image base 0)"),
        ("hunk", f"@@ PT_LOAD segments: {ctx} identical, {moved} moved @@"),
    ]
    color = {"hdr": FG, "minus": PINK, "plus": GREEN, "hunk": BLUE,
             "ctx": DIM, "del": PINK, "add": GREEN}

    fig, ax = plt.subplots(figsize=(12, 5.2), dpi=160)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.add_patch(FancyBboxPatch(
        (0.008, 0.02), 0.984, 0.94, boxstyle="round,pad=0.006,rounding_size=0.02",
        linewidth=1.2, edgecolor="#30363d", facecolor="#161b22", zorder=0))
    ax.add_patch(FancyBboxPatch(
        (0.008, 0.855), 0.984, 0.105, boxstyle="round,pad=0.006,rounding_size=0.02",
        linewidth=0, facecolor="#21262d", zorder=1))
    for i, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        ax.add_patch(plt.Circle((0.030 + i * 0.022, 0.905), 0.008,
                                color=c, zorder=2))
    ax.text(0.5, 0.905, "memory-map.png  -  nc  (netcat-openbsd 1.234-1)",
            ha="center", va="center", color=DIM, fontsize=10,
            family="monospace", zorder=2)

    y = 0.80
    for kind, text in header + [("ctx", "")] + body:
        if text:
            ax.text(0.045, y, text, ha="left", va="center", family="monospace",
                    fontsize=11.5, color=color[kind], zorder=3,
                    fontweight="bold" if kind in ("minus", "plus", "hunk") else "normal")
        y -= 0.058
    ax.text(0.5, 0.065,
            "3 PT_LOAD file-backed segments map 1:1  ·  1 RW segment shifts +0x1000  "
            "·  .bss is zero-filled at load, absent from the file",
            ha="center", va="center", color=DIM, fontsize=9, family="monospace")
    fig.savefig(os.path.join(ASSETS, "memory-map.png"),
                bbox_inches="tight", pad_inches=0.2)
    plt.close(fig)


# ---------------------------------------------------------------- hardening card
def hardening_card():
    d = load("rea-inspect-binary-layout.json")["raw_result"]
    m = d["mitigations"]
    items = [
        ("Position Independent (PIE)", bool(m["position_independent"])),
        ("NX / non-exec stack", bool(m["nx_indicator"])),
        ("Stack canary", bool(m["stack_canary_indicator"])),
        ("Full RELRO", m["relro"] == "Full"),
        ("CET: IBT + SHSTK", True),
        ("Stripped symbols", True),
        (f"Imports: {len(d['symbols'])} dynsyms", None),
        (f"Deps: {', '.join(x['display'] for x in d['linkage']['needed_libraries'])}", None),
    ]
    fig, ax = plt.subplots(figsize=(9.5, 5.0), dpi=160)
    ax.axis("off")
    ax.set_title("Hardening profile - nc", color=FG, fontsize=15, pad=16, loc="left")
    for i, (label, ok) in enumerate(items):
        y = 0.90 - i * 0.115
        if ok is True:
            c, mark = GREEN, "YES"
        elif ok is False:
            c, mark = PINK, "NO"
        else:
            c, mark = DIM, "-"
        ax.add_patch(FancyBboxPatch((0.02, y - 0.035), 0.96, 0.075,
                     boxstyle="round,pad=0.004,rounding_size=0.01",
                     linewidth=0, facecolor="#161b22", transform=ax.transAxes))
        ax.text(0.05, y, label, color=FG, fontsize=12, va="center",
                transform=ax.transAxes)
        if mark != "-":
            ax.text(0.93, y, mark, color=c, fontsize=12, fontweight="bold",
                    va="center", ha="right", transform=ax.transAxes)
        else:
            ax.text(0.93, y, label, color=c, fontsize=10, va="center",
                    ha="right", transform=ax.transAxes)
            ax.text(0.05, y, "", transform=ax.transAxes)
    fig.tight_layout()
    fig.savefig(os.path.join(ASSETS, "hardening.png"))
    plt.close(fig)


# ---------------------------------------------------------------- graphviz graphs
def render_dot(name, dot_src):
    path = os.path.join(ASSETS, name)
    p = subprocess.run(["dot", "-Tpng", "-Gdpi=150"],
                       input=dot_src.encode("utf-8"), capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr)
    with open(path, "wb") as f:
        f.write(p.stdout)


def call_graph():
    dot = f'''digraph G {{
  bgcolor="{BG}"; pad=0.3; rankdir=TB;
  node [shape=box style="rounded,filled" fontname="DejaVu Sans" fontsize=11
        color="#30363d" fontcolor="#0d1117" penwidth=0];
  edge [color="#484f58" penwidth=1.1 arrowsize=0.7];
  main    [label="main\\n0x102a90" fillcolor="{BLUE}" fontcolor="#0d1117" penwidth=2 color="{BLUE}"];
  rw      [label="readwrite\\n0x106300" fillcolor="{GREEN}"];
  rc      [label="remote_connect\\n0x105c60" fillcolor="{ORANGE}"];
  at      [label="atomicio\\n0x105340" fillcolor="{PURPLE}"];
  wp      [label="writep\\n0x106120" fillcolor="{PURPLE}"];
  fb      [label="fillbuf\\n0x105b40" fillcolor="{PURPLE}"];
  sc      [label="set_common_sockopts\\n0x102895" fillcolor="{ORANGE}"];
  st      [label="strtoport\\n0x105510" fillcolor="{DIM}"];
  us      [label="usage\\n0x1054d0" fillcolor="{DIM}"];
  ub      [label="unix_bind\\n0x106c20" fillcolor="{PINK}"];
  ua      [label="unix addr\\n0x105bb0" fillcolor="{PINK}"];
  rs      [label="report_sock\\n0x106b00" fillcolor="{PINK}"];
  pl      [label="proxy line\\n0x105440" fillcolor="{PURPLE}"];
  rv      [label="resolver\\n0x1059d0" fillcolor="{ORANGE}"];
  main -> rw; main -> rc; main -> at; main -> st; main -> us;
  main -> ub; main -> rs; main -> pl; main -> rv; main -> sc;
  rw -> at; rw -> fb; rw -> wp;
  rc -> sc;
  wp -> at; pl -> at; ub -> ua; ub -> rs;
}}'''
    render_dot("call-graph.png", dot)


def pipeline():
    dot = f'''digraph P {{
  bgcolor="{BG}"; pad=0.35; rankdir=LR;
  node [shape=box style="rounded,filled" fontname="DejaVu Sans" fontsize=11
        color="#30363d" fontcolor="#0d1117" penwidth=0];
  edge [color="#484f58" penwidth=1.3 arrowsize=0.8];
  target [label="nc\\nELF64 PIE" fillcolor="{PINK}"];
  subgraph cluster_a {{
    label="REA provider: pwntools-elf"; fontcolor="{BLUE}"; color="{BLUE}";
    style="rounded"; fontname="DejaVu Sans";
    layout [label="inspect_binary_layout\\n(offline, no execution)" fillcolor="{BLUE}"];
  }}
  subgraph cluster_b {{
    label="REA provider: Ghidra 12.1.4"; fontcolor="{GREEN}"; color="{GREEN}";
    style="rounded"; fontname="DejaVu Sans";
    analyze [label="analyze" fillcolor="{GREEN}"];
    search [label="search" fillcolor="{GREEN}"];
    dec [label="decompile" fillcolor="{GREEN}"];
    trace [label="trace" fillcolor="{GREEN}"];
    analyze -> search -> dec -> trace [color="{GREEN}"];
  }}
  out [label="results.txt + files/" fillcolor="{ORANGE}"];
  target -> layout; target -> analyze;
  layout -> out; trace -> out;
}}'''
    render_dot("rea-pipeline.png", dot)


if __name__ == "__main__":
    section_chart()
    segment_map()
    hardening_card()
    call_graph()
    pipeline()
    print("assets written to", ASSETS)
    for n in sorted(os.listdir(ASSETS)):
        print(" ", n, os.path.getsize(os.path.join(ASSETS, n)), "bytes")
