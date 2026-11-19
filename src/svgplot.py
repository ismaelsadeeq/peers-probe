"""Tiny dependency-free SVG charting (bars + multi-line), 3Blue1Brown / Manim-style
dark theme to match the report's animated figures."""

def _esc(s): return str(s).replace("&", "&amp;").replace("<", "&lt;")

# ── Manim / 3b1b-inspired dark palette ──────────────────────────────
BG     = "#0d1117"   # dark background (matches the GIFs)
GRID   = "#222a35"   # faint gridlines
TEXT   = "#c9d4e0"   # labels
TITLE  = "#e8eef5"   # title
MUTED  = "#8b98a8"   # notes / axis numbers
BLUE   = "#58c4dd"   # 3b1b signature blue (default bars/lines)
PALETTE = ["#58c4dd", "#83c167", "#fc6255", "#a67fd6", "#f0ac5f", "#5cd0b3", "#ff8fa3"]


def barh(title, items, width=760, bar_h=22, pad_left=230, unit="", color=BLUE, note="", colors=None, ghost=None, right=95):
    """items: list of (label, value) or (label, value, annotation). Horizontal bars.
    colors: optional list of per-bar fill colors (parallel to items); overrides color.
    ghost: optional list of background values (parallel to items), drawn as a faint bar
    behind each solid bar so the gap (e.g. naive-vs-precise) is visible.
    right: px reserved for value labels (raise it when labels are long)."""
    n = len(items)
    top = 58 if note else 48
    height = top + n * bar_h + 26
    maxv = max(list(it[1] for it in items) + (list(ghost) if ghost else []), default=1) or 1
    plot_w = width - pad_left - right
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
         f'font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif">']
    o.append(f'<rect width="{width}" height="{height}" fill="{BG}"/>')
    o.append(f'<text x="18" y="30" font-size="18" font-weight="600" fill="{TITLE}">{_esc(title)}</text>')
    if note: o.append(f'<text x="18" y="48" font-size="12.5" fill="{MUTED}">{_esc(note)}</text>')
    # faint vertical gridlines at 25/50/75/100% of max
    for g in (0.25, 0.5, 0.75, 1.0):
        gx = pad_left + plot_w * g
        o.append(f'<line x1="{gx:.1f}" y1="{top-4}" x2="{gx:.1f}" y2="{top+n*bar_h}" stroke="{GRID}" stroke-width="1"/>')
    for i, it in enumerate(items):
        label, val = it[0], it[1]; ann = it[2] if len(it) > 2 else ""
        y = top + i * bar_h
        w = max(2, int(plot_w * val / maxv))
        bar_c = colors[i] if colors else color
        o.append(f'<text x="{pad_left-10}" y="{y+bar_h//2+4}" font-size="12.5" fill="{TEXT}" text-anchor="end">{_esc(label)}</text>')
        gpart = ""
        if ghost is not None:
            gw = max(w, int(plot_w * ghost[i] / maxv))
            o.append(f'<rect x="{pad_left}" y="{y+2}" width="{gw}" height="{bar_h-6}" fill="{GRID}" rx="3"/>')
            if ghost[i] != val:
                gstr = f"{ghost[i]:,.1f}" if isinstance(ghost[i], float) else f"{ghost[i]:,}"
                gpart = f"  (naive {gstr}{unit})"
        o.append(f'<rect x="{pad_left}" y="{y+2}" width="{w}" height="{bar_h-6}" fill="{bar_c}" rx="3"/>')
        vstr = f"{val:,.1f}" if isinstance(val, float) else f"{val:,}"
        xr = pad_left + (max(w, int(plot_w * ghost[i] / maxv)) if ghost is not None else w) + 7
        vlabel = f"{vstr}{unit}" + (f"  {ann}" if ann else "") + gpart
        o.append(f'<text x="{xr}" y="{y+bar_h//2+4}" font-size="11.5" fill="{MUTED}">{_esc(vlabel)}</text>')
    o.append('</svg>')
    return "\n".join(o)


def barh_cols(title, items, cols=2, width=820, bar_h=20, unit="", color=BLUE, note=""):
    """Horizontal bars laid out in several newspaper-style columns, so a long list
    (e.g. every country) stays compact without dropping any item. Sorted items fill
    column by column; bars share one scale so lengths are comparable across columns."""
    import math
    n = len(items)
    cols = max(1, min(cols, n))
    rows = math.ceil(n / cols)
    top = 60 if note else 48
    height = top + rows * bar_h + 20
    maxv = max((it[1] for it in items), default=1) or 1
    gap = 26
    col_w = (width - 24 - gap * (cols - 1)) / cols
    lab_w = col_w * 0.32
    bar_max = col_w * 0.40
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
         f'font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif">']
    o.append(f'<rect width="{width}" height="{height}" fill="{BG}"/>')
    o.append(f'<text x="18" y="30" font-size="18" font-weight="600" fill="{TITLE}">{_esc(title)}</text>')
    if note: o.append(f'<text x="18" y="48" font-size="12.5" fill="{MUTED}">{_esc(note)}</text>')
    for i, it in enumerate(items):
        label, val = it[0], it[1]
        c = i // rows; r = i % rows
        x0 = 12 + c * (col_w + gap)
        y = top + r * bar_h
        bar_x = x0 + lab_w + 8
        w = max(2, int(bar_max * val / maxv))
        o.append(f'<text x="{x0+lab_w:.0f}" y="{y+bar_h//2+4}" font-size="12" fill="{TEXT}" text-anchor="end">{_esc(label)}</text>')
        o.append(f'<rect x="{bar_x:.0f}" y="{y+2}" width="{w}" height="{bar_h-6}" fill="{color}" rx="3"/>')
        vstr = f"{val:,.1f}" if isinstance(val, float) else f"{val:,}"
        o.append(f'<text x="{bar_x+w+6:.0f}" y="{y+bar_h//2+4}" font-size="11" fill="{MUTED}">{_esc(vstr)}{unit}</text>')
    o.append('</svg>')
    return "\n".join(o)


def lines(title, series, xlabel="", ylabel="", width=760, height=380, xticks=None, note=""):
    """series: dict name -> list of (x, y). Linear axes, dark theme."""
    L, R, T, B = 66, 22, 58, 50
    pw, ph = width - L - R, height - T - B
    xs = [p[0] for s in series.values() for p in s]; ys = [p[1] for s in series.values() for p in s]
    xmin, xmax = min(xs), max(xs); ymin, ymax = 0, (max(ys) * 1.08 or 1)
    xr = (xmax - xmin) or 1
    def px(x): return L + pw * (x - xmin) / xr
    def py(y): return T + ph * (1 - (y - ymin) / (ymax - ymin or 1))
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
         f'font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif">']
    o.append(f'<rect width="{width}" height="{height}" fill="{BG}"/>')
    o.append(f'<text x="18" y="30" font-size="18" font-weight="600" fill="{TITLE}">{_esc(title)}</text>')
    if note: o.append(f'<text x="18" y="48" font-size="12.5" fill="{MUTED}">{_esc(note)}</text>')
    for g in range(0, 101, 25):
        yy = py(ymax * g / 100 / 1.08)
        o.append(f'<line x1="{L}" y1="{yy:.1f}" x2="{L+pw}" y2="{yy:.1f}" stroke="{GRID}" stroke-width="1"/>')
        o.append(f'<text x="{L-8}" y="{yy+4:.1f}" font-size="10.5" fill="{MUTED}" text-anchor="end">{int(ymax*g/100/1.08)}</text>')
    o.append(f'<line x1="{L}" y1="{T}" x2="{L}" y2="{T+ph}" stroke="{MUTED}" stroke-width="1"/>')
    o.append(f'<line x1="{L}" y1="{T+ph}" x2="{L+pw}" y2="{T+ph}" stroke="{MUTED}" stroke-width="1"/>')
    for xt in (xticks or []):
        o.append(f'<text x="{px(xt):.1f}" y="{T+ph+17}" font-size="10.5" fill="{MUTED}" text-anchor="middle">{xt}</text>')
    o.append(f'<text x="{L+pw/2}" y="{height-8}" font-size="12" fill="{TEXT}" text-anchor="middle">{_esc(xlabel)}</text>')
    o.append(f'<text x="15" y="{T+ph/2}" font-size="12" fill="{TEXT}" text-anchor="middle" transform="rotate(-90 15 {T+ph/2})">{_esc(ylabel)}</text>')
    for i, (name, pts) in enumerate(series.items()):
        c = PALETTE[i % len(PALETTE)]
        d = " ".join(f"{px(x):.1f},{py(y):.1f}" for x, y in pts)
        o.append(f'<polyline points="{d}" fill="none" stroke="{c}" stroke-width="2.5"/>')
        o.append(f'<rect x="{L+14+i*150}" y="{T+4}" width="12" height="12" rx="2" fill="{c}"/>')
        o.append(f'<text x="{L+30+i*150}" y="{T+14}" font-size="11.5" fill="{TEXT}">{_esc(name)}</text>')
    o.append('</svg>')
    return "\n".join(o)
