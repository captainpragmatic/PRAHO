"""Build PRAHO's own mark ("Monogram P") as deterministic SVGs. Standard library only.

The mark: a geometric P (stem, top bar, bowl, bottom bar) with a signal dot inside the bowl,
in a 100 x 100 box. Every shape is a filled outline (no strokes, no live text), so the files
render identically everywhere.

Outputs, in PRAHO's default brand folder (shared/ui/static/brand/, ADR-0058):
  logo.svg         light blue, for PRAHO's dark staff and customer screens
  logo-light.svg   blue, for light surfaces such as the README on a light theme
  favicon.svg      follows the browser's prefers-color-scheme

favicon.ico and apple-touch-icon.png in the same folder are raster exports of these SVGs.
A deployment never edits these files; it supplies its own brand folder through BRAND_DIR.

Run:  python3 scripts/brand/build_praho_mark.py
"""

from __future__ import annotations

import math
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "shared" / "ui" / "static" / "brand"

# PRAHO's default palette (the open-source defaults; deployments override through their brand folder)
LIGHT = {"mark": "#2451B2", "signal": "#0E9F6E"}
DARK = {"mark": "#8FB0FF", "signal": "#34D399"}

# geometry, 100 x 100
STEM = (20.0, 12.0, 36.0, 88.0)  # x0, y0, x1, y1
TOP_BAR = (20.0, 12.0, 54.0, 28.0)
BOTTOM_BAR = (20.0, 60.0, 54.0, 76.0)
BOWL = {"cx": 54.0, "cy": 44.0, "r": 24.0, "t": 16.0}  # the half-ring on the right, from the bottom bar to the top bar
DOT = {"cx": 54.0, "cy": 44.0, "r": 7.0}


def rrect(x0: float, y0: float, x1: float, y1: float) -> str:
    """Rounded rectangle whose corner radius is half the shorter side (a stadium)."""
    r = min(x1 - x0, y1 - y0) / 2
    return (
        f"M{x0 + r:.3f},{y0:.3f} H{x1 - r:.3f} A{r:.3f},{r:.3f} 0 0,1 {x1:.3f},{y0 + r:.3f} "
        f"V{y1 - r:.3f} A{r:.3f},{r:.3f} 0 0,1 {x1 - r:.3f},{y1:.3f} H{x0 + r:.3f} "
        f"A{r:.3f},{r:.3f} 0 0,1 {x0:.3f},{y1 - r:.3f} V{y0 + r:.3f} A{r:.3f},{r:.3f} 0 0,1 {x0 + r:.3f},{y0:.3f} Z"
    )


def _pt(cx: float, cy: float, r: float, deg: float) -> tuple[float, float]:
    a = math.radians(deg)
    return cx + r * math.cos(a), cy - r * math.sin(a)  # SVG y grows downward


def arc_with_caps(ring: dict[str, float], start: float, end: float) -> str:
    """A stroked arc from `start` to `end` degrees (counter-clockwise, math angles) as one filled outline with round caps."""
    cx, cy, r, t = ring["cx"], ring["cy"], ring["r"], ring["t"]
    ro, ri, cap = r + t / 2, r - t / 2, t / 2
    so, eo = _pt(cx, cy, ro, start), _pt(cx, cy, ro, end)
    ei, si = _pt(cx, cy, ri, end), _pt(cx, cy, ri, start)
    large = 1 if (end - start) % 360 > 180 else 0
    return (
        f"M{so[0]:.3f},{so[1]:.3f} A{ro:.3f},{ro:.3f} 0 {large},0 {eo[0]:.3f},{eo[1]:.3f} "
        f"A{cap:.3f},{cap:.3f} 0 0,0 {ei[0]:.3f},{ei[1]:.3f} A{ri:.3f},{ri:.3f} 0 {large},1 {si[0]:.3f},{si[1]:.3f} "
        f"A{cap:.3f},{cap:.3f} 0 0,0 {so[0]:.3f},{so[1]:.3f} Z"
    )


def circle_path(cx: float, cy: float, r: float) -> str:
    return f"M{cx - r:.3f},{cy:.3f} a{r:.3f},{r:.3f} 0 1,0 {2 * r:.3f},0 a{r:.3f},{r:.3f} 0 1,0 {-2 * r:.3f},0 Z"


def mark_body(mark: str, signal: str, mark_class: str = "", signal_class: str = "") -> str:
    """Four P pieces as separate paths (overlaps paint twice, never cut holes) plus the dot."""
    fill_m = f'class="{mark_class}"' if mark_class else f'fill="{mark}"'
    fill_s = f'class="{signal_class}"' if signal_class else f'fill="{signal}"'
    pieces = [rrect(*STEM), rrect(*TOP_BAR), rrect(*BOTTOM_BAR), arc_with_caps(BOWL, -90.0, 90.0)]
    return (
        "\n".join(f'<path {fill_m} d="{p}"/>' for p in pieces)
        + f'\n<path {fill_s} d="{circle_path(DOT["cx"], DOT["cy"], DOT["r"])}"/>'
    )


def svg_doc(body: str, title: str = "PRAHO") -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" role="img" aria-label="{title}">\n'
        f"<title>{title}</title>\n{body}\n</svg>\n"
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, col in (("logo.svg", DARK), ("logo-light.svg", LIGHT)):
        (OUT / name).write_text(svg_doc(mark_body(col["mark"], col["signal"])))
    favicon = (
        f"<style>.m{{fill:{LIGHT['mark']}}}.s{{fill:{LIGHT['signal']}}}"
        f"@media (prefers-color-scheme: dark){{.m{{fill:{DARK['mark']}}}.s{{fill:{DARK['signal']}}}}}</style>\n"
        + mark_body("", "", mark_class="m", signal_class="s")
    )
    (OUT / "favicon.svg").write_text(svg_doc(favicon))
    print(f"wrote logo.svg, logo-light.svg and favicon.svg to {OUT}")


if __name__ == "__main__":
    main()
