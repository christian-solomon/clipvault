#!/usr/bin/env python3
"""Builds a gpui-component theme file from a shadcn/ui preset.

    python3 scripts/shadcn-theme.py b3ezFPvD9s assets/themes/mist.json

Fetches the preset's tokens from shadcn's public init endpoint, the same one
`shadcn init --preset` reads, and maps them onto gpui-component's theme keys.
shadcn writes colours as `oklch()`; gpui-component reads hex, so they are
converted here. Component-level choices of the preset's style (radius steps,
soft destructive buttons, the dialog overlay) are encoded in MAP below.
"""

import json
import math
import re
import sys
import urllib.request

INIT_URL = "https://ui.shadcn.com/init?base=radix&preset={code}"

# shadcn derives its radius steps from --radius: md 0.8x, lg 1x, xl 1.4x.
# Buttons and inputs are rounded-md; dialogs are rounded-xl.
RADIUS_MD, RADIUS_XL = 0.8, 1.4

# The preset has no warning, success or info tokens; these are Tailwind's
# amber, emerald and sky at steps that read as text on each background.
EXTRA = {
    "light": {
        "warning": "oklch(55.5% 0.163 48.998)",
        "success": "oklch(59.6% 0.145 163.225)",
        "info": "oklch(58.8% 0.158 241.966)",
    },
    "dark": {
        "warning": "oklch(82.8% 0.189 84.429)",
        "success": "oklch(76.5% 0.177 163.223)",
        "info": "oklch(74.6% 0.16 232.661)",
    },
}

# gpui-component key -> expression over the preset's tokens, or a pair
# (light, dark) where the two modes differ.
#   "token"            the token itself
#   "token/NN"         the token at NN% opacity
#   "mix(a,b,NN)"      a mixed NN% towards b, as CSS color-mix in oklch
#   "#rrggbbaa"        a literal
MAP = {
    "background": "background",
    "foreground": "foreground",
    "border": "border",
    "window.border": "border",
    "input.border": "input",
    "ring": "ring",
    "caret": "foreground",
    "selection.background": "ring/40",
    "overlay": "#0000001a",
    "accent.background": "accent",
    "accent.foreground": "accent-foreground",
    "muted.background": "muted",
    "muted.foreground": "muted-foreground",
    "popover.background": "popover",
    # gpui-component's card-like container.
    "group_box.background": "card",
    "group_box.foreground": "card-foreground",
    "popover.foreground": "popover-foreground",
    "primary.background": "primary",
    "primary.foreground": "primary-foreground",
    "primary.hover.background": "primary/80",
    "primary.active.background": "primary/90",
    "secondary.background": "secondary",
    "secondary.foreground": "secondary-foreground",
    "secondary.hover.background": "mix(secondary,foreground,5)",
    "secondary.active.background": "mix(secondary,foreground,8)",
    "danger.background": "destructive",
    "danger.foreground": "primary-foreground",
    "danger.hover.background": "destructive/90",
    "danger.active.background": "destructive/80",
    # Outline buttons; vega fills them with the input colour in dark mode.
    "button.background": ("background", "input/30"),
    "button.foreground": "foreground",
    "button.hover.background": ("muted", "input/50"),
    "button.active.background": ("muted", "input/50"),
    # Vega's destructive button is a tint with red text, not solid red.
    "button.danger.background": ("destructive/10", "destructive/20"),
    "button.danger.foreground": "destructive",
    "button.danger.hover.background": ("destructive/20", "destructive/30"),
    "button.danger.active.background": ("destructive/20", "destructive/30"),
    "warning.background": "warning",
    "warning.foreground": "background",
    "success.background": "success",
    "success.foreground": "background",
    "info.background": "info",
    "info.foreground": "background",
    "link": "primary",
    "link.hover": "primary/80",
    "link.active": "primary/90",
    # A subtle menu accent: the highlighted row takes the accent colour.
    "list.background": "background",
    "list.even.background": "background",
    "list.head.background": "muted",
    "list.active.background": "accent",
    "list.active.border": "#00000000",
    "list.hover.background": "muted/50",
    "tab_bar.background": "muted",
    "tab_bar.segmented.background": "muted",
    "tab.background": "#00000000",
    "tab.foreground": "foreground/60",
    "tab.active.background": ("background", "input/30"),
    "tab.active.foreground": "foreground",
    "title_bar.background": "background",
    "title_bar.border": "border",
    "scrollbar.background": "#00000000",
    "scrollbar.thumb.background": "muted-foreground/30",
    "scrollbar.thumb.hover.background": "muted-foreground/50",
    "skeleton.background": "muted",
    "progress.bar.background": "primary",
    "sidebar.background": "sidebar",
    "sidebar.foreground": "sidebar-foreground",
    "sidebar.border": "sidebar-border",
    "sidebar.accent.background": "sidebar-accent",
    "sidebar.accent.foreground": "sidebar-accent-foreground",
    "sidebar.primary.background": "sidebar-primary",
    "sidebar.primary.foreground": "sidebar-primary-foreground",
    **{f"chart.{i}": f"chart-{i}" for i in range(1, 6)},
}


def parse_oklch(value):
    m = re.fullmatch(r"oklch\(\s*([\d.]+)(%?)\s+([\d.]+)\s+([\d.]+)\s*(?:/\s*([\d.]+)(%?))?\s*\)", value)
    if not m:
        raise ValueError(f"not an oklch colour: {value}")
    lightness = float(m[1]) / (100 if m[2] else 1)
    alpha = 1.0
    if m[5]:
        alpha = float(m[5]) / (100 if m[6] else 1)
    return lightness, float(m[3]), float(m[4]), alpha


def oklch_to_srgb(lightness, chroma, hue):
    a = chroma * math.cos(math.radians(hue))
    b = chroma * math.sin(math.radians(hue))
    l_ = (lightness + 0.3963377774 * a + 0.2158037573 * b) ** 3
    m_ = (lightness - 0.1055613458 * a - 0.0638541728 * b) ** 3
    s_ = (lightness - 0.0894841775 * a - 1.2914855480 * b) ** 3
    linear = (
        4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
        -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
        -0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_,
    )

    def encode(c):
        c = min(max(c, 0.0), 1.0)
        return 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055

    return tuple(encode(c) for c in linear)


def hex_of(rgb, alpha):
    out = "#" + "".join(f"{round(c * 255):02x}" for c in rgb)
    return out if alpha >= 0.999 else out + f"{round(alpha * 255):02x}"


def resolve(expr, tokens):
    """Returns the hex colour an expression names."""
    if expr.startswith("#"):
        return expr
    if expr.startswith("mix("):
        a, b, pct = expr[4:-1].split(",")
        la, ca, ha, _ = parse_oklch(tokens[a])
        lb, cb, hb, _ = parse_oklch(tokens[b])
        t = float(pct) / 100
        # Hue is meaningless at zero chroma; keep the other colour's.
        ha, hb = (hb if ca < 1e-4 else ha), (ha if cb < 1e-4 else hb)
        dh = ((hb - ha + 180) % 360) - 180
        mixed = (la + (lb - la) * t, ca + (cb - ca) * t, ha + dh * t)
        return hex_of(oklch_to_srgb(*mixed), 1.0)
    name, _, pct = expr.partition("/")
    lightness, chroma, hue, alpha = parse_oklch(tokens[name])
    if pct:
        alpha *= float(pct) / 100
    return hex_of(oklch_to_srgb(lightness, chroma, hue), alpha)


def build(preset, code):
    css = preset["cssVars"]
    base = preset["config"]["tailwind"]["baseColor"]
    radius_px = float(css["light"]["radius"].removesuffix("rem")) * 16
    themes = []
    for mode in ("light", "dark"):
        tokens = {**css["light"], **css[mode], **EXTRA[mode]}
        pick = 0 if mode == "light" else 1
        colors = {
            key: resolve(expr if isinstance(expr, str) else expr[pick], tokens)
            for key, expr in MAP.items()
        }
        themes.append(
            {
                "name": f"{base.title()} {mode.title()}",
                "mode": mode,
                "font.family": "Inter",
                "radius": round(radius_px * RADIUS_MD),
                "radius.lg": round(radius_px * RADIUS_XL),
                "shadow": True,
                "colors": colors,
            }
        )
    return {
        "name": base.title(),
        "author": f"Generated from shadcn/ui preset {code} ({preset['name']}) by scripts/shadcn-theme.py",
        "url": f"https://ui.shadcn.com/create?preset={code}",
        "themes": themes,
    }


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__.strip().splitlines()[2].strip())
    code, out = sys.argv[1], sys.argv[2]
    req = urllib.request.Request(INIT_URL.format(code=code), headers={"User-Agent": "registry-client"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        preset = json.load(resp)
    with open(out, "w") as f:
        json.dump(build(preset, code), f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
