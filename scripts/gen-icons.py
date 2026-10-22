#!/usr/bin/env python3
"""生成 天枢 Relay 的图标集（M4-S1）。

设计：深色圆角底 + 一把钥匙（环 + 齿）+ 一条「中继」弧线。
全部用 Pillow 画，**确定性**（无随机数、无外部素材），可重复运行得到同样的字节。

产物（`src-tauri/icons/`）：
  icon.png (1024) / 32x32.png / 128x128.png / 128x128@2x.png / icon.icns / icon.ico
"""

from PIL import Image, ImageDraw

OUT = "src-tauri/icons"
BASE = 1024

BG_TOP = (22, 26, 33, 255)
BG_BOTTOM = (13, 16, 23, 255)
ACCENT = (110, 168, 254, 255)
ACCENT_DIM = (62, 96, 148, 255)
KEY = (230, 233, 239, 255)


def rounded_mask(size: int, radius_ratio: float = 0.22) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    radius = int(size * radius_ratio)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask


def vertical_gradient(size: int) -> Image.Image:
    gradient = Image.new("RGBA", (1, size))
    for y in range(size):
        t = y / max(1, size - 1)
        gradient.putpixel(
            (0, y),
            tuple(
                int(BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * t) for i in range(4)
            ),
        )
    return gradient.resize((size, size))


def build(size: int) -> Image.Image:
    s = size / BASE  # 以 1024 为基准的缩放系数

    canvas = vertical_gradient(size).convert("RGBA")

    # 中继弧线：两道同心弧，暗示「中转」
    arcs = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    adraw = ImageDraw.Draw(arcs)
    for ratio, color in ((0.74, ACCENT_DIM), (0.60, ACCENT)):
        box = [
            int(size * (1 - ratio) / 2),
            int(size * (1 - ratio) / 2),
            int(size * (1 + ratio) / 2),
            int(size * (1 + ratio) / 2),
        ]
        adraw.arc(box, start=205, end=335, fill=color, width=max(2, int(26 * s)))
    canvas.alpha_composite(arcs)

    # 钥匙：环 + 柄 + 两个齿
    key = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    kdraw = ImageDraw.Draw(key)

    ring_cx, ring_cy = int(size * 0.38), int(size * 0.60)
    ring_r = int(size * 0.155)
    ring_w = max(2, int(30 * s))
    kdraw.ellipse(
        [ring_cx - ring_r, ring_cy - ring_r, ring_cx + ring_r, ring_cy + ring_r],
        outline=KEY,
        width=ring_w,
    )

    shaft_y = ring_cy
    shaft_x0 = ring_cx + ring_r - ring_w // 2
    shaft_x1 = int(size * 0.80)
    shaft_w = max(2, int(34 * s))
    kdraw.rounded_rectangle(
        [shaft_x0, shaft_y - shaft_w // 2, shaft_x1, shaft_y + shaft_w // 2],
        radius=shaft_w // 2,
        fill=KEY,
    )

    for i, (dx, h) in enumerate(((0.0, 0.105), (0.105, 0.075))):
        x = int(size * 0.66) + int(size * dx)
        top = shaft_y + shaft_w // 2
        kdraw.rounded_rectangle(
            [x, top - 2, x + int(size * 0.032), top + int(size * h)],
            radius=int(size * 0.014),
            fill=KEY if i == 0 else ACCENT,
        )

    canvas.alpha_composite(key)
    canvas.putalpha(rounded_mask(size))
    return canvas


def main() -> None:
    import os

    os.makedirs(OUT, exist_ok=True)
    master = build(BASE)

    master.resize((1024, 1024), Image.LANCZOS).save(f"{OUT}/icon.png")
    master.resize((32, 32), Image.LANCZOS).save(f"{OUT}/32x32.png")
    master.resize((128, 128), Image.LANCZOS).save(f"{OUT}/128x128.png")
    master.resize((256, 256), Image.LANCZOS).save(f"{OUT}/128x128@2x.png")

    # macOS 打包用：iconutil 要求一个 .iconset 目录
    iconset = "/tmp/tianshu-relay.iconset"
    os.makedirs(iconset, exist_ok=True)
    for name, px in (
        ("icon_16x16", 16),
        ("icon_16x16@2x", 32),
        ("icon_32x32", 32),
        ("icon_32x32@2x", 64),
        ("icon_128x128", 128),
        ("icon_128x128@2x", 256),
        ("icon_256x256", 256),
        ("icon_256x256@2x", 512),
        ("icon_512x512", 512),
        ("icon_512x512@2x", 1024),
    ):
        master.resize((px, px), Image.LANCZOS).save(f"{iconset}/{name}.png")
    master.save(f"{OUT}/icon.icns")

    master.resize((256, 256), Image.LANCZOS).save(
        f"{OUT}/icon.ico",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )

    print("已生成：icon.png / 32x32.png / 128x128.png / 128x128@2x.png / icon.icns / icon.ico")


if __name__ == "__main__":
    main()
