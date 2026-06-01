#!/usr/bin/env python3
"""Generate the app icon PNG and ICO assets from a small vector drawing."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
PNG = ASSETS / "app-icon.png"
ICO = ASSETS / "app-icon.ico"


def draw_icon(size: int) -> Image.Image:
    scale = size / 256
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    def xy(values: tuple[float, ...]) -> tuple[int, ...]:
        return tuple(round(value * scale) for value in values)

    radius = round(56 * scale)
    draw.rounded_rectangle(xy((0, 0, 256, 256)), radius=radius, fill="#0f66e8")
    shield_outer = [xy((128, 30)), xy((202, 58)), xy((202, 128)), xy((196, 160)), xy((176, 190)), xy((128, 226)), xy((80, 190)), xy((60, 160)), xy((54, 128)), xy((54, 58))]
    draw.polygon(shield_outer, fill="#ffffff")
    shield_inner = [xy((128, 50)), xy((181, 70)), xy((181, 128)), xy((176, 152)), xy((160, 177)), xy((128, 203)), xy((96, 177)), xy((80, 152)), xy((75, 128)), xy((75, 70))]
    draw.polygon(shield_inner, fill="#0b4db8")

    stroke = max(2, round(12 * scale))
    thin = max(1, round(8 * scale))
    draw.ellipse(xy((79, 74, 177, 172)), outline="#ffffff", width=stroke)
    draw.line(xy((82, 123, 174, 123)), fill="#ffffff", width=max(1, round(9 * scale)))
    draw.arc(xy((103, 74, 153, 172)), 90, 270, fill="#ffffff", width=max(1, round(9 * scale)))
    draw.arc(xy((103, 74, 153, 172)), 270, 90, fill="#ffffff", width=max(1, round(9 * scale)))
    draw.arc(xy((88, 82, 168, 126)), 18, 162, fill="#ffffff", width=thin)
    draw.arc(xy((88, 120, 168, 164)), 198, 342, fill="#ffffff", width=thin)
    return image


def main() -> int:
    ASSETS.mkdir(parents=True, exist_ok=True)
    image = draw_icon(1024)
    image.save(PNG)
    ico_images = [draw_icon(size) for size in (16, 24, 32, 48, 64, 128, 256)]
    ico_images[-1].save(ICO, sizes=[(img.width, img.height) for img in ico_images], append_images=ico_images[:-1])
    print(f"wrote {PNG}")
    print(f"wrote {ICO}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
