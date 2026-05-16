#!/usr/bin/env python3
"""Generate pxgo.ico — blue background, white PX text + arrow glyphs."""

from PIL import Image, ImageDraw, ImageFont
import os

BG      = (59, 130, 246)      # #3b82f6
FG      = (255, 255, 255)
ARROW   = (200, 226, 255)     # lighter blue for arrows
SIZES   = [256, 128, 64, 48, 32, 16]
OUT     = os.path.join(os.path.dirname(__file__), "..", "pxgo.ico")


def make_frame(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), BG)
    draw = ImageDraw.Draw(img)

    # Rounded corners via alpha mask
    mask = Image.new("L", (size, size), 0)
    mask_draw = ImageDraw.Draw(mask)
    radius = max(2, size // 8)
    mask_draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    img.putalpha(mask)

    # Font sizes scaled to icon size
    px_font_size  = max(4, int(size * 0.45))
    arr_font_size = max(3, int(size * 0.20))

    def load_font(size_pt):
        for name in [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
        ]:
            try:
                return ImageFont.truetype(name, size_pt)
            except (OSError, IOError):
                pass
        return ImageFont.load_default()

    font_px  = load_font(px_font_size)
    font_arr = load_font(arr_font_size)

    # Draw "PX" centered in upper 60% of icon
    text = "PX"
    bbox = draw.textbbox((0, 0), text, font=font_px)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (size - tw) // 2 - bbox[0]
    ty = int(size * 0.08) - bbox[1]
    draw.text((tx, ty), text, font=font_px, fill=FG)

    # Draw "→→" centered in lower 30% of icon
    arrows = "→→"
    abbox = draw.textbbox((0, 0), arrows, font=font_arr)
    aw, ah = abbox[2] - abbox[0], abbox[3] - abbox[1]
    ax = (size - aw) // 2 - abbox[0]
    ay = int(size * 0.70) - abbox[1]
    draw.text((ax, ay), arrows, font=font_arr, fill=ARROW)

    return img


frames = [make_frame(s) for s in SIZES]
frames[0].save(
    OUT,
    format="ICO",
    sizes=[(s, s) for s in SIZES],
    append_images=frames[1:],
)
print(f"Generated {os.path.abspath(OUT)}  ({len(frames)} sizes: {SIZES})")
