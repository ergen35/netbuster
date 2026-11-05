#!/usr/bin/env python3
"""Dessine l'icône de NetBuster à toutes les tailles : python3 assets/make_icon.py

Un N formé par les liens d'un petit réseau, dont un nœud orange : le paquet repéré.
Bleu et orange sont les couleurs du trafic entrant et sortant dans l'application.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

OUT = Path(__file__).parent / "icons"
SIZES = [16, 22, 24, 32, 48, 64, 128, 256, 512]
SS = 2048  # dessin à grande échelle, puis réduction de qualité


def gradient(size, top, bottom):
    img = Image.new("RGBA", (1, size))
    for y in range(size):
        t = y / (size - 1)
        img.putpixel((0, y), tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    return img.resize((size, size))


def squircle_mask(size, margin, radius):
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([margin, margin, size - margin - 1, size - margin - 1], radius, fill=255)
    return mask


def render(small: bool) -> Image.Image:
    s = SS
    margin = round(s * (0.03 if small else 0.07))
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))

    if not small:
        # Ombre douce sous la plaque.
        shadow = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        offset = squircle_mask(s, margin, round(s * 0.2))
        shadow.paste((0, 0, 0, 130), (0, round(s * 0.012)), offset)
        img = Image.alpha_composite(img, shadow.filter(ImageFilter.GaussianBlur(s * 0.012)))

    plate = gradient(s, (0x2f, 0x7c, 0xdc), (0x12, 0x35, 0x73))
    mask = squircle_mask(s, margin, round(s * 0.2))

    if not small:
        # Ondes de radar autour du nœud repéré : invisibles et donc absentes en petite taille.
        waves = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        d = ImageDraw.Draw(waves)
        c = (0.70 * s, 0.30 * s)
        for r, a in [(0.26, 46), (0.42, 32), (0.60, 20), (0.80, 12)]:
            R = r * s
            d.ellipse([c[0] - R, c[1] - R, c[0] + R, c[1] + R], outline=(255, 255, 255, a), width=round(s * 0.012))
        plate = Image.alpha_composite(plate, waves)

    img.paste(plate, (0, 0), mask)

    # Reflet fin sur le bord haut de la plaque.
    if not small:
        rim = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        ImageDraw.Draw(rim).rounded_rectangle(
            [margin, margin, s - margin - 1, s - margin - 1], round(s * 0.2), outline=(255, 255, 255, 60), width=round(s * 0.006)
        )
        fade = Image.new("L", (s, s), 0)
        for y in range(s // 2):
            ImageDraw.Draw(fade).line([(0, y), (s, y)], fill=round(255 * (1 - y / (s / 2))))
        rim.putalpha(Image.composite(rim.getchannel("A"), Image.new("L", (s, s), 0), fade))
        img = Image.alpha_composite(img, rim)

    # Le N : deux montants et une diagonale, avec un nœud à chaque sommet.
    left, right = (0.29 if small else 0.31) * s, (0.71 if small else 0.69) * s
    top, bottom = (0.27 if small else 0.30) * s, (0.73 if small else 0.70) * s
    a, b, c, e = (left, bottom), (left, top), (right, bottom), (right, top)
    width = round(s * (0.105 if small else 0.072))
    node = s * (0.085 if small else 0.062)
    hot = s * (0.115 if small else 0.088)

    lines = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(lines)
    white = (255, 255, 255, 255)
    d.line([a, b], fill=white, width=width)
    d.line([b, c], fill=white, width=width)
    d.line([c, e], fill=white, width=width)
    for x, y in (a, b, c):
        d.ellipse([x - node, y - node, x + node, y + node], fill=white)
    img = Image.alpha_composite(img, lines)

    if not small:
        # Halo du nœud repéré.
        glow = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        R = hot * 1.55
        ImageDraw.Draw(glow).ellipse([e[0] - R, e[1] - R, e[0] + R, e[1] + R], fill=(0xff, 0x8a, 0x4c, 80))
        img = Image.alpha_composite(img, glow.filter(ImageFilter.GaussianBlur(s * 0.022)))

    # Anneau sombre qui détache le nœud orange du reste, puis le nœud.
    d = ImageDraw.Draw(img)
    ring = hot + s * (0.022 if small else 0.016)
    d.ellipse([e[0] - ring, e[1] - ring, e[0] + ring, e[1] + ring], fill=(0x10, 0x2c, 0x60, 255))
    d.ellipse([e[0] - hot, e[1] - hot, e[0] + hot, e[1] + hot], fill=(0xf2, 0x6f, 0x2c, 255))
    return img


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    big, small = render(False), render(True)
    for size in SIZES:
        src = small if size <= 32 else big
        src.resize((size, size), Image.LANCZOS).save(OUT / f"netbuster-{size}.png", optimize=True)

    # Planche de contrôle : les tailles réelles sur fonds sombre et clair.
    sheet = Image.new("RGBA", (980, 620), (0x1a, 0x1a, 0x19, 255))
    ImageDraw.Draw(sheet).rectangle([0, 340, 980, 620], fill=(0xee, 0xee, 0xec, 255))
    for base in (20, 360):
        x = 20
        for size in [256, 128, 64, 48, 32, 24, 22, 16]:
            icon = Image.open(OUT / f"netbuster-{size}.png")
            sheet.alpha_composite(icon, (x, base))
            x += size + 26
    sheet.save(Path("/tmp") / "netbuster-icon-sheet.png")


if __name__ == "__main__":
    main()
