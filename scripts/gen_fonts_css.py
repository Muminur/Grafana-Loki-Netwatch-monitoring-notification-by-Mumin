"""Generate self-hosted fonts.css from Google Fonts.

Replaces gstatic URLs with local paths pointing to downloaded WOFF2 files.
"""

import re
from pathlib import Path

import httpx

CSS_OUT_PATH = Path("src/web/static/css/fonts.css")

FONT_REQUESTS = [
    (
        "Orbitron",
        "https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap",
    ),
    (
        "JetBrains Mono",
        "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700"
        "&display=swap",
    ),
    (
        "Inter",
        "https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap",
    ),
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    )
}

css_blocks = ["/* Self-hosted fonts — generated from Google Fonts (offline-first) */\n"]

for family, url in FONT_REQUESTS:
    resp = httpx.get(url, headers=HEADERS, timeout=60)
    css = resp.text

    def replace_url(m: re.Match) -> str:  # type: ignore[type-arg]
        fname = m.group(1).split("/")[-1]
        return "url('/static/fonts/" + fname + "')"

    local_css = re.sub(
        r"url\((https://fonts\.gstatic\.com/[^)]+\.woff2)\)",
        replace_url,
        css,
    )
    face_blocks = re.findall(r"@font-face \{[^}]+\}", local_css)
    css_blocks.append(f"/* {family} */")
    css_blocks.extend(face_blocks)
    css_blocks.append("")

final_css = "\n".join(css_blocks)
CSS_OUT_PATH.write_text(final_css, encoding="utf-8")
print(f"Written {len(final_css)} chars to {CSS_OUT_PATH}")
print("Font-face count:", final_css.count("@font-face"))
