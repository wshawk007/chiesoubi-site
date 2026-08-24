#!/usr/bin/env python3
"""Fail closed when the static site's security contract regresses."""

from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML_FILES = tuple(sorted(ROOT.glob("*.html")))


class SiteParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: list[str] = []
        self.inline_style = False
        self.inline_script = False
        self.event_handler = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        self.inline_style |= tag == "style" or "style" in values
        self.inline_script |= tag == "script" and not values.get("src")
        self.event_handler |= any(name.lower().startswith("on") for name, _ in attrs)
        for name in ("href", "src"):
            value = values.get(name)
            if value and not value.startswith(("#", "http://", "https://", "mailto:", "tel:")):
                self.references.append(value.split("?", 1)[0].split("#", 1)[0])


def fail(message: str) -> None:
    raise SystemExit(message)


if not HTML_FILES:
    fail("No HTML files found")

for page in HTML_FILES:
    parser = SiteParser()
    parser.feed(page.read_text(encoding="utf-8"))
    if parser.inline_style or parser.inline_script or parser.event_handler:
        fail(f"Inline executable/style content is forbidden: {page.name}")
    for reference in parser.references:
        if not (page.parent / reference).is_file():
            fail(f"Broken local reference in {page.name}: {reference}")

headers = (ROOT / "_headers").read_text(encoding="utf-8")
required = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
for name, value in required.items():
    if f"{name}:" not in headers or value not in headers:
        fail(f"Missing security header contract: {name}: {value}")

csp_line = next((line for line in headers.splitlines() if "Content-Security-Policy:" in line), "")
if "'unsafe-inline'" in csp_line or "'unsafe-eval'" in csp_line:
    fail("CSP must not allow unsafe-inline or unsafe-eval")

print(f"Verified {len(HTML_FILES)} HTML pages and the security header contract")
