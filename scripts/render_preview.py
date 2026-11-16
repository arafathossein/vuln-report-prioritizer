"""Render docs/preview.png from the demo report (needs: pip install playwright && playwright install chromium)."""

import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parents[1]
out = Path(tempfile.mkdtemp())
subprocess.run([sys.executable, "-m", "vulnprio.cli", "demo", "--out", str(out)], check=True, cwd=root)

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1180, "height": 1400}, device_scale_factor=2, color_scheme="light")
    page.goto((out / "fix-list.html").as_uri())
    # Show the summary and the first ten rows.
    page.evaluate("() => document.querySelectorAll('tbody')[0].querySelectorAll('tr').forEach((r, i) => { if (i >= 10) r.remove(); })")
    page.evaluate("() => { const h = [...document.querySelectorAll('h2')][1]; if (h) { h.nextElementSibling.remove(); h.remove(); } }")
    h = min(page.evaluate("document.body.scrollHeight"), 1400)
    page.screenshot(path=str(root / "docs" / "preview.png"), clip={"x": 0, "y": 0, "width": 1180, "height": h})
    browser.close()
print("wrote docs/preview.png")
