#!/usr/bin/env python3
"""Capture a PNG screenshot of the sample quality HTML report (synthetic only)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "examples" / "sample-quality-report.html"
OUT = ROOT / "docs" / "images" / "sample-detection-engineering-report.png"


def find_browser() -> Path | None:
    candidates = [
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path("/usr/bin/google-chrome"),
        Path("/usr/bin/google-chrome-stable"),
        Path("/usr/bin/chromium"),
        Path("/usr/bin/chromium-browser"),
        Path("/usr/bin/microsoft-edge"),
        Path("/snap/bin/chromium"),
    ]
    which_chrome = (
        shutil.which("chrome") or shutil.which("google-chrome") or shutil.which("chromium")
    )
    which_edge = shutil.which("msedge") or shutil.which("microsoft-edge")
    found: list[Path] = []
    for path in candidates:
        if path.is_file():
            found.append(path)
    if which_chrome:
        found.append(Path(which_chrome))
    if which_edge:
        found.append(Path(which_edge))
    return found[0] if found else None


def main() -> int:
    if not HTML.is_file():
        raise SystemExit(f"Missing input HTML: {HTML}")
    text = HTML.read_text(encoding="utf-8")
    if "SYNTHETIC" not in text.upper():
        raise SystemExit("Refusing non-synthetic HTML input")

    browser = find_browser()
    if browser is None:
        raise SystemExit("No Chrome/Edge/Chromium found for headless screenshot")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    uri = HTML.resolve().as_uri()
    cmd = [
        str(browser),
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--window-size=1440,1000",
        f"--screenshot={OUT}",
        uri,
    ]
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=ROOT)
    if not OUT.is_file() or OUT.stat().st_size == 0:
        raise SystemExit("Screenshot was not created")
    size = OUT.stat().st_size
    if size > 2_000_000:
        print(f"WARNING: screenshot is {size} bytes (>2MB preferred)")
    print(f"Wrote {OUT} ({size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
