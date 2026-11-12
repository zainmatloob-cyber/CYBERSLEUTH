"""Capture README screenshots from the running app, using synthetic sample data only.

Usage:  python scripts/take_screenshots.py [--chrome PATH]

1. Analyses the three synthetic samples in data/samples/ into a temporary database, and
   records one analyst verdict (the "enforce multi-factor authentication" mapping rejected).
2. Serves the web app on that database (localhost only), in this process.
3. Every view has its own URL, so headless Chrome or Edge simply loads each one and saves a
   PNG in docs/screenshots/ (light theme, plus dark versions of two views).

Nothing but the synthetic samples is ever shown, so the images are safe to publish.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "screenshots"
PORT = 8598
APP = f"http://127.0.0.1:{PORT}"
BROWSERS = [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "google-chrome", "chromium", "chromium-browser"]
SAMPLES = ("synthetic_advisory.pdf", "synthetic_advisory.txt", "synthetic_advisory.docx")
# (file name, path, theme, window height). {txt} is the analysis of the .txt sample, whose
# stored analysis carries the rejected T1556.006 verdict.
SHOTS = [
    ("analysis_risk", "/analyses/{txt}?tab=risk", "light", 1500),
    ("analysis_attack", "/analyses/{txt}?tab=attack&f=1&hide_negated=1", "light", 1000),
    ("analysis_iocs", "/analyses/{txt}?tab=iocs", "light", 1300),
    ("dashboard", "/dashboard", "light", 1250),
    ("history", "/history", "light", 700),
    ("ioc_explorer", "/explorer/iocs", "light", 1300),
    ("attack_explorer", "/explorer/attack", "light", 1100),
    ("analysis_attack_dark", "/analyses/{txt}?tab=attack&f=1&hide_negated=1", "dark", 1000),
    ("dashboard_dark", "/dashboard", "dark", 1250),
]
COLOR_SCHEME = {"light": 1, "dark": 0}  # Blink's preferredColorScheme values


def build_app(db_url: str):
    """Analyse the samples, save them, and return the app plus the .txt analysis id."""
    from src.database.db_manager import AnalysisRepository, make_engine
    from src.database.views import rescore_analysis
    from src.intelligence.analyzer import Analyzer
    from src.intelligence.mitre_mapper import AnalystVerdict
    from src.web.app import create_app

    repo, analyzer = AnalysisRepository(make_engine(db_url)), Analyzer()
    app = create_app(lambda: analyzer, lambda: repo)
    txt_id = None
    for name in SAMPLES:
        result = analyzer.analyze((ROOT / "data" / "samples" / name).read_bytes(), name)
        outcome = repo.save(result)
        app.state.cs.cache.put(str(outcome.analysis_id), result)  # enables the text tabs
        stored = repo.get_analysis(outcome.analysis_id)
        rejected = [m.id for m in stored.mappings if m.technique_id == "T1556.006"]
        for mapping_id in rejected:  # as in the UI: save the verdict, then re-score
            repo.set_mapping_verdict(mapping_id, AnalystVerdict.REJECTED,
                                     "mitigation advice, not attacker behaviour")
        if rejected:
            rescore_analysis(repo, outcome.analysis_id)
        if name.endswith(".txt"):
            txt_id = outcome.analysis_id
    return app, txt_id


def wait_http(url: str, deadline: float) -> None:
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=3)
            return
        except OSError:
            time.sleep(0.5)
    raise SystemExit(f"{url} did not answer.")


def shoot(browser: str, profile: Path, url: str, theme: str, height: int, target: Path) -> None:
    subprocess.run(
        [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
         f"--user-data-dir={profile}", f"--window-size=1440,{height}",
         f"--blink-settings=preferredColorScheme={COLOR_SCHEME[theme]}",
         "--virtual-time-budget=10000",  # let charts finish drawing
         f"--screenshot={target}", url],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    if not target.exists():
        raise SystemExit(f"{browser} wrote no screenshot for {url}")
    print(f"wrote {target.relative_to(ROOT)}")


def main() -> int:
    import uvicorn

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", default=None)
    args = parser.parse_args()
    browser = args.chrome or next((b for b in BROWSERS if shutil.which(b) or Path(b).exists()),
                                  None)
    if browser is None:
        raise SystemExit("No Chrome/Edge found; pass --chrome PATH.")
    workdir = Path(tempfile.mkdtemp(prefix="cybersleuth-shots-"))
    app, txt_id = build_app(f"sqlite:///{(workdir / 'demo.db').as_posix()}")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT,
                                           log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        wait_http(f"{APP}/healthz", time.time() + 30)
        for stale in OUT.glob("*.png"):
            stale.unlink()
        for name, path, theme, height in SHOTS:
            shoot(browser, workdir / f"profile-{theme}", APP + path.format(txt=txt_id), theme,
                  height, OUT / f"{name}.png")
    finally:
        server.should_exit = True
        thread.join(timeout=30)
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
