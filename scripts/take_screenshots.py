"""Capture README screenshots from the running app, using synthetic sample data only.

Usage:  python scripts/take_screenshots.py [--chrome PATH]

1. Analyses the three synthetic samples in data/samples/ into a temporary database, and
   records one analyst verdict (the "enforce multi-factor authentication" mapping rejected).
2. Starts the app on that database (localhost only).
3. Drives headless Chrome or Edge over the DevTools protocol: it waits until each page has
   rendered, uploads a sample for the analysis view, clicks tabs, and saves PNGs in
   docs/screenshots/.

Nothing but the synthetic samples is ever shown, so the images are safe to publish. Uses
the ``websockets`` client (already installed with Streamlit).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "screenshots"
APP_PORT, DEBUG_PORT = 8598, 9333
APP = f"http://127.0.0.1:{APP_PORT}"
BROWSERS = [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "google-chrome", "chromium", "chromium-browser"]
# The .txt sample: its stored analysis carries the rejected T1556.006 verdict.
SAMPLE = ROOT / "data" / "samples" / "synthetic_advisory.txt"


def build_database(url: str) -> None:
    from src.database.db_manager import AnalysisRepository, make_engine
    from src.database.views import rescore_analysis
    from src.intelligence.analyzer import Analyzer
    from src.intelligence.mitre_mapper import AnalystVerdict

    repo, analyzer = AnalysisRepository(make_engine(url)), Analyzer()
    for name in ("synthetic_advisory.pdf", "synthetic_advisory.txt", "synthetic_advisory.docx"):
        data = (ROOT / "data" / "samples" / name).read_bytes()
        outcome = repo.save(analyzer.analyze(data, name))
        stored = repo.get_analysis(outcome.analysis_id)
        rejected = [m.id for m in stored.mappings if m.technique_id == "T1556.006"]
        for mapping_id in rejected:  # as in the UI: save the verdict, then re-score
            repo.set_mapping_verdict(mapping_id, AnalystVerdict.REJECTED,
                                     "mitigation advice, not attacker behaviour")
        if rejected:
            rescore_analysis(repo, outcome.analysis_id)


def wait_http(url: str, deadline: float) -> None:
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=3)
            return
        except OSError:
            time.sleep(1)
    raise SystemExit(f"{url} did not answer.")


class DevTools:
    """Minimal Chrome DevTools Protocol client."""

    def __init__(self, connection) -> None:
        self.connection, self.ids = connection, itertools.count(1)

    async def call(self, method: str, **params):
        message_id = next(self.ids)
        await self.connection.send(json.dumps(
            {"id": message_id, "method": method, "params": params}))
        while True:
            reply = json.loads(await self.connection.recv())
            if reply.get("id") == message_id:
                if "error" in reply:
                    raise RuntimeError(f"{method}: {reply['error']}")
                return reply.get("result", {})

    async def evaluate(self, expression: str):
        result = await self.call("Runtime.evaluate", expression=expression,
                                 returnByValue=True, awaitPromise=True)
        return result.get("result", {}).get("value")

    async def wait_for(self, expression: str, timeout: float = 60) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if await self.evaluate(expression):
                return
            await asyncio.sleep(0.5)
        await self.screenshot("_timeout_debug")  # what the browser showed; delete after use
        raise RuntimeError(f"timed out waiting for: {expression}")

    async def settle(self) -> None:
        """Wait until Streamlit has finished running and rendering the page."""
        await self.wait_for("document.querySelector('[data-testid=\"stMain\"]') !== null"
                            " && !document.querySelector('[data-testid=\"stSkeleton\"]')"
                            " && !document.querySelector('[data-testid=\"stStatusWidget\"]')")
        await asyncio.sleep(2.5)  # charts finish their layout animation

    async def screenshot(self, name: str) -> None:
        data = await self.call("Page.captureScreenshot", format="png")
        target = OUT / f"{name}.png"
        target.write_bytes(base64.b64decode(data["data"]))
        print(f"wrote {target.relative_to(ROOT)}")

    async def open(self, path: str) -> None:
        await self.call("Page.navigate", url=f"{APP}/{path}")
        await asyncio.sleep(1)
        await self.settle()

    async def click_tab(self, label: str) -> None:
        clicked = await self.evaluate(
            "(() => { const t = [...document.querySelectorAll('[role=tab]')]"
            f".find(b => b.innerText.includes({json.dumps(label)}));"
            " if (t) { t.click(); return true; } return false; })()")
        if not clicked:
            raise RuntimeError(f"tab {label!r} not found")
        await asyncio.sleep(1)
        await self.settle()


async def capture() -> None:
    from websockets.asyncio.client import connect

    targets = json.loads(urllib.request.urlopen(
        f"http://127.0.0.1:{DEBUG_PORT}/json/list", timeout=5).read())
    page = next(t for t in targets if t["type"] == "page")
    connection = await connect(page["webSocketDebuggerUrl"], max_size=64 * 2**20)
    tools = DevTools(connection)
    await tools.call("Page.enable")
    await tools.call("Emulation.setDeviceMetricsOverride", width=1440, height=1000,
                     deviceScaleFactor=1, mobile=False)

    # Analysis of a sample, uploaded through the file input as a user would.
    await tools.open("")  # the default page is served at /
    await tools.wait_for("document.querySelector('input[type=file]') !== null")
    handle = await tools.call("Runtime.evaluate",
                              expression="document.querySelector('input[type=file]')")
    await tools.call("DOM.setFileInputFiles", objectId=handle["result"]["objectId"],
                     files=[str(SAMPLE)])
    await tools.wait_for("[...document.querySelectorAll('[role=tab]')]"
                         ".some(b => b.innerText.includes('Risk'))", timeout=120)
    await tools.settle()
    await tools.screenshot("analysis_risk")
    for label, name in (("ATT&CK", "analysis_attack"), ("IOCs", "analysis_iocs")):
        await tools.click_tab(label)
        await tools.screenshot(name)

    for path, name in (("dashboard", "dashboard"), ("history", "history"),
                       ("iocs", "ioc_explorer"), ("attack", "attack_explorer")):
        await tools.open(path)
        await tools.screenshot(name)
    await connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", default=None)
    args = parser.parse_args()
    browser = args.chrome or next((b for b in BROWSERS if shutil.which(b) or Path(b).exists()),
                                  None)
    if browser is None:
        raise SystemExit("No Chrome/Edge found; pass --chrome PATH.")
    workdir = Path(tempfile.mkdtemp(prefix="cybersleuth-shots-"))
    db_url = f"sqlite:///{(workdir / 'demo.db').as_posix()}"
    build_database(db_url)
    env = dict(os.environ, CYBERSLEUTH_DB_URL=db_url)
    server = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "app.py", "--server.address=127.0.0.1",
         f"--server.port={APP_PORT}", "--server.headless=true", "--server.fileWatcherType=none"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    chrome = subprocess.Popen(
        [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
         f"--remote-debugging-port={DEBUG_PORT}", "--remote-debugging-address=127.0.0.1",
         f"--user-data-dir={workdir / 'profile'}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        wait_http(f"{APP}/_stcore/health", time.time() + 90)
        wait_http(f"http://127.0.0.1:{DEBUG_PORT}/json/version", time.time() + 30)
        for stale in OUT.glob("*.png"):
            stale.unlink()
        asyncio.run(capture())
    finally:
        chrome.terminate()
        server.terminate()
        chrome.wait(timeout=30)
        server.wait(timeout=30)
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
