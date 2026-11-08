"""Time and memory of a full analysis, by stage and document size.

Usage:
    python scripts/benchmark.py                        # synthetic TXT documents, several sizes
    python scripts/benchmark.py --sizes 100000 500000
    python scripts/benchmark.py --file path/to/report.pdf [--file ...]

Synthetic documents repeat the committed synthetic evaluation reports
(``data/evaluation/*/*.txt``) up to the requested number of characters. Each run happens in a
fresh process, so the reported peak memory belongs to that run alone. Model loading is timed
separately and is not part of the analysis time. Results are printed as JSON; the write-up
is docs/performance.md.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SIZES = (50_000, 100_000, 250_000, 500_000, 1_000_000)


def synthetic_text(chars: int) -> str:
    sources = sorted((ROOT / "data" / "evaluation").glob("*/*.txt"))
    corpus = "\n\n".join(p.read_text(encoding="utf-8") for p in sources)
    repeats = chars // len(corpus) + 1
    return ("\n\n".join([corpus] * repeats))[:chars]


def peak_memory_mb() -> float | None:
    """Peak resident memory of this process, in MB."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        kernel32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
        # 64-bit handles: without explicit types ctypes truncates them to 32 bits.
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters),
                                               wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        process = kernel32.GetCurrentProcess()
        if not psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
            return None
        return counters.PeakWorkingSetSize / 2**20
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / 2**20 if sys.platform == "darwin" else peak / 2**10  # bytes vs KB


def worker(kind: str, value: str) -> dict:
    sys.path.insert(0, str(ROOT))
    from config.settings import IngestionSettings
    from src.intelligence.analyzer import Analyzer

    started = time.perf_counter()
    analyzer = Analyzer()
    load_s = time.perf_counter() - started
    baseline_mb = peak_memory_mb()
    if kind == "size":
        data, name = synthetic_text(int(value)).encode("utf-8"), f"synthetic_{value}.txt"
    else:
        path = Path(value)
        data, name = path.read_bytes(), path.name
    # Benchmarks may exceed the default text cap on purpose, to see what it protects against.
    from src.ingestion import pipeline

    original = pipeline.ingest

    def ingest_without_cap(*args, **kwargs):
        kwargs["limits"] = IngestionSettings(max_text_chars=10**9)
        return original(*args, **kwargs)

    import src.intelligence.analyzer as analyzer_module
    analyzer_module.ingest = ingest_without_cap
    result = analyzer.analyze(data, name)
    return {
        "document": name, "pages": result.document.page_count,
        "chars": result.document.char_count, "sentences": len(result.document.sentences),
        "indicators": len(result.indicators), "entities": len(result.entities),
        "techniques": len(result.mappings), "model_load_s": round(load_s, 2),
        "stages_s": {k: round(v / 1000, 2) for k, v in result.timings_ms.items()},
        "peak_memory_mb": round(peak_memory_mb() or 0), "after_load_mb": round(baseline_mb or 0),
    }


def run(kind: str, value: str) -> dict:
    out = subprocess.run([sys.executable, __file__, "--worker", kind, value],
                         capture_output=True, text=True, check=True, cwd=ROOT)
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="*", default=None)
    parser.add_argument("--file", type=Path, action="append", default=[])
    parser.add_argument("--worker", nargs=2, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(*args.worker)))
        return 0
    runs = [("file", str(p)) for p in args.file]
    if args.sizes is not None or not runs:
        runs += [("size", str(n)) for n in (args.sizes or DEFAULT_SIZES)]
    results = []
    for kind, value in runs:
        result = run(kind, value)
        results.append(result)
        stages = result["stages_s"]
        print(f"{result['document']}: {result['chars']:,} chars, total {stages['total']} s, "
              f"peak {result['peak_memory_mb']} MB  {stages}", file=sys.stderr)
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
