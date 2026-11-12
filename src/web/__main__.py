"""Start the web server:  python -m src.web  [--host 127.0.0.1] [--port 8000]

Binds to localhost by default: the app has no login, so expose it on a network only
behind an authenticating reverse proxy (see docs/deployment.md).
"""

from __future__ import annotations

import argparse
import os

import uvicorn

from src.utils.logging_config import configure_logging


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the CyberSleuth web interface.")
    parser.add_argument("--host", default=os.getenv("CYBERSLEUTH_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("CYBERSLEUTH_PORT", "8000")))
    args = parser.parse_args()
    configure_logging()
    print(f"CyberSleuth running at http://{args.host}:{args.port}  (Ctrl+C to stop)")
    uvicorn.run("src.web.app:create_app", factory=True, host=args.host, port=args.port,
                log_level="warning", server_header=False)


if __name__ == "__main__":
    main()
