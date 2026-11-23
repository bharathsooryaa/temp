"""CLI:  uv run --locked python -m guardian.api [--port 8000] [--db runs/guardian.db]

Serves the read-only API and the built UI (ui/dist) on loopback only.
"""

from __future__ import annotations

import argparse
import sys

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="guardian.api")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--db", default="runs/guardian.db")
    a = p.parse_args(argv)
    if a.host not in LOOPBACK:
        print(
            f"refused: {a.host} is not a loopback address (the API is local-only)", file=sys.stderr
        )
        return 2

    import uvicorn

    from guardian.api.app import create_app

    uvicorn.run(create_app(a.db), host=a.host, port=a.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
