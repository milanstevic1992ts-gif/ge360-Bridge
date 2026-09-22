#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ge360_bridge.update_engine import build_update_package


def main() -> None:
    parser = argparse.ArgumentParser(description="Build GE360 Bridge update package")
    parser.add_argument("--source", default=".", help="Repository/source root")
    parser.add_argument("--output", required=True, help="Output .tar.gz")
    args = parser.parse_args()
    result = build_update_package(Path(args.source), Path(args.output))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
