#!/usr/bin/env python3
# Copyright (c) 2026 Judica, Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from __future__ import annotations

import argparse
import json
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CBMC with JSON output and print a concise summary.")
    parser.add_argument("--name", required=True, help="User-facing proof name.")
    parser.add_argument("--cbmc", required=True, help="Path to the cbmc executable.")
    parser.add_argument("cbmc_args", nargs=argparse.REMAINDER, help="Arguments passed through to cbmc after '--'.")
    args = parser.parse_args()

    cbmc_args = list(args.cbmc_args)
    if cbmc_args and cbmc_args[0] == "--":
        cbmc_args = cbmc_args[1:]

    command = [args.cbmc, *cbmc_args, "--json-ui"]
    proc = subprocess.run(command, capture_output=True, text=True)

    if not proc.stdout.strip():
        print(f"CBMC FAIL {args.name}")
        print(f"  cbmc exited with code {proc.returncode} and produced no JSON output")
        print(f"  command: {' '.join(command)}")
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        return proc.returncode or 1

    try:
        events = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"CBMC FAIL {args.name}")
        print(f"  cbmc exited with code {proc.returncode} and produced non-JSON output")
        print(f"  command: {' '.join(command)}")
        sys.stdout.write(proc.stdout)
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        return proc.returncode or 1

    failures: list[str] = []
    proven_properties = 0
    for event in events:
        if not isinstance(event, dict) or "result" not in event:
            continue
        result = event["result"]
        if not isinstance(result, list):
            continue
        for item in result:
            if not isinstance(item, dict):
                continue
            status = item.get("status")
            if status in ("SUCCESS", "UNKNOWN"):
                if status == "SUCCESS":
                    proven_properties += 1
                continue
            property_name = item.get("property")
            description = item.get("description")
            source_location = item.get("sourceLocation") or {}
            location = source_location.get("file")
            line = source_location.get("line")
            detail = property_name or description or "unknown property"
            if location:
                if line:
                    detail = f"{detail} ({location}:{line})"
                else:
                    detail = f"{detail} ({location})"
            failures.append(detail)

    if failures or proc.returncode != 0:
        print(f"CBMC FAIL {args.name}")
        for failure in failures[:20]:
            print(f"  {failure}")
        if proc.returncode != 0 and not failures:
            print(f"  cbmc exited with code {proc.returncode} without reporting a failed property")
            print(f"  command: {' '.join(command)}")
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        return 1

    print(f"CBMC PASS {args.name} ({proven_properties} properties)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
