#!/usr/bin/env python3

import argparse
import difflib
import re
import subprocess
import sys
from pathlib import Path


SECRET_HEX = (
    "11427c7268288dddf0cd24af3d30524fd817a91e103e7e02eb28b78db81cb350"
    "b3d2562f45fa8ecd711d1becc02fa348cf2187429228e7aac6644a3da2824e93"
)
MESSAGE_HEX = "01234567"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare the checked-out Python reference verifier against purify_cpp."
    )
    parser.add_argument("--reference-script", required=True, type=Path)
    parser.add_argument("--purify-cpp", required=True, type=Path)
    return parser.parse_args()


def run_checked(args: list[str]) -> str:
    completed = subprocess.run(args, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        command = " ".join(str(arg) for arg in args)
        raise RuntimeError(
            f"command failed: {command}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout.rstrip("\r\n")


def extract_hex_assignment(output: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}=([0-9a-fA-F]+)\b", output, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"missing {name}=... field in output:\n{output}")
    return match.group(1).lower()


def split_verifier(program: str) -> list[str]:
    lines = []
    for statement in program.split(";"):
        statement = statement.strip()
        if statement:
            lines.append(f"{statement};\n")
    return lines


def main() -> int:
    args = parse_args()
    reference_script = args.reference_script.resolve()
    purify_cpp = args.purify_cpp.resolve()

    if not reference_script.is_file():
        raise RuntimeError(f"missing reference script: {reference_script}")
    if not purify_cpp.is_file():
        raise RuntimeError(f"missing purify_cpp executable: {purify_cpp}")

    reference_gen = run_checked([sys.executable, str(reference_script), "gen", SECRET_HEX])
    cpp_gen = run_checked([str(purify_cpp), "gen", SECRET_HEX])

    reference_pubkey = extract_hex_assignment(reference_gen, "x")
    cpp_pubkey = extract_hex_assignment(cpp_gen, "x")
    if cpp_pubkey != reference_pubkey:
        print("public key mismatch between Python reference and purify_cpp", file=sys.stderr)
        print(f"reference: {reference_pubkey}", file=sys.stderr)
        print(f"purify_cpp: {cpp_pubkey}", file=sys.stderr)
        return 1

    reference_verifier = run_checked(
        [sys.executable, str(reference_script), "verifier", MESSAGE_HEX, reference_pubkey]
    )
    cpp_verifier = run_checked([str(purify_cpp), "verifier", MESSAGE_HEX, reference_pubkey])

    if cpp_verifier != reference_verifier:
        diff = "".join(
            difflib.unified_diff(
                split_verifier(reference_verifier),
                split_verifier(cpp_verifier),
                fromfile="reference/purify",
                tofile="purify_cpp",
            )
        )
        print("verifier circuit mismatch between Python reference and purify_cpp", file=sys.stderr)
        if diff:
            print(diff, file=sys.stderr, end="")
        else:
            print("outputs differ but no statement-level diff was generated", file=sys.stderr)
        return 1

    print("reference circuit regression passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
