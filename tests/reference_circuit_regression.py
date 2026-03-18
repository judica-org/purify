#!/usr/bin/env python3

import argparse
import collections
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
FIELD_MODULUS = 115792089237316195423570985008687907852837564279074904382605163141518161494337
VARIABLE_RE = re.compile(r"^(?:[LROV]\d+|v\[\d+\])$")


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


def parse_linear_expr(expr: str) -> tuple[int, collections.Counter[str]]:
    constant = 0
    coeffs: collections.Counter[str] = collections.Counter()
    for term in expr.split(" + "):
        term = term.strip()
        if not term:
            continue
        if " * " in term:
            coeff_text, symbol = term.split(" * ", 1)
            if not VARIABLE_RE.fullmatch(symbol):
                raise RuntimeError(f"unsupported variable term in verifier output: {term}")
            coeffs[symbol] = (coeffs[symbol] + int(coeff_text)) % FIELD_MODULUS
            if coeffs[symbol] == 0:
                del coeffs[symbol]
            continue
        if VARIABLE_RE.fullmatch(term):
            coeffs[term] = (coeffs[term] + 1) % FIELD_MODULUS
            if coeffs[term] == 0:
                del coeffs[term]
            continue
        constant = (constant + int(term)) % FIELD_MODULUS
    return constant, coeffs


def normalize_statement(statement: str) -> tuple[str, str] | tuple[tuple[tuple[str, int], ...], int]:
    statement = statement.strip()
    if statement.endswith(";"):
        statement = statement[:-1]
    if " = " not in statement:
        return ("raw", statement)
    lhs, rhs = statement.split(" = ", 1)
    lhs_const, lhs_coeffs = parse_linear_expr(lhs)
    rhs_const, rhs_coeffs = parse_linear_expr(rhs)

    for symbol, coeff in rhs_coeffs.items():
        lhs_coeffs[symbol] = (lhs_coeffs[symbol] - coeff) % FIELD_MODULUS
        if lhs_coeffs[symbol] == 0:
            del lhs_coeffs[symbol]

    constant = (lhs_const - rhs_const) % FIELD_MODULUS
    return tuple(sorted(lhs_coeffs.items())), constant


def canonical_statement(statement: str) -> str:
    normalized = normalize_statement(statement)
    if isinstance(normalized[0], str):
        return f"{normalized[1]};\n"
    coeffs, constant = normalized
    terms: list[str] = []
    for symbol, coeff in coeffs:
        if coeff == 1:
            terms.append(symbol)
        else:
            terms.append(f"{coeff} * {symbol}")
    rhs = (-constant) % FIELD_MODULUS
    if not terms:
        terms.append("0")
    return f"{' + '.join(terms)} = {rhs};\n"


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
        reference_statements = split_verifier(reference_verifier)
        cpp_statements = split_verifier(cpp_verifier)

        if len(reference_statements) == len(cpp_statements):
            reference_normalized = [normalize_statement(statement) for statement in reference_statements]
            cpp_normalized = [normalize_statement(statement) for statement in cpp_statements]
            if cpp_normalized == reference_normalized:
                print("reference circuit regression passed (normalized verifier circuit matches)")
                return 0

        diff = "".join(
            difflib.unified_diff(
                [canonical_statement(statement) for statement in reference_statements],
                [canonical_statement(statement) for statement in cpp_statements],
                fromfile="reference/purify",
                tofile="purify_cpp",
            )
        )
        print("verifier circuit mismatch between Python reference and purify_cpp", file=sys.stderr)
        if diff:
            print(diff, file=sys.stderr, end="")
        else:
            print("outputs differ but no normalized statement-level diff was generated", file=sys.stderr)
        return 1

    print("reference circuit regression passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
