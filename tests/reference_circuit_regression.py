#!/usr/bin/env python3

import argparse
import collections
import difflib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SECRET_HEX = (
    "11427c7268288dddf0cd24af3d30524fd817a91e103e7e02eb28b78db81cb350"
    "b3d2562f45fa8ecd711d1becc02fa348cf2187429228e7aac6644a3da2824e93"
)
MESSAGE_HEX = "01234567"
FIELD_MODULUS = 115792089237316195423570985008687907852837564279074904382605163141518161494337
VARIABLE_RE = re.compile(r"^(?:[LROV]\d+|v\[\d+\])$")
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare the checked-out Python reference verifier against purify_cpp."
    )
    parser.add_argument("--reference-script", required=True, type=Path)
    parser.add_argument("--purify-cpp", required=True, type=Path)
    parser.add_argument("--reference-patches-dir", type=Path)
    parser.add_argument("--hash-mode", choices=("legacy", "tagged"), default="tagged")
    return parser.parse_args()


def run_checked(args: list[str], env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(args, capture_output=True, text=True, check=False, env=env)
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


def normalize_patch_path(path_text: str) -> Path:
    path_text = path_text.strip().split("\t", 1)[0]
    if path_text in ("/dev/null", ""):
        raise RuntimeError(f"unsupported patch path: {path_text!r}")
    if path_text.startswith("a/") or path_text.startswith("b/"):
        path_text = path_text[2:]
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        raise RuntimeError(f"unsafe patch path: {path_text!r}")
    return path


def parse_patch_file(patch_file: Path) -> list[tuple[Path, list[tuple[int, list[str]]]]]:
    lines = patch_file.read_text(encoding="utf-8").splitlines()
    files: list[tuple[Path, list[tuple[int, list[str]]]]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line or line.startswith("diff --git ") or line.startswith("index "):
            i += 1
            continue
        if not line.startswith("--- "):
            raise RuntimeError(f"unsupported patch header in {patch_file}: {line}")
        old_path = normalize_patch_path(line[4:])
        i += 1
        if i >= len(lines) or not lines[i].startswith("+++ "):
            raise RuntimeError(f"missing +++ header in {patch_file}")
        new_path = normalize_patch_path(lines[i][4:])
        if old_path != new_path:
            raise RuntimeError(f"rename patches are unsupported in {patch_file}: {old_path} -> {new_path}")
        i += 1

        hunks: list[tuple[int, list[str]]] = []
        while i < len(lines):
            line = lines[i]
            if not line:
                i += 1
                continue
            if line.startswith("--- "):
                break
            if line.startswith("diff --git ") or line.startswith("index "):
                i += 1
                continue
            match = HUNK_RE.match(line)
            if match is None:
                raise RuntimeError(f"unsupported patch line in {patch_file}: {line}")
            old_start = int(match.group(1))
            i += 1
            hunk_lines: list[str] = []
            while i < len(lines):
                line = lines[i]
                if line.startswith("--- ") or HUNK_RE.match(line):
                    break
                if line == r"\ No newline at end of file":
                    i += 1
                    continue
                if not line or line[0] not in (" ", "+", "-"):
                    raise RuntimeError(f"unsupported hunk line in {patch_file}: {line}")
                hunk_lines.append(line)
                i += 1
            hunks.append((old_start, hunk_lines))
        files.append((new_path, hunks))
    return files


def apply_hunks_to_lines(lines: list[str], hunks: list[tuple[int, list[str]]], patch_file: Path, target_path: Path) -> list[str]:
    offset = 0
    for old_start, hunk_lines in hunks:
        old_chunk: list[str] = []
        new_chunk: list[str] = []
        for line in hunk_lines:
            if line[0] == " ":
                old_chunk.append(line[1:])
                new_chunk.append(line[1:])
            elif line[0] == "-":
                old_chunk.append(line[1:])
            elif line[0] == "+":
                new_chunk.append(line[1:])
        index = old_start - 1 + offset
        current = lines[index:index + len(old_chunk)]
        if current != old_chunk:
            raise RuntimeError(
                f"failed to apply {patch_file} to {target_path}: expected hunk context at line {old_start}"
            )
        lines[index:index + len(old_chunk)] = new_chunk
        offset += len(new_chunk) - len(old_chunk)
    return lines


def apply_reference_patch_tree(reference_root: Path, patches_dir: Path) -> None:
    patch_files = sorted(patches_dir.glob("patch_*.patch"))
    for patch_file in patch_files:
        for relative_path, hunks in parse_patch_file(patch_file):
            target_path = reference_root / relative_path
            if not target_path.is_file():
                raise RuntimeError(f"patch target does not exist: {target_path}")
            original_text = target_path.read_text(encoding="utf-8")
            has_trailing_newline = original_text.endswith("\n")
            lines = original_text.splitlines()
            patched_lines = apply_hunks_to_lines(lines, hunks, patch_file, target_path)
            patched_text = "\n".join(patched_lines)
            if has_trailing_newline or patched_text:
                patched_text += "\n"
            target_path.write_text(patched_text, encoding="utf-8")


def prepare_reference_script(reference_script: Path, reference_patches_dir: Path | None) -> tuple[tempfile.TemporaryDirectory, Path]:
    temp_dir = tempfile.TemporaryDirectory(prefix="purify_reference_")
    copied_root = Path(temp_dir.name) / reference_script.parent.name
    shutil.copytree(reference_script.parent, copied_root)
    if reference_patches_dir is not None:
        if not reference_patches_dir.is_dir():
            raise RuntimeError(f"missing reference patches directory: {reference_patches_dir}")
        apply_reference_patch_tree(copied_root, reference_patches_dir)
    return temp_dir, copied_root / reference_script.name


def main() -> int:
    args = parse_args()
    reference_script = args.reference_script.resolve()
    purify_cpp = args.purify_cpp.resolve()
    reference_patches_dir = args.reference_patches_dir.resolve() if args.reference_patches_dir else None

    if not reference_script.is_file():
        raise RuntimeError(f"missing reference script: {reference_script}")
    if not purify_cpp.is_file():
        raise RuntimeError(f"missing purify_cpp executable: {purify_cpp}")

    reference_env = os.environ.copy()
    reference_env["PURIFY_REFERENCE_FIELD_HASH_MODE"] = args.hash_mode

    temp_dir, patched_reference_script = prepare_reference_script(reference_script, reference_patches_dir)
    try:
        reference_gen = run_checked([sys.executable, str(patched_reference_script), "gen", SECRET_HEX], env=reference_env)
        cpp_gen = run_checked([str(purify_cpp), "gen", SECRET_HEX])

        reference_pubkey = extract_hex_assignment(reference_gen, "x")
        cpp_pubkey = extract_hex_assignment(cpp_gen, "x")
        if cpp_pubkey != reference_pubkey:
            print("public key mismatch between Python reference and purify_cpp", file=sys.stderr)
            print(f"reference: {reference_pubkey}", file=sys.stderr)
            print(f"purify_cpp: {cpp_pubkey}", file=sys.stderr)
            return 1

        reference_verifier = run_checked(
            [sys.executable, str(patched_reference_script), "verifier", MESSAGE_HEX, reference_pubkey],
            env=reference_env,
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
    finally:
        temp_dir.cleanup()


if __name__ == "__main__":
    sys.exit(main())
