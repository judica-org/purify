#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: contrib/vendor.sh --output <dir> [--include-extras=minified,tests,extras]

Flags accepted by --include-extras:
  minified  Trim third-party vendored trees to the dependency closure needed by
            the exported sources. This requires a C compiler available as CC,
            cc, clang, or gcc.
  tests     Include tests/, verification/, and reference-test patch files.
  extras    Include optional CLI, bench, fuzz, docs support files, and
            nanobench when needed for bench builds.

Notes:
  - The reference/ subtrees are always excluded.
  - The output directory must not already contain files.
  - Multiple flags can be separated by ',' or '|', and --include-extras can be
    repeated.
EOF
}

die() {
    printf 'vendor.sh: %s\n' "$*" >&2
    exit 1
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_DIR=""
INCLUDE_SPEC=""
INCLUDE_MINIFIED=0
INCLUDE_TESTS=0
INCLUDE_EXTRAS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            [[ $# -ge 2 ]] || die "missing value for --output"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --output=*)
            OUTPUT_DIR="${1#*=}"
            shift
            ;;
        --include-extras)
            [[ $# -ge 2 ]] || die "missing value for --include-extras"
            if [[ -n "$INCLUDE_SPEC" ]]; then
                INCLUDE_SPEC="${INCLUDE_SPEC},${2}"
            else
                INCLUDE_SPEC="$2"
            fi
            shift 2
            ;;
        --include-extras=*)
            if [[ -n "$INCLUDE_SPEC" ]]; then
                INCLUDE_SPEC="${INCLUDE_SPEC},${1#*=}"
            else
                INCLUDE_SPEC="${1#*=}"
            fi
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[[ -n "$OUTPUT_DIR" ]] || die "--output is required"

if [[ -e "$OUTPUT_DIR" ]]; then
    [[ -d "$OUTPUT_DIR" ]] || die "--output must be a directory path"
    if find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 | read -r _; then
        die "--output must be empty: $OUTPUT_DIR"
    fi
else
    mkdir -p "$OUTPUT_DIR"
fi

git -C "$REPO_ROOT" rev-parse --show-toplevel >/dev/null 2>&1 || die "repository root is not a git checkout"

if [[ -n "$INCLUDE_SPEC" ]]; then
    INCLUDE_SPEC="${INCLUDE_SPEC//|/,}"
    OLD_IFS="$IFS"
    IFS=','
    read -r -a INCLUDE_TOKENS <<< "$INCLUDE_SPEC"
    IFS="$OLD_IFS"
    for token in "${INCLUDE_TOKENS[@]}"; do
        token="$(printf '%s' "$token" | tr -d '[:space:]')"
        [[ -n "$token" ]] || continue
        case "$token" in
            minified)
                INCLUDE_MINIFIED=1
                ;;
            tests)
                INCLUDE_TESTS=1
                ;;
            extras)
                INCLUDE_EXTRAS=1
                ;;
            *)
                die "unsupported --include-extras flag: $token"
                ;;
        esac
    done
fi

FILE_LIST="$(mktemp)"
SORTED_LIST="$(mktemp)"
trap 'rm -f "$FILE_LIST" "$SORTED_LIST"' EXIT

append_file() {
    local rel="$1"
    [[ -f "$REPO_ROOT/$rel" ]] || die "missing required file: $rel"
    printf '%s\n' "$rel" >> "$FILE_LIST"
}

append_superproject_dir() {
    local rel_dir="$1"
    git -C "$REPO_ROOT" ls-files -- "$rel_dir" >> "$FILE_LIST"
}

append_submodule_dir() {
    local submodule_rel="$1"
    local submodule_dir="$REPO_ROOT/$submodule_rel"
    [[ -d "$submodule_dir" ]] || die "missing submodule directory: $submodule_rel"
    git -C "$submodule_dir" ls-files | sed "s#^#${submodule_rel}/#" >> "$FILE_LIST"
}

find_c_compiler() {
    local candidate
    if [[ -n "${CC:-}" ]] && command -v -- "${CC}" >/dev/null 2>&1; then
        printf '%s\n' "${CC}"
        return 0
    fi
    for candidate in cc clang gcc; do
        if command -v -- "$candidate" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

append_dependencies_for_source() {
    local compiler="$1"
    local source_rel="$2"
    local dep_output
    dep_output="$(
        cd "$REPO_ROOT"
        "$compiler" -MM \
            -I"$REPO_ROOT" \
            -I"$REPO_ROOT/include" \
            -I"$REPO_ROOT/src/core" \
            -I"$REPO_ROOT/src/api" \
            -I"$REPO_ROOT/src/support" \
            -I"$REPO_ROOT/src/protocol" \
            -I"$REPO_ROOT/src/bridge" \
            "$source_rel"
    )" || die "failed to derive dependencies for $source_rel with $compiler"
    dep_output="$(printf '%s\n' "$dep_output" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\\\n/ /g' -e 's/^[^:]*: *//')"
    printf '%s\n' "$dep_output" \
        | tr ' ' '\n' \
        | sed '/^$/d' \
        | while IFS= read -r rel; do
            case "$rel" in
                "$REPO_ROOT"/*)
                    rel="${rel#"$REPO_ROOT"/}"
                    ;;
                ./*)
                    rel="${rel#./}"
                    ;;
            esac
            case "$rel" in
                third_party/secp256k1-zkp/*)
                    append_file "$rel"
                    ;;
            esac
        done
}

append_minified_secp256k1() {
    local compiler
    compiler="$(find_c_compiler)" || die "minified exports require a C compiler (set CC or install cc/clang/gcc)"
    append_file "third_party/secp256k1-zkp/COPYING"
    append_dependencies_for_source "$compiler" "src/bridge/bppp_bridge.c"
    append_dependencies_for_source "$compiler" "src/legacy_bulletproof/scratch_frames.c"
}

append_minified_nanobench() {
    append_file "third_party/nanobench/CMakeLists.txt"
    append_file "third_party/nanobench/LICENSE"
    append_file "third_party/nanobench/README.md"
    append_file "third_party/nanobench/src/include/nanobench.h"
    append_file "third_party/nanobench/src/test/app/nanobench.cpp"
}

append_file "CMakeLists.txt"
append_file "COPYING"
append_file "README.md"
append_superproject_dir "cmake"
append_superproject_dir "include"
append_superproject_dir "src"

if [[ "$INCLUDE_TESTS" -eq 1 ]]; then
    append_superproject_dir "tests"
    append_superproject_dir "verification"
    append_superproject_dir "patches"
fi

if [[ "$INCLUDE_EXTRAS" -eq 1 ]]; then
    append_superproject_dir "cli"
    append_superproject_dir "bench"
    append_superproject_dir "fuzz"
    append_file "Doxyfile.in"
    append_file "site/doxygen-awesome-custom.css"
fi

if [[ "$INCLUDE_MINIFIED" -eq 1 ]]; then
    append_minified_secp256k1
else
    append_submodule_dir "third_party/secp256k1-zkp"
fi

if [[ "$INCLUDE_EXTRAS" -eq 1 ]]; then
    if [[ "$INCLUDE_MINIFIED" -eq 1 ]]; then
        append_minified_nanobench
    else
        append_submodule_dir "third_party/nanobench"
    fi
fi

LC_ALL=C sort -u "$FILE_LIST" > "$SORTED_LIST"

while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    mkdir -p "$OUTPUT_DIR/$(dirname "$rel")"
    cp -p "$REPO_ROOT/$rel" "$OUTPUT_DIR/$rel"
done < "$SORTED_LIST"

printf 'wrote vendor tree to %s (%s files)\n' "$OUTPUT_DIR" "$(wc -l < "$SORTED_LIST" | tr -d '[:space:]')"
