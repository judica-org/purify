#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_DIR="${SCRIPT_DIR}/build"
OUTPUT_PDF="${SCRIPT_DIR}/purify-paper.pdf"

mkdir -p "${BUILD_DIR}"

cd "${SCRIPT_DIR}"
latexmk -pdf -file-line-error -interaction=nonstopmode -halt-on-error -outdir="${BUILD_DIR}" purify-paper.tex
cp "${BUILD_DIR}/purify-paper.pdf" "${OUTPUT_PDF}"
