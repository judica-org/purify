#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <output-dir> <docs-html-dir> <paper-pdf> <paper-tex>" >&2
  exit 1
fi

out_dir="$1"
docs_dir="$2"
paper_pdf="$3"
paper_tex="$4"

rm -rf "$out_dir"
mkdir -p "$out_dir"

cp -R site/static/. "$out_dir/"

mkdir -p "$out_dir/docs"
cp -R "$docs_dir"/. "$out_dir/docs/"

mkdir -p "$out_dir/paper"
cp "$paper_pdf" "$out_dir/paper/purify-paper.pdf"
cp "$paper_tex" "$out_dir/paper/purify-paper.tex"

