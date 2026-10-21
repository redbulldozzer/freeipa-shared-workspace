#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir="$project_dir/dist"
archive="$output_dir/shared-workspace-rollout.tar.gz"
mkdir -p "$output_dir"
tar --sort=name --owner=0 --group=0 --numeric-owner \
    --transform='s,^,shared-workspace-rollout/,' \
    --exclude='build' --exclude='dist' --exclude='.git' --exclude='__pycache__' \
    --exclude='*.pyc' --exclude='*.key' --exclude='*.keytab' --exclude='.secrets' \
    -C "$project_dir" -czf "$archive" \
    Makefile README.md config docs scripts src tests
(cd "$output_dir" && sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256")
printf '%s\n' "$archive" "$archive.sha256"
