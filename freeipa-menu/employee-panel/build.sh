#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p dist
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 2026-09-23' \
    -czf dist/office-employee-panel-1.0.0.tar.gz \
    applet panel_helper.py install.py office-employee-panel.desktop README.md
cd dist
sha256sum office-employee-panel-1.0.0.tar.gz > office-employee-panel-1.0.0.tar.gz.sha256
