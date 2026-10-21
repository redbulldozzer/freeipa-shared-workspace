#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p freeipa-menu/dist
tar --sort=name --owner=0 --group=0 --numeric-owner \
    --exclude='freeipa-menu/dist' --exclude='freeipa-menu/employee-panel/dist' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='*.token' --exclude='*.key' --exclude='*.keytab' \
    -czf freeipa-menu/dist/freeipa-menu.tar.gz freeipa-menu
cd freeipa-menu/dist
sha256sum freeipa-menu.tar.gz > freeipa-menu.tar.gz.sha256
