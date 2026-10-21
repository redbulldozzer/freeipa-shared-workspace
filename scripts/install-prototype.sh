#!/bin/bash
set -euo pipefail
test "$(id -u)" = 0 || { echo 'Run as root.' >&2; exit 1; }
project_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
installed_dir=/usr/local/share/shared-workspace-pilot
config_file=/etc/shared-workspace.conf
if [ ! -f "$config_file" ]; then
    install -m 0644 "$project_dir/config/shared-workspace.conf" "$config_file"
fi
workspace_user=$(sed -n 's/^target=//p' "$config_file")
test -n "$workspace_user" || { echo 'Missing target in /etc/shared-workspace.conf.' >&2; exit 1; }
make -C "$project_dir"
if [ "$project_dir" != "$installed_dir" ]; then
    install -d -m 0755 "$installed_dir"
    rsync -a --delete --exclude build/ --exclude .git/ --exclude __pycache__/ \
        --exclude '*.pyc' --exclude '*.key' --exclude '*.keytab' --exclude .secrets/ \
        "$project_dir/" "$installed_dir/"
fi
chown -R root:root "$installed_dir"
chmod -R go-w "$installed_dir"
find "$installed_dir/scripts" -maxdepth 1 -type f -exec chmod 0755 {} +
if ! getent passwd "$workspace_user" >/dev/null; then
    useradd --create-home --shell /bin/bash --comment 'Shared office workspace' "$workspace_user"
fi
if ! awk -F: -v user="$workspace_user" '$1 == user && $3 >= 1000 { found=1 } END { exit !found }' /etc/passwd; then
    echo 'Target must be a dedicated local account.' >&2; exit 1
fi
passwd -l "$workspace_user" >/dev/null
install -D -m 0755 "$project_dir/build/pam_shared_workspace.so" /usr/local/lib/security/pam_shared_workspace.so.new
mv -f /usr/local/lib/security/pam_shared_workspace.so.new /usr/local/lib/security/pam_shared_workspace.so
install -D -m 0755 "$project_dir/build/shared-workspace-greeter" /usr/local/libexec/shared-workspace-greeter
install -D -m 0755 "$project_dir/scripts/shared-workspace-lock-bridge" /usr/local/libexec/shared-workspace-lock-bridge
install -D -m 0755 "$project_dir/scripts/shared-workspace-display-setup" /usr/local/libexec/shared-workspace-display-setup
install -D -m 0644 "$project_dir/config/shared-workspace-greeter.desktop" /usr/share/xgreeters/shared-workspace-greeter.desktop
install -D -m 0644 "$project_dir/config/shared-workspace-lock-bridge.desktop" /etc/xdg/autostart/shared-workspace-lock-bridge.desktop
install -m 0644 "$project_dir/config/shared-workspace-domain.pam" /etc/pam.d/shared-workspace-domain
python3 - <<'PY'
import os, secrets
path = '/etc/shared-workspace.keyring'
if not os.path.exists(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(secrets.token_hex(32))
        f.flush()
        os.fsync(f.fileno())
PY
install -d -m 0755 /var/lib/shared-workspace
cat > /etc/pam.d/shared-workspace-check <<'EOF'
# Standalone probe only. Does not start a graphical/logind session.
auth requisite pam_nologin.so
auth [success=done ignore=ignore default=die] /usr/local/lib/security/pam_shared_workspace.so
@include common-auth
@include common-account
session requisite /usr/local/lib/security/pam_shared_workspace.so
session required pam_permit.so
EOF
chmod 0644 /etc/pam.d/shared-workspace-check
cat > /etc/pam.d/shared-workspace-unlock-check <<'EOF'
auth [success=done ignore=ignore default=die] /usr/local/lib/security/pam_shared_workspace.so
@include common-auth
@include common-account
EOF
chmod 0644 /etc/pam.d/shared-workspace-unlock-check
cc -O2 -Wall -Wextra -Werror -o "$project_dir/build/pam-probe" "$project_dir/tests/pam_probe.c" -lpam
install -m 0755 "$project_dir/build/pam-probe" /usr/local/sbin/shared-workspace-pam-probe
install -m 0755 "$project_dir/scripts/shared-workspacectl.py" /usr/local/sbin/shared-workspacectl
printf '%s\n' 'Prototype installed for standalone testing. LightDM and screen locking are unchanged.'
