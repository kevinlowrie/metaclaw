#!/usr/bin/env python3
"""Emit reviewable NoCloud text files only; never builds an ISO or starts a VM."""
import base64
import os
from pathlib import Path
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: build-nocloud-qualification-source.py /absolute/new-directory')
    output = Path(sys.argv[1])
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise SystemExit('output must be a new absolute path')
    bootstrap = Path(__file__).with_name('nocloud-qualification-bootstrap.py').read_bytes()
    encoded = base64.b64encode(bootstrap).decode('ascii')
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)
    (output / 'meta-data').write_text('instance-id: metaclaw-no-start-qualification-v1\nlocal-hostname: metaclaw-qualification\n')
    (output / 'network-config').write_text('version: 2\nethernets: {}\n')
    # Existing cloud-init runs the bounded child. A missing serial result or
    # timeout is UNKNOWN to the external host. Poweroff is guest-gated.
    command = 'if [ "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)" = QEMU ] && [ "$(ls -1 /sys/class/net 2>/dev/null)" = lo ]; then /usr/bin/timeout --signal=TERM --kill-after=10s 180s /usr/bin/python3 /run/metaclaw-qualification-bootstrap.py || true; /usr/sbin/poweroff -f; fi'
    user = '#cloud-config\nusers: []\npackage_update: false\npackage_upgrade: false\nnetwork: {config: disabled}\nwrite_files:\n  - path: /run/metaclaw-qualification-bootstrap.py\n    owner: root:root\n    permissions: "0700"\n    encoding: b64\n    content: ' + encoded + '\nruncmd:\n  - [ /bin/sh, -c, ' + "'" + command.replace("'", "''") + "'" + ' ]\n'
    (output / 'user-data').write_text(user)
    for name in ('meta-data', 'network-config', 'user-data'):
        os.chmod(output / name, 0o600)
    print(str(output))


if __name__ == '__main__':
    main()
