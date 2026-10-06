#!/bin/sh
set -eu
# Mounted volumes may start root-owned; drop privileges before serving traffic.
chown node:node /data
chmod 700 /data
umask 077
exec gosu node "$@"
