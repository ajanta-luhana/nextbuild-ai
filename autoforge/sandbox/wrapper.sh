#!/bin/sh
# Fixed sandbox entry script (never built from model output).
# Runs inside: unshare --mount --net --pid --fork --map-root-user
# Builds a minimal root: read-only system dirs, the run workspace at /work, private /tmp.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
WS="$1"; shift
R=/mnt/.afroot
mkdir -p "$R"
mount -t tmpfs tmpfs "$R"
mkdir -p "$R/work" "$R/tmp" "$R/dev" "$R/etc"
for d in usr lib lib64 bin sbin; do
  if [ -L "/$d" ]; then
    ln -s "$(readlink "/$d")" "$R/$d"
  elif [ -d "/$d" ]; then
    mkdir -p "$R/$d"
    mount --rbind "/$d" "$R/$d"
    mount -o remount,bind,ro "$R/$d" 2>/dev/null || true
  fi
done
mount --bind "$WS" "$R/work"
mount -t tmpfs tmpfs "$R/tmp"
touch "$R/dev/null"
mount --bind /dev/null "$R/dev/null"
echo "sandbox:x:0:0:sandbox:/work:/bin/sh" > "$R/etc/passwd"
exec chroot "$R" /bin/sh -c 'cd /work && exec "$@"' sh "$@"
