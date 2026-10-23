#!/bin/sh
# Rebuild the orphan branch `device-m2381` (root = this device repository) for
# the CI workflow. The macOS CI checks out the device repository as
# owner/name + ref; pushing this branch to origin avoids creating a second
# repository: dispatch with device_repository=<origin owner/name> and
# device_ref=device-m2381. Run after every workspace commit, then push:
#
#   git push origin device-m2381
#
# The branch carries ONLY the device repository files (board.toml, configs/,
# scripts/, package/, unixnu.lock) — no Apple material, nothing gitignored.
set -e
ROOT="$(git rev-parse --show-toplevel)"
WORK="$ROOT/out/m2381/device-branch"
DEV="$ROOT/devices/m2381/unixnu-m2381"

rm -rf "$WORK"
git -C "$ROOT" worktree prune
git -C "$ROOT" worktree add --detach "$WORK" >/dev/null 2>&1
(
  cd "$WORK"
  git checkout --orphan device-m2381 >/dev/null 2>&1
  git rm -rf --quiet . 2>/dev/null || true
  rm -rf board.toml configs scripts package unixnu.lock
  cp -r "$DEV/board.toml" "$DEV/configs" "$DEV/scripts" "$DEV/package" "$DEV/unixnu.lock" .
  git add -A
  git commit -q -m "unixnu-m2381 device repository (mirror of devices/m2381/unixnu-m2381 @ $(git -C "$ROOT" rev-parse --short m2381))"
)
git -C "$ROOT" worktree remove "$WORK" >/dev/null 2>&1 || true
echo "device-m2381 ready: $(git -C "$ROOT" rev-parse --short device-m2381) (from m2381 $(git -C "$ROOT" rev-parse --short m2381))"
