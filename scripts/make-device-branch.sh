#!/bin/sh
# Rebuild an orphan branch carrying this device repository for the CI workflow.
# The macOS CI checks out the device repository as owner/name + ref and always
# reads device/board.toml, so a bring-up pass rides its own branch whose
# board.toml IS the bring-up board (the nx729j pattern):
#
#   scripts/make-device-branch.sh                        # device-m2381       (full board.toml)
#   scripts/make-device-branch.sh device-m2381-bringup board.bringup.toml
#
# Then push:  git push origin <branch>
set -e
ROOT="$(git rev-parse --show-toplevel)"
BRANCH="${1:-device-m2381}"
BOARD="${2:-board.toml}"
WORK="$ROOT/out/m2381/device-branch"
DEV="$ROOT/devices/m2381/unixnu-m2381"

[ -f "$DEV/$BOARD" ] || { echo "no such board file: $DEV/$BOARD" >&2; exit 1; }

rm -rf "$WORK"
git -C "$ROOT" worktree prune
git -C "$ROOT" worktree add --detach "$WORK" >/dev/null 2>&1
(
  cd "$WORK"
  git checkout --orphan "$BRANCH" >/dev/null 2>&1
  git rm -rf --quiet . 2>/dev/null || true
  rm -rf board.toml board.bringup.toml configs scripts drivers package kits unixnu.lock feeds.toml dts patches keys records forensic ci .github
  cp -r "$DEV/configs" "$DEV/scripts" "$DEV/drivers" "$DEV/package" "$DEV/kits" "$DEV/unixnu.lock" "$DEV/feeds.toml" "$DEV/dts" "$DEV/patches" . 2>/dev/null || cp -r "$DEV/configs" "$DEV/scripts" "$DEV/package" "$DEV/kits" "$DEV/unixnu.lock" .
  # Porting record + evidence ride with the mirror so the porting-record
  # workflow validates porting.toml on the branch itself (upstream records spec).
  cp "$DEV/porting.toml" "$DEV/README.md" .
  [ -d "$DEV/records" ] && cp -r "$DEV/records" .
  [ -d "$DEV/forensic" ] && cp -r "$DEV/forensic" .
  [ -d "$DEV/ci" ] && mkdir -p .github/workflows && cp "$DEV/ci/"*.yml .github/workflows/
  # The policy anchor key rides with the device repository (private repo): the
  # two-volume bundle requires every run to sign under the same anchor.
  [ -d "$DEV/keys" ] && cp -r "$DEV/keys" .
  cp "$DEV/board.toml" "$DEV/board.bringup.toml" .
  cp "$DEV/$BOARD" board.toml
  git add -A
  git commit -q -m "$BRANCH: device repository mirror (board=$BOARD, from m2381 $(git -C "$ROOT" rev-parse --short m2381))"
)
git -C "$ROOT" worktree remove "$WORK" >/dev/null 2>&1 || true
echo "$BRANCH ready: $(git -C "$ROOT" rev-parse --short "$BRANCH") (board=$BOARD, from m2381 $(git -C "$ROOT" rev-parse --short m2381))"
