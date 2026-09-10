#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University
# Check out the sibling modules this module's go.mod `replace`s, next to
# it, reproducing the workspace layout developers use locally:
#
#   <workspace>/OutRelay        <- github.com/boanlab/OutRelay
#   <workspace>/outrelay-relay
#   <workspace>/outrelay-agent
#
# Without this, `go build` in CI fails with "replacement directory
# ../OutRelay does not exist": the replace points at a sibling checkout
# that a single-repo actions/checkout never creates.
#
# Siblings come from the same owner as the code under test — a pull
# request from a fork is built against that fork's siblings, since the
# three repos move together — falling back to the upstream org, and
# from the current branch to main when the sibling has no such branch.
#
#   usage: .github/scripts/checkout-siblings.sh OutRelay [outrelay-relay ...]
set -euo pipefail

owner=${SIBLING_OWNER:-boanlab}
ref=${SIBLING_REF:-main}
cd "$(dirname "$0")/../.."

for m in "$@"; do
  if [ -d "../$m" ]; then
    echo "sibling $m already present"
    continue
  fi
  for o in "$owner" boanlab; do
    url="https://github.com/$o/$m"
    git ls-remote --exit-code -h "$url" >/dev/null 2>&1 || continue
    r=$ref
    git ls-remote --exit-code -h "$url" "$r" >/dev/null 2>&1 || r=main
    git clone --quiet --depth 1 --branch "$r" "$url" "../$m"
    echo "sibling $m <- $o @ $r"
    break
  done
  [ -d "../$m" ] || { echo "cannot find sibling module $m" >&2; exit 1; }
done
