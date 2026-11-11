#!/bin/zsh
# Regenerates both app icon sets from Tools/IconRenderer.swift. Run from the repo root.
set -euo pipefail
tmp=$(mktemp -d)
swiftc -O -o "$tmp/icon" Tools/IconRenderer.swift
"$tmp/icon" "$tmp"

pad=iPad/Assets.xcassets/AppIcon.appiconset
mac=Mac/Assets.xcassets/AppIcon.appiconset
mkdir -p "$pad" "$mac"
cp "$tmp/ipad-1024.png" "$pad/icon-1024.png"
for s in 16 32 128 256 512; do
  sips -z $s $s "$tmp/mac-1024.png" --out "$mac/icon-$s.png" >/dev/null
  sips -z $((s*2)) $((s*2)) "$tmp/mac-1024.png" --out "$mac/icon-$s@2x.png" >/dev/null
done
rm -rf "$tmp"
echo "Icons written to $pad and $mac"
