#!/bin/bash
# Save the real help of the disk-image tools (task 4.3c) into docs/tool_help/ (CLAUDE.md rule 6).
# Run in the container: docker compose exec forensic bash scripts/capture_disk_help.sh
# Sleuth Kit tools print their usage on an unknown option (exit 1); that output IS the help.
set -u
out=/app/docs/tool_help
for t in mmls fls icat; do
  { "$t" -V; "$t" -h; echo; echo "## image types (-i list)"; "$t" -i list; } > "$out/$t.txt" 2>&1
  echo "$t -> $out/$t.txt ($(wc -l < "$out/$t.txt") lines)"
done
for t in ewfinfo ewfverify; do
  { "$t" -V; "$t" -h; } > "$out/$t.txt" 2>&1
  echo "$t -> $out/$t.txt ($(wc -l < "$out/$t.txt") lines)"
done
