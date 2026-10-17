#!/bin/bash
# Save the real help of the network tools (task 6.7) into docs/tool_help/ (CLAUDE.md rule 6).
# Run in the container: docker compose exec forensic bash scripts/capture_net_help.sh
set -u
out=/app/docs/tool_help
for t in tshark capinfos editcap mergecap; do
  { "$t" --version | head -3; echo; "$t" -h; } > "$out/$t.txt" 2>&1
  echo "$t -> $out/$t.txt ($(wc -l < "$out/$t.txt") lines)"
done
# Every field name engines/tshark.py can ask for, as the installed tshark lists it. The full
# `tshark -G fields` dump is ~6.8 MB / 236k names: only the used ones are recorded here.
tshark -G fields | cut -f3 | sort -u > /tmp/tshark_fields_all.txt
python -c "from forensic_mcp.engines import tshark; print('\n'.join(tshark.all_fields()))" \
  > /tmp/tshark_fields_used.txt
missing=$(comm -23 <(sort /tmp/tshark_fields_used.txt) /tmp/tshark_fields_all.txt)
{ echo "# Fields used by engines/tshark.py, as listed by \`tshark -G fields\` of the installed"
  echo "# version ($(tshark --version | head -1)). Written by scripts/capture_net_help.sh."
  comm -12 <(sort /tmp/tshark_fields_used.txt) /tmp/tshark_fields_all.txt; } \
  > "$out/tshark_fields_used.txt"
echo "fields -> $out/tshark_fields_used.txt ($(grep -vc '^#' "$out/tshark_fields_used.txt") known)"
[ -n "$missing" ] && { echo "MISSING from this tshark: $missing"; exit 1; }
