#!/usr/bin/env python3
"""Run the provided scripts/check_tools.py (unchanged) with Hasher added: 18 EZ CLI tools.

check_tools.py is provided and tested and must not be edited (CLAUDE.md rule 6); it keeps its
tool list in the module-level EZ_TOOLS, which this wrapper extends before calling its main().
Same options as check_tools.py, e.g. in the container:
    python scripts/check_tools_18.py --vol3 /opt/venv/bin/vol [--install]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_tools  # noqa: E402

EXTRA_EZ_TOOLS = ["Hasher"]

if __name__ == "__main__":
    for tool in EXTRA_EZ_TOOLS:
        if tool not in check_tools.EZ_TOOLS:
            check_tools.EZ_TOOLS.append(tool)
    sys.exit(check_tools.main())
