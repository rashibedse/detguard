"""``python -m detguard`` — the same entry point as the ``detguard`` script.

Three ways to invoke this tool now agree:

    detguard ...                # the installed console script
    python -m detguard ...      # this file
    python -m detguard.cli ...  # the module directly

They agree on ``sys.path`` too: ``main()`` puts the invocation directory on it
(see ``cli._ensure_cwd_importable``), so a ``--graph``/``--agent`` import string
naming the user's own project resolves the same way under all three.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
