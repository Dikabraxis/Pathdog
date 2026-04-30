"""Entry point for `python -m pathdog`.

The CLI lives in the top-level pathdog.py script alongside the package.
This shim loads it and dispatches to its main().
"""
import importlib.util
import sys
from pathlib import Path

_CLI_PATH = Path(__file__).resolve().parent.parent / "pathdog.py"
if not _CLI_PATH.is_file():
    sys.stderr.write(
        f"pathdog: cannot find CLI script at {_CLI_PATH}.\n"
        f"Run `python pathdog.py` from the repo root, or install the package "
        f"with a console_script entry point.\n"
    )
    sys.exit(2)

_spec = importlib.util.spec_from_file_location("_pathdog_cli", _CLI_PATH)
if _spec is None or _spec.loader is None:
    sys.stderr.write(f"pathdog: failed to load CLI from {_CLI_PATH}.\n")
    sys.exit(2)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
sys.exit(_mod.main())
