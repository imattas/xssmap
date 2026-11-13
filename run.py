#!/usr/bin/env python3
"""Entry point for xssmap when running from a source checkout.

`python run.py ...`, `xssmap.cmd` and `pip install .` (which installs a console
script pointing at xssmap.cli) all end up in the same place.
"""
import os
import sys

MINIMUM = (3, 9)


def _check_python() -> None:
    """Fail early and clearly on an interpreter the code cannot run on.

    Without this, an old interpreter reaches a syntax-level failure inside an
    import and prints a traceback that says nothing about the actual problem.
    """
    if sys.version_info >= MINIMUM:
        return
    have = ".".join(str(part) for part in sys.version_info[:3])
    need = ".".join(str(part) for part in MINIMUM)
    sys.stderr.write(
        f"[-] xssmap needs Python {need} or newer, but this is Python {have}\n"
        f"    ({sys.executable}).\n")
    sys.stderr.write("    Install a current Python and run: python run.py --help\n")
    raise SystemExit(2)


if __name__ == "__main__":
    _check_python()
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from xssmap.cli import main

    sys.exit(main())
