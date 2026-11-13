"""xssmap - context-aware cross-site scripting scanner with a crawler."""

__version__ = "2.9.1"

__all__ = ["__version__", "main"]


def main(argv=None):
    from .cli import main as _main
    return _main(argv)
