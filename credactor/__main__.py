"""Allow running as ``python -m credactor``."""

import sys

from .cli import main

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nInterrupted.', file=sys.stderr)
        sys.exit(130)
