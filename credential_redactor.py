#!/usr/bin/env python3
"""
credential_redactor.py — backward-compatible CLI entry point.

Usage:
    python3 credential_redactor.py --help
    python3 credential_redactor.py [directory]           # interactive mode
    python3 credential_redactor.py [directory] --ci      # CI mode: report only, exit 1
    python3 credential_redactor.py [directory] --fix-all # redact all without prompting
    python3 -m credactor --help                          # equivalent
"""

from credactor.cli import main

if __name__ == '__main__':
    main()
