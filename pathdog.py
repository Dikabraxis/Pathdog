#!/usr/bin/env python3
"""Compatibility wrapper for running Pathdog directly from a checkout."""

from pathdog.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
