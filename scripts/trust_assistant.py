#!/usr/bin/env python3
"""Stable CLI entry point for advisory trust-store setup instructions."""
from __future__ import annotations

from core.trust_assistant import main


if __name__ == "__main__":
    raise SystemExit(main())
