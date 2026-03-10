#!/usr/bin/env python3
"""
pe_protect.py — AiDA post-build PE utility (no-op).

Watermark stamping has been removed. This script is retained as a no-op
so that existing build pipelines that invoke it do not break.
"""

import sys


def main():
    sys.exit(0)


if __name__ == '__main__':
    main()