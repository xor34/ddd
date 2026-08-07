#!/usr/bin/env python3
"""Helper for transform.test: the vendor's XOR "encryption"."""
import sys

sys.stdout.buffer.write(bytes(b ^ 0x5A for b in sys.stdin.buffer.read()))
