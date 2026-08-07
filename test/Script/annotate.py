#!/usr/bin/env python3
"""Helper for python-pass.test: a pass written in Python.

Reads the function as JSON on stdin, writes directives on stdout. The
asymmetry is the point -- JSON is what a script wants to receive, and one
directive per line is what it wants to emit.
"""
import json
import sys

fn = json.load(sys.stdin)
print(f"block-comment 0 seen by python on {fn['target']}")

for op in fn["ops"]:
    if op["opcode"] != "INT_MULT":
        continue
    print(f"comment {op['id']} multiply, worth a look")
    if op["out"] is not None:
        print(f"label {op['out']} product")
