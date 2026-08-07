#!/usr/bin/env python3
"""Assemble a test's source with llvm-mc, then lift it with sleigh_poc.

Used from RUN lines:

    // RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa | FileCheck %s

Anything this script does not recognise is forwarded to sleigh_poc verbatim,
so a test can pass --passes, --cfg, --max and friends straight through.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile


def fail(message):
    print(f"lift.py: {message}", file=sys.stderr)
    return 1


def tool(name):
    path = shutil.which(name)
    if path is None:
        print(f"lift.py: {name} not found on PATH", file=sys.stderr)
        sys.exit(1)
    return path


def run(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode(errors="replace"))
        print("lift.py: " + " ".join(command) + " failed", file=sys.stderr)
        sys.exit(1)
    return result


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--arch")
    parser.add_argument("--triple")
    parser.add_argument("--mattr")
    parser.add_argument("--sla", required=True,
                        help="spec name (looked up in --specs) or a path to a .sla")
    parser.add_argument("--base", default="0x1000")
    parser.add_argument("--sleigh-poc", default=os.environ.get("SLEIGH_POC"))
    parser.add_argument("--specs", default=os.environ.get("DDD_SPECS", "specs"))
    parser.add_argument("source")
    args, forwarded = parser.parse_known_args()

    if not args.arch and not args.triple:
        return fail("one of --arch or --triple is required")
    if not args.sleigh_poc:
        return fail("--sleigh-poc not set (and SLEIGH_POC is empty)")

    sla = args.sla
    if not sla.endswith(".sla"):
        sla = os.path.join(args.specs, sla + ".sla")
    if not os.path.exists(sla):
        return fail(f"no such spec: {sla}")

    with tempfile.TemporaryDirectory() as scratch:
        obj = os.path.join(scratch, "a.o")
        raw = os.path.join(scratch, "a.bin")

        assemble = [tool("llvm-mc"), "-filetype=obj", args.source, "-o", obj]
        if args.arch:
            assemble.append(f"-arch={args.arch}")
        if args.triple:
            assemble.append(f"-triple={args.triple}")
        if args.mattr:
            assemble.append(f"-mattr={args.mattr}")
        run(assemble)

        run([tool("llvm-objcopy"), "-O", "binary", "--only-section=.text", obj, raw])

        with open(raw, "rb") as handle:
            code = handle.read()
        if not code:
            return fail(f"{args.source} assembled to an empty .text section")

    lift = [args.sleigh_poc, f"--sla={sla}", f"--bytes={code.hex()}",
            f"--base={args.base}"] + forwarded
    return subprocess.run(lift).returncode


if __name__ == "__main__":
    sys.exit(main())
