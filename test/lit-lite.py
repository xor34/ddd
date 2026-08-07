#!/usr/bin/env python3
"""A small stand-in for llvm-lit, so the suite runs without installing lit.

It implements the subset the tests here use: RUN lines with `|` pipelines,
`%s`/`%t`/`%lift`/`%sleigh-poc`/`%specs` substitutions, backslash
continuations, and a non-zero exit when any RUN line fails. FileCheck itself
is the real one from LLVM.

If you would rather use the real thing, `pip install lit` and run
`lit -v test/ -Dsleigh_poc=<path>`; test/lit.cfg.py wires up the same
substitutions.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

SUFFIXES = (".s", ".test")
RUN_LINE = re.compile(r"\bRUN:\s*(.*)$")


def collect(root, pattern):
    tests = []
    for directory, _, files in os.walk(root):
        if "tools" in os.path.relpath(directory, root).split(os.sep):
            continue
        for name in sorted(files):
            if not name.endswith(SUFFIXES):
                continue
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, root)
            if pattern and not re.search(pattern, relative):
                continue
            tests.append((relative, path))
    return sorted(tests)


def run_lines(path):
    """Every RUN line in the file, with trailing-backslash continuations joined."""
    commands = []
    pending = None

    with open(path, encoding="utf-8") as handle:
        for line in handle:
            match = RUN_LINE.search(line)
            if match is None:
                continue

            text = match.group(1).rstrip()
            if pending is not None:
                text = pending + " " + text.lstrip()
                pending = None
            if text.endswith("\\"):
                pending = text[:-1].rstrip()
                continue
            commands.append(text)

    if pending is not None:
        commands.append(pending)
    return commands


def substitute(command, substitutions):
    # Longest key first: %sleigh-poc and %specs both start with %s.
    for key in sorted(substitutions, key=len, reverse=True):
        command = command.replace(key, substitutions[key])
    return command


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)

    parser = argparse.ArgumentParser()
    parser.add_argument("--sleigh-poc", default=os.environ.get("SLEIGH_POC"),
                        help="path to the sleigh_poc binary under test")
    parser.add_argument("--specs", default=os.environ.get("DDD_SPECS", os.path.join(root, "specs")))
    parser.add_argument("--filter", default=None, help="only run tests matching this regex")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show the output of passing tests too")
    parser.add_argument("tests", nargs="?", default=here)
    args = parser.parse_args()

    if not args.sleigh_poc or not os.path.exists(args.sleigh_poc):
        print(f"lit-lite: sleigh_poc not found ({args.sleigh_poc!r}); "
              f"pass --sleigh-poc=<path>", file=sys.stderr)
        return 2
    if shutil.which("FileCheck") is None:
        print("lit-lite: FileCheck not found on PATH", file=sys.stderr)
        return 2

    tools = os.path.join(here, "tools")
    environment = dict(os.environ)
    environment["PATH"] = os.pathsep.join([tools, environment.get("PATH", "")])

    lift = f'"{sys.executable}" "{os.path.join(tools, "lift.py")}"'
    lift += f' --sleigh-poc="{args.sleigh_poc}" --specs="{args.specs}"'

    tests = collect(os.path.abspath(args.tests), args.filter)
    if not tests:
        print("lit-lite: no tests found", file=sys.stderr)
        return 2

    failures = []
    for name, path in tests:
        commands = run_lines(path)
        if not commands:
            print(f"UNSUPPORTED: {name} (no RUN lines)")
            continue

        with tempfile.TemporaryDirectory() as scratch:
            substitutions = {
                "%sleigh-poc": f'"{args.sleigh_poc}"',
                "%specs": f'"{args.specs}"',
                "%lift": lift,
                "%t": os.path.join(scratch, "t"),
                "%S": f'"{os.path.dirname(path)}"',
                "%s": f'"{path}"',
            }

            for command in commands:
                expanded = substitute(command, substitutions)
                result = subprocess.run(expanded, shell=True, cwd=root, env=environment,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                if result.returncode == 0:
                    continue

                failures.append(name)
                print(f"FAIL: {name}")
                print(f"  $ {expanded}")
                for line in result.stdout.decode(errors="replace").splitlines():
                    print(f"  | {line}")
                break
            else:
                print(f"PASS: {name}")
                if args.verbose:
                    for command in commands:
                        print(f"  $ {substitute(command, substitutions)}")

    print(f"\n{len(tests) - len(failures)} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
