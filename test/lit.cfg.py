# Config for the real llvm-lit:  lit -v test/ -Dsleigh_poc=<path to binary>
#
# test/lit-lite.py implements the same substitutions without needing lit
# installed; keep the two in sync when adding one.
import os
import sys

import lit.formats

config.name = "ddd"
config.test_format = lit.formats.ShTest(True)
config.suffixes = [".s", ".test"]
config.test_source_root = os.path.dirname(__file__)
config.test_exec_root = os.path.join(config.test_source_root, "Output")
config.excludes = ["tools", "Output"]

root = os.path.dirname(config.test_source_root)
tools = os.path.join(config.test_source_root, "tools")

sleigh_poc = lit_config.params.get("sleigh_poc", os.environ.get("SLEIGH_POC", ""))
specs = lit_config.params.get("specs", os.environ.get("DDD_SPECS", os.path.join(root, "specs")))

if not sleigh_poc or not os.path.exists(sleigh_poc):
    lit_config.fatal("pass -Dsleigh_poc=<path to the sleigh_poc binary>")

config.environment["PATH"] = os.pathsep.join([tools, os.environ.get("PATH", "")])

lift = '"%s" "%s" --sleigh-poc="%s" --specs="%s"' % (
    sys.executable, os.path.join(tools, "lift.py"), sleigh_poc, specs)

# Longest first: %sleigh-poc and %specs both start with %s.
config.substitutions.append(("%sleigh-poc", '"%s"' % sleigh_poc))
config.substitutions.append(("%specs", '"%s"' % specs))
config.substitutions.append(("%lift", lift))
