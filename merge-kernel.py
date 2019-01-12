#!/usr/bin/env python3

# Merges OpenCL source files into a single file for compilation
# equivalent to what gpu.rs does.
#
# Example usages:
#   ./merge-kernel.py > kernel.cl
#   ./merge-kernel.py | cat -n

import sys

files = [
    "blake2b.cl",
    "curve25519-constants.cl",
    "curve25519-constants2.cl",
    "curve25519.cl",
    "entry.cl"
]

for f_name in files:
    with open("src/opencl/" + f_name, "r") as f:
        for line in f:
            sys.stdout.write(line)
