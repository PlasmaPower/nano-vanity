#!/usr/bin/env python

# Gets the actual file and line number from an OpenCL error line number

import sys

files = [
    "blake2b.cl",
    "curve25519-constants.cl",
    "curve25519-constants2.cl",
    "curve25519.cl",
    "entry.cl"
]

num = int(sys.argv[1])

for f_name in files:
    f = open("src/opencl/" + f_name, "r")
    lines = len(f.readlines())
    lines += 1
    if num > lines:
        num -= lines
    else:
        print(f_name + ":" + str(num))
