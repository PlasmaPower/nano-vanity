# nano-vanity

Generate a NANO address with a prefix of your choice.
The longer the prefix, the longer it'll take to compute.

## Installation

First, setup Rust. The best way to do this is with [rustup](https://rustup.rs).

To install `nano-vanity` from crates.io:

```
cargo install nano-vanity
```

To install `nano-vanity` from source:

```
cargo install
```

For a list of options, use `nano-vanity --help`.

## Using your GPU

This project supports using your GPU to compute the address.
This utilizes OpenCL, so you'll need OpenCL installed and working.
To enable GPU use, use the `--gpu` (or `-g`) option. To disable
use of your CPU, use `--threads 0` (or `-t 0`).
