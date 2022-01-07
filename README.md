# Static Recompilation of IRIX Programs
Convert selected IRIX C toolchain programs into modern Linux or macOS programs

## Supported Programs
* IDO 5.3
  * cc, acpp, as0, as1, cfe, copt, ugen, ujoin, uld, umerge, uopt, usplit
* IDO 7.1
  * cc, as1, cfe, ugen, umerge, uopt

# Dependencies
Note that the `python3` dependency is only necessary if building with the `build.py` script. 
Likewise, the `make` dependency is only needed if building with `make`.

## Linux (Debian / Ubuntu)
```bash
sudo apt-get install build-essential libcapstone3 pkg-config python3
```

## macOS
[Install homebrew](https://brew.sh/) and then:
```bash
brew install make python3 pkg-config capstone
```
When building, use `gmake` instead of `make` in order to use homebrew's `make`

# Build using Make
```bash
make VERSION=5.3
make VERSION=7.1
```
The build artifacts are located in `build/{7.1|5.3}/out`.

# Build using Python3
Using `build.py`
```bash
./build.py -O2 ido/5.3
./build.py -O2 ido/7.1
```
The build artifacts are located in `build/{7.1|5.3}/out`. For more options, run `./build.py --help`.

## Creating Universal ARM/x86_64 macOS Builds
By default, the python and make build script create native binaries on macOS. This was done to minimize the time to build the recompiled suite.
In order to create "fat," universal ARM and x86_64, pass the `-universal` flag to `build.py`, or `TARGET=universal` to `gmake`.

# Manual Building

Example for compiling `as1` in a Linux environment:

```
g++ recomp.cpp -o recomp -g -lcapstone
./recomp ~/ido7.1_compiler/usr/lib/as1 > as1_c.c
gcc libc_impl.c as1_c.c -o as1 -g -fno-strict-aliasing -lm -no-pie -DIDO71
```

Use the same approach for `cc`, `cfe`, `uopt`, `ugen`, `as1` (and `copt` if you need that).

Use `-DIDO53` instead of `-DIDO71` if the program you are trying to recompile was compiled with IDO 5.3 rather than IDO 7.1.

You can add `-O2` to step 3. To compile `ugen` for IDO 5.3, add `--conservative` after `./recomp` in step 2. This mimics UB present in `ugen53`. That program reads uninitialized stack memory and its result depends on that stack memory.
