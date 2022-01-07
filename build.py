#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import platform
import threading
import shutil
from pathlib import Path

BINS = {
    "5.3": [
        "usr/bin/cc",
        "usr/lib/acpp",
        "usr/lib/as0",
        "usr/lib/as1",
        "usr/lib/cfe",
        "usr/lib/copt",
        "usr/lib/ugen",
        "usr/lib/ujoin",
        "usr/lib/uld",
        "usr/lib/umerge",
        "usr/lib/uopt",
        "usr/lib/usplit",
    ],
    "7.1": [
        "usr/bin/cc",
        "usr/lib/as1",
        "usr/lib/cfe",
        "usr/lib/ugen",
        "usr/lib/umerge",
        "usr/lib/uopt",
    ]
}

MACOS_TARGETS = [
    "arm64-apple-macos11", 
    "x86_64-apple-macos10.14"
]

class Colors:
    NO_COL = "\033[0m"
    RED    = "\033[0;31m"
    GREEN  = "\033[0;32m"
    BLUE   = "\033[0;34m"
    YELLOW = "\033[0;33m"

    def disable(self):
        self.NO_COL = ""
        self.RED    = ""
        self.GREEN  = ""
        self.BLUE   = ""
        self.YELLOW = ""

COLORS = Colors()

def print_step(cmd, input, output, rev=False):
    if rev:
        print(f"{COLORS.GREEN}{cmd}\t{COLORS.BLUE}{output}{COLORS.GREEN} <- {COLORS.YELLOW}{input}{COLORS.NO_COL}")
    else:
        print(f"{COLORS.GREEN}{cmd}\t{COLORS.YELLOW}{input}{COLORS.GREEN} -> {COLORS.BLUE}{output}{COLORS.NO_COL}")

def call(args, output_file=None, verbose=False):
    if verbose:
        print(args)

    p = subprocess.Popen(args, shell=True, universal_newlines=True, stdout=output_file)
    p.wait()
    if output_file:
        output_file.flush()

def process_prog(prog, ido_path, ido_flag, fix_ugen, build_dir, out_dir, args, recomp):
    prog_path = ido_path / prog
    prog_name = prog_path.name
    c_file_path = build_dir / (prog_name + ".c")
    out_file_path = name_executable(out_dir, prog_name)

    conservative_flag = " --conservative " if fix_ugen and prog_name == "ugen" else " "

    emit_translated_c(recomp, conservative_flag, prog_path, c_file_path, args.verbose)

    flags = f"-I. {ido_flag} -Wno-tautological-compare -fno-strict-aliasing -lm"

    if platform.system() == "Darwin":
        flags += " -Wno-deprecated-declarations"
        if "x86" in platform.processor() and not args.universal:
            flags += " -fno-pie"
    else:
        flags += " -g -no-pie"

    if args.O2:
        flags += " -O2"

    if args.universal:
        cross_bins = []
        for target in MACOS_TARGETS:
            cross_dir = build_dir / target
            cross_dir.mkdir(parents=True, exist_ok=True)
            out = name_executable(cross_dir, prog_name)
            cross_bins.append(str(out))

            f = f"{flags} -target {target}"
            if 'x86' in target:
                f += ' -fno-pie'
            
            compile_translated_c(c_file_path, 'libc_impl.c', out, f, args.verbose)

        artifacts = " ".join(cross_bins)
        stitch_artifacts(out_file_path, artifacts, args.verbose)

    else:
        compile_translated_c(c_file_path, 'libc_impl.c', out_file_path, flags, args.verbose)
    
    return

def name_executable(location, name):
    if platform.system().startswith("CYGWIN_NT"):
        return location / (name + ".exe")
    else:
        return location / name

def build_recompiler(in_dir, v):
    opt = "-O2"
    capstone = "`pkg-config --cflags --libs capstone`"
    flags = "-Wno-switch"

    if platform.system() == "Darwin":
        flags += " -std=c++11"
    
    recomp = name_executable(in_dir, "recomp")

    print_step('C++','recomp.cpp',recomp)
    call(f"g++ recomp.cpp -o {recomp} {opt} {flags} {capstone}", verbose=v)

    return recomp

def emit_translated_c(recomp, flags, idoprog, output_path, v):
    print_step('RECOMP', idoprog, output_path)
    with open(output_path, 'w') as cFile:
        call(f"{recomp} {flags} {idoprog}", cFile, verbose=v)

def compile_translated_c(c_file, libc, out, flags, v):
    print_step('CC', c_file, out)
    call(f"gcc {libc} {c_file} -o {out} {flags}", verbose=v)

def stitch_artifacts(out, artifacts, v):
    print_step('LIPO', artifacts, out, rev=True)
    call(f'lipo -create -output {out} {artifacts}', verbose=v)


def main(args):
    build_base = Path("build")

    ido_path = Path(args.ido_path)
    ido_dir = ido_path.parts[-1]
    if "7.1" in ido_dir:
        print("Detected IDO version 7.1")
        ido_flag = "-DIDO71"
        fix_ugen = False
        build_dir = build_base / "7.1"
        bins = BINS["7.1"]
    elif "5.3" in ido_dir:
        print("Detected IDO version 5.3")
        ido_flag = "-DIDO53"
        fix_ugen = True
        build_dir = build_base / "5.3"
        bins = BINS["5.3"]
    else:
        sys.exit("Unsupported ido dir: " + ido_dir)

    if args.multhreading and args.O2:
        print("WARNING: -O2 and -multhreading used together")
    
    if args.universal and platform.system() != "Darwin":
        sys.exit("'-universal' only supported on macOS")

    if args.nocolor:
        COLORS.disable()
    
    out_dir = build_dir / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    recomp = build_recompiler(build_base, args.verbose)
    
    threads = []
    for prog in bins:
        if args.multhreading:
            t = threading.Thread(target=process_prog, args=(prog, ido_path, ido_flag, fix_ugen, build_dir, out_dir, args, recomp))
            threads.append(t)
            t.start()
        else:
            process_prog(prog, ido_path, ido_flag, fix_ugen, build_dir, out_dir, args, recomp)
    
    if args.multhreading:
        for t in threads:
            t.join()

    shutil.copyfile(os.path.join(ido_path, "usr/lib/err.english.cc"), os.path.join(out_dir, "err.english.cc"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static ido recompilation build utility")
    parser.add_argument("ido_path", help="Path to ido")
    parser.add_argument("-O2", help="Build binaries with -O2", action='store_true')
    parser.add_argument("-multhreading", help="Enables multi threading (deprecated with O2)", action='store_true')
    parser.add_argument("-universal", help="Create universal ARM and x86_64 binaries on macOS", action='store_true')
    parser.add_argument("-verbose", help="Print detailed build commands", action='store_true')
    parser.add_argument("-nocolor", help="Disable colored printing", action='store_true')
    rgs = parser.parse_args()
    main(rgs)
