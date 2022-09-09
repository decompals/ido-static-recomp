#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
from pathlib import Path
import platform
import threading
import shutil

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


def call(args, output_file=None):
    print(args)
    p = subprocess.Popen(args, shell=True, universal_newlines=True, stdout=output_file)
    p.wait()
    if output_file:
        output_file.flush()

def process_prog(prog, ido_path, ido_flag, build_dir, out_dir, args, recomp_path):
    print("Recompiling " + ido_path + prog + "...")

    c_file_path = os.path.join(build_dir, prog.split("/")[-1] + "_c.c")
    out_file_path = os.path.join(out_dir, prog)
    os.makedirs(Path(out_file_path).parent, exist_ok=True)
    if platform.system().startswith("CYGWIN_NT"):
        out_file_path += ".exe"

    if not args.onlylibc:
        with open(c_file_path, "w") as cFile:
            call(recomp_path + " " + os.path.join(ido_path, prog), cFile)

    flags = " -fno-strict-aliasing -lm"

    if platform.system() == "Darwin":
        flags += " -fno-pie"
    else:
        flags += " -g -no-pie"

    if args.O2:
        flags += " -O2"

    flags += " -Wno-deprecated-declarations"

    call("gcc libc_impl.c " + c_file_path + " -o " + out_file_path + flags + ido_flag)

    return

def main(args):
    ido_path = args.ido_path
    if ido_path[len(ido_path)-1] == "/":
        ido_path = ido_path[:len(ido_path)-1]

    ido_dir = ido_path.split(os.path.sep)[-1]
    if "7.1" in ido_dir:
        print("Detected IDO version 7.1")
        ido_flag = " -DIDO71"
        ugen_flag = ""
        build_dir = "build7.1"
        bins = BINS["7.1"]
    elif "5.3" in ido_dir:
        print("Detected IDO version 5.3")
        ido_flag = " -DIDO53"
        ugen_flag = " -Dugen53"
        build_dir = "build5.3"
        bins = BINS["5.3"]
    else:
        sys.exit("Unsupported ido dir: " + ido_dir)

    if args.multhreading and args.O2:
        print("WARNING: -O2 and -multhreading used together")

    if not os.path.exists(build_dir):
        os.mkdir(build_dir)
    shutil.copy("header.h", build_dir)
    shutil.copy("libc_impl.h", build_dir)
    shutil.copy("helpers.h", build_dir)

    out_dir = os.path.join(build_dir, "out")
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)

    std_flag = ""
    if platform.system() == "Darwin":
        std_flag = " -std=c++11"

    recomp_path = os.path.join(build_dir, "recomp")
    if platform.system().startswith("CYGWIN_NT"):
        recomp_path += ".exe"
    if not args.norecomp:
        call("g++ recomp.cpp -o " + recomp_path + " -g -lcapstone" + std_flag + ugen_flag)

    threads = []
    for prog in bins:
        if args.multhreading:
            t = threading.Thread(target=process_prog, args=(prog, ido_path, ido_flag, build_dir, out_dir, args, recomp_path))
            threads.append(t)
            t.start()
        else:
            process_prog(prog, ido_path, ido_flag, build_dir, out_dir, args, recomp_path)

    if args.multhreading:
        for t in threads:
            t.join()

    shutil.copyfile(os.path.join(ido_path, "usr/lib/err.english.cc"), os.path.join(out_dir, "usr/lib/err.english.cc"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static ido recompilation build utility")
    parser.add_argument("ido_path", help="Path to ido")
    parser.add_argument("-O2", help="Build binaries with -O2", action='store_true')
    parser.add_argument("-onlylibc", help="Builds libc_impl.c only", action='store_true')
    parser.add_argument("-multhreading", help="Enables multi threading (deprecated with O2)", action='store_true')
    parser.add_argument("-norecomp", help="Do not build the recomp binary", action='store_true')
    rgs = parser.parse_args()
    main(rgs)
