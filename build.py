#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import re
import platform
import threading

BINS = [
    "/usr/lib/as1",
    "/usr/lib/cfe",
    "/usr/lib/ugen",
    "/usr/lib/uopt",
    "/usr/bin/cc",
]


def call(args, output_file=None):
    print(args)
    p = subprocess.Popen(args, shell=True, universal_newlines=True, stdout=output_file)
    p.wait()
    if output_file:
        output_file.flush()

def process_prog(prog, ido_path, ido_flag, build_dir, out_dir, args, recomp_path):
    print("Recompiling " + ido_path + prog + "...")

    c_file_path = os.path.join(build_dir, os.path.basename(prog) + "_c.c")
    o_file_path = os.path.join(build_dir, os.path.basename(prog) + "_c.o")
    out_file_path = os.path.join(out_dir, os.path.basename(prog))
    skeleton_file_path = os.path.join(build_dir, "skeleton_" + os.path.basename(prog) + ".c")

    if not args.onlylibc:
        with open(c_file_path, "w") as cFile:
            call(recomp_path + " " + ido_path + prog, cFile)

        with open("skeleton.c", "r") as skeleton:
            text = re.sub(
                    r"#include \"([^\r\n]+).c\"",
                    "#include \"" + os.path.basename(prog) + "_c.c" + "\"",
                    skeleton.read()
                )
        with open(skeleton_file_path, "w") as skeleton:
            skeleton.write(text)

    o2_flag = "" if not args.O2 else " -O2"
    if not args.onlylibc:
        call("gcc " + skeleton_file_path + " -c -o " + o_file_path + " -g -fno-strict-aliasing" + o2_flag)

    pie_flag = " -no-pie"
    if platform.system() == "Darwin":
        pie_flag = " -fno-pie"

    call("gcc libc_impl.c " + o_file_path + " -o " + out_file_path + " -g -fno-strict-aliasing -lm" + pie_flag
             + o2_flag + ido_flag)

    return

def main(args):
    ido_path = args.ido_path
    if ido_path[len(ido_path)-1] == "/":
        ido_path = ido_path[:len(ido_path)-1]

    ido_dir = ido_path.split(os.path.sep)[-1]
    if "7.1" in ido_dir:
        print("Detected IDO version 7.1")
        ido_flag = " -DIDO71"
        build_dir = "build71"
    elif "5.3" in ido_dir:
        print("Detected IDO version 5.3")
        ido_flag = " -DIDO53"
        build_dir = "build53"
    else:
        sys.exit("Unsupported ido dir: " + ido_dir)

    if args.multhreading and args.O2:
        print("WARNING: -O2 and -multhreading used together")

    if not os.path.exists(build_dir):
        os.mkdir(build_dir)
    
    out_dir = os.path.join(build_dir, "out")
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)

    std_flag = ""
    if platform.system() == "Darwin":
        std_flag = "-std=c++11"

    recomp_path = os.path.join(build_dir, "recomp")
    call("g++ recomp.cpp -o " + recomp_path + " -g -lcapstone " + std_flag)
    
    threads = []
    for prog in BINS:
        if args.multhreading:
            t = threading.Thread(target=process_prog, args=(prog, ido_path, ido_flag, build_dir, out_dir, args, recomp_path))
            threads.append(t)
            t.start()
        else:
            process_prog(prog, ido_path, ido_flag, build_dir, out_dir, args, recomp_path)
    
    if args.multhreading:
        for t in threads:
            t.join()

    with open(os.path.join(out_dir, "cc_wrapper.sh"), "w") as wrapper:
        wrapper.write(
            '#!/bin/bash\n' \
            'export PATH=$(dirname "$0"):$PATH\n' \
            '$(dirname "$0")/cc $@\n'
        )
    os.chmod(os.path.join(out_dir, "cc_wrapper.sh"), 0o777)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static ido recompilation build utility")
    parser.add_argument("ido_path", help="Path to ido")
    parser.add_argument("-O2", help="Build binaries with -O2 (warning: may take forever)", action='store_true')
    parser.add_argument("-onlylibc", help="Builds libc_impl.c only", action='store_true')
    parser.add_argument("-multhreading", help="Enables multi threading (deprecated with O2)", action='store_true')
    rgs = parser.parse_args()
    main(rgs)
