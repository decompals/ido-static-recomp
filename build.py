#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import re
import platform

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

    if not os.path.exists(build_dir):
        os.mkdir(build_dir)

    std_flag = ""
    if platform.system() == "Darwin":
        std_flag = "-std=c++11"

    recomp_path = os.path.join(build_dir, "recomp")
    call("g++ recomp.cpp -o " + recomp_path + " -g -lcapstone " + std_flag)
    
    for prog in BINS:
        print("*******************************************************************")
        print(ido_path + prog)

        out_file_path = os.path.join(build_dir, os.path.basename(prog))
        c_file_path = out_file_path + "_c.c"
        o_file_path = out_file_path + "_c.o"

        with open(c_file_path, "w") as cFile:
            call(recomp_path + " " + ido_path + prog, cFile)

        with open("skeleton.c", "r") as skeleton:
            text = re.sub(
                    r"#include \"([^\r\n]+).c\"",
                    "#include \"" + c_file_path + "\"",
                    skeleton.read()
                )
        with open("skeleton.c", "w") as skeleton:
            skeleton.write(text)

        o2_flag = "" if not args.O2 else " -O2"
        call("gcc skeleton.c -c -o " + o_file_path + " -g -fno-strict-aliasing" + o2_flag)

        pie_flag = " -no-pie"
        if platform.system() == "Darwin":
            pie_flag = " -fno-pie"

        call("gcc libc_impl.c " + o_file_path + " -o " + out_file_path + " -g -fno-strict-aliasing" + pie_flag
             + o2_flag + ido_flag)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static ido recompilation build utility")
    parser.add_argument("ido_path", help="Path to ido")
    parser.add_argument("-O2", help="Build binaries with -O2 (warning: may take forever)", action='store_true')
    rgs = parser.parse_args()
    main(rgs)
