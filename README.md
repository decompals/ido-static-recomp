# Static recomp of IRIX programs

Example for compiling `as1`:

```
1. g++ recomp.cpp -o recomp -g -lcapstone
2. ./recomp ~/ido7.1_compiler/usr/lib/as1 > as1_c.c
3. make sure as1_c.c is the file to be included in skeleton.c
4. gcc skeleton.c -c -o as1_c.o -g -fno-strict-aliasing
5. gcc libc_impl.c as1_c.o -o as1 -g -fno-strict-aliasing -lm -no-pie -DIDO71
```

Use the same approach for `cc`, `cfe`, `uopt`, `ugen`, `as1` (and `copt` if you need that).

Use `-DIDO53` instead of `-DIDO71` if the program you are trying to recompile was compiled with IDO 5.3 rather than IDO 7.1.

You can add `-O2` to step 4 and step 5. Using `-O2` in step 4 will however take a few minutes and use up to 11 GB for `uopt`. Don't use `-O2` on `copt` unless you have >= 32 GB RAM and can wait at least half an hour.
