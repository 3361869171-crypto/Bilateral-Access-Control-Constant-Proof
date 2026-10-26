#!/bin/bash
# Build script for MIRACL library on x86_64 Linux
# Supports bilinear pairings
#
# Only 2 deviations from upstream, both taken from the official build scripts (⇒ fully auditable):
#   1) mirdef.h          <- cp include/mirdef.hpp          (lib/linux64_cpp:3  verbatim)
#   2) mrmuldv.c         <- cp source/mrmuldv.g64          (lib/linux64_cpp:54 verbatim)
# Source files such as bn_pair.cpp are byte-identical to upstream (no sed patches remain).

set -e

MIRACL_DIR="MIRACL-master"
SOURCE_DIR="$MIRACL_DIR/source"
INCLUDE_DIR="$MIRACL_DIR/include"
BUILD_DIR="miracl_build"
OUTPUT_DIR="miracl_output"

if [ ! -d "$SOURCE_DIR" ] || [ ! -d "$INCLUDE_DIR" ]; then
    echo "ERROR: MIRACL source not found at $MIRACL_DIR/." >&2
    echo "MIRACL is not bundled with this repository (AGPLv3)." >&2
    echo "Download MIRACL from https://github.com/miracl/MIRACL and unpack it as ./MIRACL-master/." >&2
    exit 1
fi

echo "=== Building MIRACL Library for x86_64 Linux with Bilinear Pairing support ==="

# Create build and output directories
rm -rf "$BUILD_DIR" "$OUTPUT_DIR"
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR/include" "$OUTPUT_DIR/lib"

# Step 1: Copy all header files from include to build directory first
echo "Copying header files to build directory..."
cp "$INCLUDE_DIR"/*.h "$BUILD_DIR/"

# Step 2: Use the official 64-bit C++ configuration for mirdef.h
#   Source (official wording): MIRACL-master/lib/linux64_cpp line 3 — "cp mirdef.hpp mirdef.h"
#   mirdef.hpp is the official 64-bit C++ configuration (MIRACL 64 / mr_utype long / MR_CPP),
#   while upstream include/mirdef.h (byte-identical to the 32-bit mirdef.h32) is the other value of the same "configuration slot".
#   Note: this previously used a heredoc with equivalent content; it now copies the official file directly ⇒ 100% auditable.
echo "Using official mirdef.hpp as mirdef.h (same as lib/linux64_cpp:3)..."
cp "$INCLUDE_DIR/mirdef.hpp" "$BUILD_DIR/mirdef.h"

# Copy only the pairing headers required by the MR_PAIRING_BN closure
#   Closure: pairing_3.h unconditionally includes only ecn.h (:51); all other branches are inside #ifdef;
#            the MR_PAIRING_BN branch (pairing_3.h:74-84) additionally needs zzn2.h / ecn2.h / zzn12a.h;
#             zzn12a.h -> zzn4.h -> zzn2.h -> zzn.h -> big.h -> miracl.h/mirdef.h
#   Why not copy everything: that would pull in KSS/BLS/MNT headers; zzn12.h and zzn12b.h share the include
#            guard `ZZN12_H` and both define class ZZn12 ⇒ including both in one TU silently drops one.
#            This project defines only MR_PAIRING_BN, so those branches are never compiled and their headers are unnecessary.
PAIRING_SRC="$SOURCE_DIR/curve/pairing"
for h in pairing_3.h ecn2.h zzn2.h zzn4.h zzn12a.h; do
    cp "$PAIRING_SRC/$h" "$BUILD_DIR/"
done

# Step 3: Setup mrmuldv.c for x86_64 Linux
echo "Setting up mrmuldv.c for x86_64..."
cp "$SOURCE_DIR/mrmuldv.g64" "$BUILD_DIR/mrmuldv.c"

# Step 4: Copy all source files to build directory
echo "Copying source files..."
# Core C source files
for f in mrcore.c mrarth0.c mrarth1.c mrarth2.c mralloc.c mrsmall.c \
         mrio1.c mrio2.c mrgcd.c mrjack.c mrxgcd.c mrarth3.c mrbits.c \
         mrrand.c mrprime.c mrcrt.c mrscrt.c mrmonty.c mrpower.c mrsroot.c \
         mrcurve.c mrfast.c mrshs.c mrshs256.c mrshs512.c mrsha3.c \
         mrfpe.c mraes.c mrgcm.c mrlucas.c mrzzn2.c mrzzn2b.c mrzzn3.c \
         mrzzn4.c mrecn2.c mrstrong.c mrbrick.c mrebrick.c mrec2m.c \
         mrgf2m.c mrflash.c mrfrnd.c mrdouble.c mrround.c mrbuild.c \
         mrflsh1.c mrpi.c mrflsh2.c mrflsh3.c mrflsh4.c; do
    cp "$SOURCE_DIR/$f" "$BUILD_DIR/"
done

# C++ source files
for f in big.cpp zzn.cpp ecn.cpp ec2.cpp flash.cpp crt.cpp; do
    cp "$SOURCE_DIR/$f" "$BUILD_DIR/"
done

# (Removed) ecnzzn.cpp — a bridge for type-1 (SSP) pairings, unused by MR_PAIRING_BN

# Copy pairing-related source files (only the 5 modules required by MR_PAIRING_BN)
#   Source: the BN-curve compile command in MIRACL-master/amd64.txt:180-187 and source/curve/pairing/ake.cpp:13 —
#           bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp
#   (the remaining zzn3/zzn6/zzn6a/zzn8/zzn12/zzn12b/zzn18/zzn24/zzn36 and ecn3/ecn4/ecn6/ecn8
#    belong to the MNT (k=6)/KSS (k=18)/BLS (k=24) families and are unused here ⇒ not compiled, matching the official list)
echo "Copying BN pairing sources (5 modules, per amd64.txt:180-187)..."
for f in bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp; do
    cp "$PAIRING_SRC/$f" "$BUILD_DIR/"
done

# Step 5: (Removed) This step used to sed bn_pair.cpp's mod_bits from 256 to 2048
#   to accommodate the 507-bit intermediate products from "bare multiplication (a*b)%p" (see tests/miracl_semantics_test).
#   The project now uses the official API (Big's modmult/moddiv/inverse),
#   based on: MIRACL-master/source/curve/pairing/pairings.txt:101-103 —
#     "For arithmetic in Zr ... use the Big functions modmult(x,y,r) (returns x*y mod r),
#      moddiv(x,y,r) and inverse(x,r) to avoid overflow."
#   Mechanism: mad() stores the product in the double-length internal workspace mr_mip->w0
#   (see mrarth2.c:1556-1583 and docs/.../low-level-routines.md:495-496
#    "The initial product is stored in a double-length internal variable to avoid
#     the possibility of overflow at this stage."),
#   Therefore intermediate products no longer enter a normal Big ⇒ no budget increase is needed ⇒ bn_pair.cpp is byte-identical to upstream.
echo "mod_bits patch removed: bn_pair.cpp stays byte-identical to upstream"

cd "$BUILD_DIR"

echo "=== Compiling C source files ==="
for f in *.c; do
    echo "  Compiling $f..."
    g++ -c -m64 -O2 -I. "$f"
done

echo "=== Compiling C++ source files ==="
for f in *.cpp; do
    echo "  Compiling $f..."
    g++ -c -m64 -O2 -I. "$f"
done

echo "=== Creating static library libmiracl.a ==="
ar rc ../"$OUTPUT_DIR/lib/libmiracl.a" *.o

echo "=== Cleaning up object files ==="
rm -f *.o

# Copy all headers to output include directory for users
echo "=== Copying headers to output ==="
cp *.h ../"$OUTPUT_DIR/include/" 2>/dev/null || true

cd ..

echo ""
echo "=== Build Complete! ==="
echo "Library: $OUTPUT_DIR/lib/libmiracl.a"
echo "Headers: $OUTPUT_DIR/include/"
echo ""
echo "To compile your program:"
echo "  g++ -m64 -O2 -I$OUTPUT_DIR/include your_program.cpp -L$OUTPUT_DIR/lib -lmiracl -o your_program"
echo ""
echo "Example test:"
echo "  g++ -m64 -O2 -I$OUTPUT_DIR/include test_bilinear.cpp -L$OUTPUT_DIR/lib -lmiracl -o test_bilinear"
echo "  ./test_bilinear"
