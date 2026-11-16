#!/usr/bin/env bash
#
# mayhem/build.sh — builds cpworker (the C packet-capture engine) three ways, offline:
#   1. every cpworker source except main.c, with $SANITIZER_FLAGS + $DEBUG_FLAGS, linked into one fuzz
#      binary and one standalone reproducer per harness in mayhem/fuzz_*.c;
#   2. upstream's Unity unit tests with the project's NORMAL flags, run by mayhem/test.sh.
# libpcap comes from apt, libzmq.a from the pinned static build the Dockerfile puts in /opt/toolchains/deps.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${ZMQ_VER:=4.3.5}"
export SANITIZER_FLAGS DEBUG_FLAGS CC LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
ZMQ_ROOT=/opt/toolchains/deps/libzmq-${ZMQ_VER}
LIBROOT="$SRC/mayhem/build-libroot"
ASAN_DIR="$SRC/mayhem/build-asan"
TEST_DIR="$SRC/mayhem/build-tests"
# Packet parsers cast `pkt_data + 14` (Ethernet header) to struct ipv4_hdr/ipv6_hdr, which UBSan's alignment
# check rejects on every IPv4 frame; the cast is benign on the supported CPUs, so only that check is relaxed.
SAN="$SANITIZER_FLAGS -fno-sanitize=alignment"
TARGETS="fuzz_config fuzz_packet_split fuzz_bpf_nic fuzz_req_pattern"

# cpworker's CMake wants LIBRARY_ROOT/{lib/libpcap.so, lib/libzmq.a, include}.
rm -rf "$LIBROOT" "$ASAN_DIR" "$TEST_DIR"
mkdir -p "$LIBROOT/lib" "$LIBROOT/include"
PCAP_SO="$(find /usr/lib -name libpcap.so -print -quit)"
[ -n "$PCAP_SO" ] || { echo "libpcap.so not found" >&2; exit 1; }
ln -s "$PCAP_SO" "$LIBROOT/lib/libpcap.so"
ln -s "$ZMQ_ROOT/lib/libzmq.a" "$LIBROOT/lib/libzmq.a"
ln -s "$ZMQ_ROOT/include/zmq.h" "$LIBROOT/include/zmq.h"

# 1) Sanitized project objects (main.c excluded: the harnesses bring their own entry point).
cmake -S cpworker -B "$ASAN_DIR" -DLIBRARY_ROOT="$LIBROOT" -DENABLE_UNIT_TESTS=OFF \
      -DCMAKE_C_COMPILER="$CC" \
      -DCMAKE_C_FLAGS="$SAN -fsanitize=fuzzer-no-link $DEBUG_FLAGS" >/dev/null
cmake --build "$ASAN_DIR" -j"$MAYHEM_JOBS" --target cpworker
mapfile -t OBJS < <(find "$ASAN_DIR/CMakeFiles/cpworker.dir" -name '*.o' ! -name 'main.c.o' | sort)
[ "${#OBJS[@]}" -gt 20 ] || { echo "unexpected object list: ${#OBJS[@]}" >&2; exit 1; }

# 2) Harnesses: fuzzer binary + standalone reproducer, both with LSan turned off at build time.
"$CC" $SAN $DEBUG_FLAGS -c mayhem/lsan_off.c -o "$ASAN_DIR/lsan_off.o"
CFLAGS_H="$SAN -fsanitize=fuzzer-no-link $DEBUG_FLAGS -D_GNU_SOURCE -Icpworker/src -I$ASAN_DIR -I$LIBROOT/include"
LIBS_H=("$LIBROOT/lib/libpcap.so" "$LIBROOT/lib/libzmq.a" -lpthread -lm -lstdc++)
for t in $TARGETS; do
  "$CC" $CFLAGS_H $LIB_FUZZING_ENGINE "mayhem/$t.c" "${OBJS[@]}" "$ASAN_DIR/lsan_off.o" \
        "${LIBS_H[@]}" -o "/mayhem/$t"
  "$CC" $CFLAGS_H "$STANDALONE_FUZZ_MAIN" "mayhem/$t.c" "${OBJS[@]}" "$ASAN_DIR/lsan_off.o" \
        "${LIBS_H[@]}" -o "/mayhem/$t-standalone"
done

# 3) Unit tests with the project's normal flags.
cmake -S cpworker -B "$TEST_DIR" -DLIBRARY_ROOT="$LIBROOT" -DENABLE_UNIT_TESTS=ON \
      -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" >/dev/null
cmake --build "$TEST_DIR" -j"$MAYHEM_JOBS"
