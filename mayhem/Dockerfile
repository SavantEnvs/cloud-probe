# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org C/C++ base image.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t mytag .
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# libpcap (cpworker captures and reads pcap files through it) and the autotools toolchain libzmq's
# release tarball needs. libpcap-dev is a regular apt dependency, pinned via SOURCE_DATE_EPOCH.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends libpcap-dev make \
 && rm -rf /var/lib/apt/lists/*

# libzmq as a minimal static library. apt's libzmq.a is a "fat" build (OpenPGM + GSSAPI) whose pgm_*/gss_*
# symbols cpworker's static link cannot resolve, and cpworker's CI builds its own for the same reason.
# Built once from the pinned release tarball; uninstrumented, like apt libraries (SPEC §6.2 item 19).
ARG ZMQ_VER=4.3.5
ARG ZMQ_SHA256=6653ef5910f17954861fe72332e68b03ca6e4d9c7160eb3a8de5a5a913bfab43
RUN d=/opt/toolchains/deps/libzmq-${ZMQ_VER} && mkdir -p "$d/src" /tmp/dep-build \
 && curl -fsSL -o /tmp/dep.tgz \
      https://github.com/zeromq/libzmq/releases/download/v${ZMQ_VER}/zeromq-${ZMQ_VER}.tar.gz \
 && echo "${ZMQ_SHA256}  /tmp/dep.tgz" | sha256sum -c - \
 && tar -xzf /tmp/dep.tgz --strip-components=1 -C "$d/src" && cd /tmp/dep-build \
 && "$d/src/configure" --prefix="$d" --enable-static --disable-shared \
      --without-pgm --without-libgssapi_krb5 --disable-libunwind --disable-perf --disable-curve \
      --disable-Werror --without-docs CFLAGS="-O2 -g -gdwarf-3" CXXFLAGS="-O2 -g -gdwarf-3" \
 && make -j"$(nproc)" install-libLTLIBRARIES install-includeHEADERS \
 && cd / && rm -rf /tmp/dep-build /tmp/dep.tgz && chmod -R a+rX "$d"
USER mayhem

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
