#!/usr/bin/env bash
# Provision an Ubuntu 24.04 host (e.g. a Claude Code cloud session) with
# the toolchain Ember needs: gcc-15 / g++-15 (C++23), cmake >= 3.28,
# ninja, python3. Idempotent — safe to re-run.
#
# CI uses the gcc:15 Docker image; on a bare 24.04 host we get gcc-15
# from ppa:ubuntu-toolchain-r/test. Goldens are toolchain-stable to
# gcc-15 specifically, so any other compiler will diff-fail tests.
#
#   ./scripts/setup.sh           # install toolchain
#   ./scripts/setup.sh --build   # also configure + build + test

set -euo pipefail

SUDO=""
if [[ $EUID -ne 0 ]]; then
    SUDO="sudo"
fi

export DEBIAN_FRONTEND=noninteractive

echo "==> apt update + base prerequisites"
$SUDO apt-get update -y
$SUDO apt-get install -y --no-install-recommends \
    ca-certificates gnupg software-properties-common

echo "==> add ppa:ubuntu-toolchain-r/test (for gcc-15 on noble)"
$SUDO add-apt-repository -y ppa:ubuntu-toolchain-r/test
$SUDO apt-get update -y

echo "==> install build toolchain"
$SUDO apt-get install -y --no-install-recommends \
    gcc-15 g++-15 \
    cmake ninja-build python3

echo "==> point gcc/g++ at version 15 via update-alternatives"
$SUDO update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-15 150
$SUDO update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-15 150
$SUDO update-alternatives --set gcc /usr/bin/gcc-15
$SUDO update-alternatives --set g++ /usr/bin/g++-15

echo "==> versions"
gcc --version | head -1
g++ --version | head -1
cmake --version | head -1
ninja --version

if [[ "${1:-}" == "--build" ]]; then
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    cd "$REPO_ROOT"

    echo "==> configure"
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release

    echo "==> build"
    cmake --build build -j

    echo "==> test"
    ctest --test-dir build --output-on-failure
fi

echo "==> done"
