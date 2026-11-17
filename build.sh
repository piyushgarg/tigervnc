#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build-viewer}"
CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
TARGET="${TARGET:-vncviewer}"

if command -v nproc >/dev/null 2>&1; then
  JOBS="${JOBS:-$(nproc)}"
else
  JOBS="${JOBS:-1}"
fi

echo "Configuring $TARGET in $BUILD_DIR"

cmake_options=()
# Some FLTK packages enable Cairo but omit its headers from CMake's
# include directories. Add them when Cairo is available locally.
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists cairo; then
  cairo_include_dirs="$(pkg-config --cflags-only-I cairo)"
  cairo_include_dirs="${cairo_include_dirs//-I/}"
  read -r -a cairo_include_dirs <<< "$cairo_include_dirs"
  fltk_include_dirs="$(IFS=';'; echo "${cairo_include_dirs[*]}")"
  cmake_options+=("-DFLTK_INCLUDE_DIR=$fltk_include_dirs")
fi

# The local system FLTK package does not satisfy TigerVNC's version probe.
# We override that check here to match the successful local build.
cmake \
  -S "$ROOT_DIR" \
  -B "$BUILD_DIR" \
  -DBUILD_VIEWER=ON \
  -DOK_FLTK_VERSION=ON \
  -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
  "${cmake_options[@]}"

echo "Building $TARGET with $JOBS job(s)"

cmake \
  --build "$BUILD_DIR" \
  -j"$JOBS" \
  --target "$TARGET"

BIN_PATH="$BUILD_DIR/vncviewer/vncviewer"

if [[ ! -x "$BIN_PATH" ]]; then
  echo "Build finished but $BIN_PATH was not found" >&2
  exit 1
fi

echo "Built binary: $BIN_PATH"
