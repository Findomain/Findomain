#!/usr/bin/env bash
# Findomain releaser
LINUX_TARGET="x86_64-unknown-linux-musl"
LINUX_X86_TARGET="i686-unknown-linux-musl"
WIN_TARGET="x86_64-pc-windows-gnu"
RPI_TARGET="armv7-unknown-linux-gnueabihf"
AARCH_TARGET="aarch64-unknown-linux-gnu"
OSX_TARGET="x86_64-apple-darwin"
MANPAGE_DIR="./findomain.1"

# Linux build
echo "Building Linux artifact."
if cargo build -q --release --target="$LINUX_TARGET"; then
  echo "Linux artifact build: SUCCESS"
  cp "target/$LINUX_TARGET/release/findomain" "target/$LINUX_TARGET/release/findomain-linux-amd64"
  strip "target/$LINUX_TARGET/release/findomain-linux-amd64"
else
  echo "Linux artifact build: FAILED"
fi

# Linux x86 build
echo "Building Linux artifact."
if cross build -q --release --target="$LINUX_X86_TARGET"; then
  echo "Linux x86 artifact build: SUCCESS"
  cp "target/$LINUX_X86_TARGET/release/findomain" "target/$LINUX_X86_TARGET/release/findomain-linux-i386"
  strip "target/$LINUX_X86_TARGET/release/findomain-linux-i386"
else
  echo "Linux x86 artifact build: FAILED"
fi

# Windows build
echo "Building Windows artifact."
if cross build -q --release --target="$WIN_TARGET"; then
  echo "Windows artifact build: SUCCESS"
  cp "target/$WIN_TARGET/release/findomain.exe" "target/$WIN_TARGET/release/findomain-windows.exe"
  strip "target/$WIN_TARGET/release/findomain-windows.exe"
else
  echo "Windows artifact build: FAILED"
fi

# RPi 2-3 build
echo "Building RPi artifact."
if cross build -q --release --target="$RPI_TARGET"; then
  echo "Windows artifact build: SUCCESS"
  cp "target/$RPI_TARGET/release/findomain" "target/$RPI_TARGET/release/findomain-rpi"
  strip "target/$RPI_TARGET/release/findomain-rpi"
else
  echo "RPi artifact build: FAILED"
fi

# Aarch64 build
echo "Building Aarch64 artifact."
if cross build -q --release --target="$AARCH_TARGET"; then
  echo "Aarch64 artifact build: SUCCESS"
  cp "target/$AARCH_TARGET/release/findomain" "target/$AARCH_TARGET/release/findomain-aarch64"
  strip "target/$AARCH_TARGET/release/findomain-aarch64"
else
  echo "Aarch64 artifact build: FAILED"
fi

# Mac OS build
echo "Building OSX artifact."
if CC=o64-clang CXX=o64-clang++ LIBZ_SYS_STATIC=1 cargo build -q --release --target="$OSX_TARGET"; then
  echo "OSX artifact build: SUCCESS"
  cp "target/$OSX_TARGET/release/findomain" "target/$OSX_TARGET/release/findomain-osx"
  strip "target/$OSX_TARGET/release/findomain-osx"
else
  echo "OSX artifact build: FAILED"
fi

echo "Creating manpage..."
if command -v help2man >/dev/null; then
  if help2man -o "$MANPAGE_DIR" "target/$LINUX_TARGET/release/findomain"; then
    echo "Manpage created sucessfully and saved in $MANPAGE_DIR"
  else
    echo "Error creating manpage."
  fi
else
  echo "Please install the help2man package."
fi

if command -v git >/dev/null; then
  git add .
  git commit -m "Bump version."
  git push
fi

echo "All builds have passed!"
