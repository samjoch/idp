#!/bin/sh
# Installer for `idp` — the mock OIDC provider.
#
#   curl -fsSL https://raw.githubusercontent.com/OWNER/idp/main/install.sh | sh
#
# Downloads a prebuilt binary for your platform from GitHub Releases, and
# falls back to building from source with cargo if none is available.
#
# Override the source repo or install dir:
#   curl -fsSL .../install.sh | IDP_REPO=me/idp IDP_INSTALL_DIR=/usr/local/bin sh
set -eu

REPO="${IDP_REPO:-OWNER/idp}"
BIN="idp"
INSTALL_DIR="${IDP_INSTALL_DIR:-$HOME/.local/bin}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$1" >&2; }
err()  { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# --- detect platform -> Rust target triple --------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Darwin)
    case "$arch" in
      arm64|aarch64) target="aarch64-apple-darwin" ;;
      x86_64)        target="x86_64-apple-darwin" ;;
      *)             target="" ;;
    esac ;;
  Linux)
    case "$arch" in
      x86_64)        target="x86_64-unknown-linux-gnu" ;;
      aarch64|arm64) target="aarch64-unknown-linux-gnu" ;;
      *)             target="" ;;
    esac ;;
  *) target="" ;;
esac

# --- try a prebuilt binary from the latest release ------------------------
try_prebuilt() {
  [ -n "$target" ] || return 1
  command -v curl >/dev/null 2>&1 || return 1
  url="https://github.com/$REPO/releases/latest/download/${BIN}-${target}.tar.gz"
  info "Looking for a prebuilt binary ($target)..."
  tmp="$(mktemp -d)"
  if curl -fsSL "$url" -o "$tmp/$BIN.tar.gz" 2>/dev/null; then
    tar -xzf "$tmp/$BIN.tar.gz" -C "$tmp"
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "$tmp/$BIN" "$INSTALL_DIR/$BIN"
    rm -rf "$tmp"
    info "Installed prebuilt binary to $INSTALL_DIR/$BIN"
    BIN_PATH="$INSTALL_DIR/$BIN"
    return 0
  fi
  rm -rf "$tmp"
  warn "No prebuilt binary for $os/$arch in $REPO releases."
  return 1
}

# --- fall back to building from source ------------------------------------
build_from_source() {
  command -v cargo >/dev/null 2>&1 || \
    err "cargo not found. Install Rust from https://rustup.rs and re-run, or build a release for $target."
  info "Building from source: cargo install --git https://github.com/$REPO $BIN"
  cargo install --git "https://github.com/$REPO" "$BIN"
  BIN_PATH="$(command -v "$BIN" 2>/dev/null || echo "${CARGO_HOME:-$HOME/.cargo}/bin/$BIN")"
  info "Installed to $BIN_PATH"
}

try_prebuilt || build_from_source

# --- PATH hint ------------------------------------------------------------
dir="$(dirname "$BIN_PATH")"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) warn "$dir is not on your PATH. Add it:  export PATH=\"$dir:\$PATH\"" ;;
esac

info "Done — run: $BIN --help"
