#!/bin/sh
# 2cha one-liner installer: fetch the latest release binary, install it, and
# launch the turn-key server setup.
#
#   sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/keepinfov/2cha/master/scripts/install.sh)"
#
# (The `sh -c "$(curl ...)"` form keeps stdin on the terminal so the setup
# wizard can ask questions. Plain `curl ... | sudo sh` also works but only
# installs the binary — it then tells you to run `sudo 2cha setup`.)
#
# Flags (pass after `sh -s --`):
#   --no-setup   install the binary only, do not launch `2cha setup`
#
# Env overrides (mainly for testing):
#   TWOCHA_VERSION   release tag to install (default: latest)
#   TWOCHA_URL       full tarball URL (overrides arch/version detection)
#   TWOCHA_BIN_DIR   install directory (default: /usr/local/bin)
set -eu

REPO="keepinfov/2cha"
BIN_DIR="${TWOCHA_BIN_DIR:-/usr/local/bin}"
RUN_SETUP=1

for arg in "$@"; do
    case "$arg" in
        --no-setup) RUN_SETUP=0 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root (curl ... | sudo sh)" >&2
    exit 1
fi

# ── Arch detection (matches release asset naming in .github/workflows/release.yml)
case "$(uname -m)" in
    x86_64 | amd64) ARCH=x86_64 ;;
    aarch64 | arm64) ARCH=aarch64 ;;
    armv7l | armv7) ARCH=armv7 ;;
    *)
        echo "error: unsupported architecture: $(uname -m)" >&2
        echo "build from source instead: https://github.com/$REPO" >&2
        exit 1
        ;;
esac

# ── Asset selection: the static "universal" build (pure Rust, no dependencies).
ASSET="2cha-universal-linux-$ARCH.tar.gz"

if [ -n "${TWOCHA_URL:-}" ]; then
    URL="$TWOCHA_URL"
elif [ -n "${TWOCHA_VERSION:-}" ]; then
    URL="https://github.com/$REPO/releases/download/$TWOCHA_VERSION/$ASSET"
else
    URL="https://github.com/$REPO/releases/latest/download/$ASSET"
fi

# ── Fetch (curl or wget, whichever exists)
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "» downloading $URL"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$TMP/2cha.tar.gz" "$URL"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP/2cha.tar.gz" "$URL"
else
    echo "error: need curl or wget" >&2
    exit 1
fi

tar -xzf "$TMP/2cha.tar.gz" -C "$TMP"
# The universal tarball ships the binary as `2cha-universal` (see
# .github/workflows/release.yml); accept a plain `2cha` too for robustness.
if [ -f "$TMP/2cha-universal" ]; then
    BIN="$TMP/2cha-universal"
elif [ -f "$TMP/2cha" ]; then
    BIN="$TMP/2cha"
else
    echo "error: tarball did not contain a 2cha binary" >&2
    exit 1
fi

# ── Install
install -m 0755 "$BIN" "$BIN_DIR/2cha"
echo "» installed $("$BIN_DIR/2cha" --version) to $BIN_DIR/2cha"

# ── Hand over to the turn-key wizard (interactive terminals only)
if [ "$RUN_SETUP" -eq 1 ] && [ -t 0 ] && [ -t 1 ]; then
    exec "$BIN_DIR/2cha" setup
fi

echo
echo "next step: sudo 2cha setup   (turn-key server: wizard + service + firewall)"
