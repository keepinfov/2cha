#!/bin/bash
# =============================================================================
# 2cha Build Script
# =============================================================================
# Build static binaries for various targets
#
# Usage:
#   ./build.sh                    # Build for current system
#   ./build.sh static             # Build static musl binary (x86_64)
#   ./build.sh static-arm         # Build static musl binary (aarch64)
#   ./build.sh all                # Build all targets
#   ./build.sh release            # Build optimized release
#   ./build.sh small              # Build size-optimized release
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
BINARY_NAME="2cha"

check_deps() {
    if ! command -v cargo &> /dev/null; then
        error "Rust/Cargo not found. Install from https://rustup.rs"
        exit 1
    fi
}

build_release() {
    info "Building release binary..."
    cargo build --release
    success "Built: target/release/$BINARY_NAME"
}

build_small() {
    info "Building size-optimized binary..."
    cargo build --profile release-small
    success "Built: target/release-small/$BINARY_NAME"
}

build_static_x86_64() {
    info "Building static x86_64-musl binary..."
    
    if ! rustup target list --installed | grep -q "x86_64-unknown-linux-musl"; then
        info "Installing x86_64-unknown-linux-musl target..."
        rustup target add x86_64-unknown-linux-musl
    fi
    
    # Check for musl-gcc
    if ! command -v musl-gcc &> /dev/null; then
        warn "musl-gcc not found. Install musl-tools:"
        echo "  Ubuntu/Debian: sudo apt install musl-tools"
        echo "  Fedora: sudo dnf install musl-gcc"
        echo "  Arch: sudo pacman -S musl"
    fi
    
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    cargo build --release --target x86_64-unknown-linux-musl
    
    local OUTPUT="target/x86_64-unknown-linux-musl/release/$BINARY_NAME"
    if [ -f "$OUTPUT" ]; then
        success "Built: $OUTPUT"
        info "Size: $(du -h "$OUTPUT" | cut -f1)"
        info "Type: $(file "$OUTPUT" | cut -d: -f2)"
    fi
}

build_static_aarch64() {
    info "Building static aarch64-musl binary..."
    
    if ! rustup target list --installed | grep -q "aarch64-unknown-linux-musl"; then
        info "Installing aarch64-unknown-linux-musl target..."
        rustup target add aarch64-unknown-linux-musl
    fi
    
    # Check for cross-compiler
    if ! command -v aarch64-linux-musl-gcc &> /dev/null; then
        warn "aarch64-linux-musl-gcc not found. Install musl cross-compiler:"
        echo "  Or use cross: cargo install cross"
        
        # Try using cross if available
        if command -v cross &> /dev/null; then
            info "Using 'cross' for cross-compilation..."
            cross build --release --target aarch64-unknown-linux-musl
        else
            error "No cross-compiler available"
            exit 1
        fi
    else
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc \
        cargo build --release --target aarch64-unknown-linux-musl
    fi
    
    local OUTPUT="target/aarch64-unknown-linux-musl/release/$BINARY_NAME"
    if [ -f "$OUTPUT" ]; then
        success "Built: $OUTPUT"
        info "Size: $(du -h "$OUTPUT" | cut -f1)"
    fi
}

build_all() {
    build_release
    build_static_x86_64
    build_static_aarch64 || warn "aarch64 build skipped"
}

package() {
    local TARGET=$1
    local ARCH=$2
    
    info "Creating package for $ARCH..."
    
    local DIR="dist/${BINARY_NAME}-${VERSION}-${ARCH}"
    mkdir -p "$DIR"
    
    cp "target/$TARGET/release/$BINARY_NAME" "$DIR/"
    cp examples/*.toml "$DIR/" 2>/dev/null || true
    cp README.md "$DIR/" 2>/dev/null || true
    
    # Create tarball
    cd dist
    tar -czvf "${BINARY_NAME}-${VERSION}-${ARCH}.tar.gz" "${BINARY_NAME}-${VERSION}-${ARCH}"
    cd ..
    
    success "Package: dist/${BINARY_NAME}-${VERSION}-${ARCH}.tar.gz"
}

install_local() {
    info "Installing to /usr/local/bin..."
    
    local BINARY="target/release/$BINARY_NAME"
    if [ ! -f "$BINARY" ]; then
        build_release
    fi
    
    sudo cp "$BINARY" /usr/local/bin/
    sudo chmod +x "/usr/local/bin/$BINARY_NAME"
    
    success "Installed: /usr/local/bin/$BINARY_NAME"
}

clean() {
    info "Cleaning build artifacts..."
    cargo clean
    rm -rf dist/
    success "Cleaned"
}

show_help() {
    echo "2cha Build Script v$VERSION"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  release       Build optimized release (default)"
    echo "  small         Build size-optimized release"
    echo "  static        Build static musl binary (x86_64)"
    echo "  static-arm    Build static musl binary (aarch64)"
    echo "  all           Build all targets"
    echo "  package       Create distribution packages"
    echo "  install       Install to /usr/local/bin"
    echo "  clean         Clean build artifacts"
    echo "  help          Show this help"
    echo ""
    echo "Environment:"
    echo "  CC            C compiler for native builds"
    echo "  CARGO_TARGET_*_LINKER  Linker for cross-compilation"
}

# Main
check_deps

case "${1:-release}" in
    release)
        build_release
        ;;
    small)
        build_small
        ;;
    static)
        build_static_x86_64
        ;;
    static-arm|static-aarch64)
        build_static_aarch64
        ;;
    all)
        build_all
        ;;
    package)
        build_static_x86_64
        package "x86_64-unknown-linux-musl" "linux-x86_64-musl"
        ;;
    install)
        install_local
        ;;
    clean)
        clean
        ;;
    help|-h|--help)
        show_help
        ;;
    *)
        error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
