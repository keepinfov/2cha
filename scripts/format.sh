#!/usr/bin/env bash
# =============================================================================
# Code Formatting Script
# =============================================================================
# This script formats all Rust code in the project using rustfmt.
#
# Usage:
#   ./format.sh           # Format all code
#   ./format.sh --check   # Check formatting without modifying files
# =============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if rustfmt is installed
check_rustfmt() {
    if ! command -v rustfmt &> /dev/null; then
        log_error "rustfmt is not installed"
        echo "Install it with: rustup component add rustfmt"
        exit 1
    fi
}

# Check if cargo is available
check_cargo() {
    if ! command -v cargo &> /dev/null; then
        log_error "cargo is not available"
        exit 1
    fi
}

# Format all code
format_code() {
    log_info "Formatting all Rust code..."
    cargo fmt --all
    log_info "Formatting complete!"
}

# Check formatting without modifying
check_format() {
    log_info "Checking code formatting..."
    if cargo fmt --all -- --check; then
        log_info "All code is properly formatted!"
        exit 0
    else
        log_error "Some files are not properly formatted"
        echo "Run './format.sh' to format all files"
        exit 1
    fi
}

# Main
check_rustfmt
check_cargo

case "${1:-format}" in
    --check|-c|check)
        check_format
        ;;
    --help|-h|help)
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  (none)      Format all Rust code in the project"
        echo "  --check     Check if code is formatted without modifying files"
        echo "  --help      Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0              # Format all code"
        echo "  $0 --check      # Check formatting"
        exit 0
        ;;
    format|"")
        format_code
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Run '$0 --help' for usage information"
        exit 1
        ;;
esac
