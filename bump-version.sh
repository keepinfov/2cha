#!/usr/bin/env bash
# Version management script for 2cha
# Usage: ./bump-version.sh <new_version>
# Example: ./bump-version.sh 0.7.0

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.7.0"
    exit 1
fi

NEW_VERSION="$1"

# Validate version format (X.Y.Z)
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 0.7.0)"
    exit 1
fi

echo "📦 Bumping version to $NEW_VERSION..."
echo ""

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2)
echo "Current version: $CURRENT_VERSION"
echo "New version:     $NEW_VERSION"
echo ""

# Update Cargo.toml
echo "Updating Cargo.toml..."
sed -i.bak "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml

# Update flake.nix (both occurrences)
echo "Updating flake.nix..."
sed -i.bak "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/g" flake.nix

# Update Cargo.lock
echo "Updating Cargo.lock..."
cargo update -p twocha

# Clean up backup files
rm -f Cargo.toml.bak flake.nix.bak

echo ""
echo "✅ Version bumped successfully!"
echo ""
echo "Files updated:"
echo "  • Cargo.toml"
echo "  • flake.nix"
echo "  • Cargo.lock"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Test build: cargo build --release"
echo "  3. Commit: git commit -am \"Bump version to $NEW_VERSION\""
echo "  4. Tag: git tag v$NEW_VERSION"
echo "  5. Push: git push && git push --tags"
