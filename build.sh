#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════
#  @pixagram/pixa-vault — Build & Package
#
#  Prerequisites:
#    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
#    rustup target add wasm32-unknown-unknown
#    cargo install wasm-pack
#
#  Usage:
#    ./build.sh              # Release build (size-optimized WASM)
#    ./build.sh dev          # Debug build (fast compilation)
#    ./build.sh test         # Rust unit tests
#    ./build.sh pack         # Build + prepare npm tarball
#    ./build.sh publish      # Build + npm publish
#    ./build.sh clean        # Remove build artifacts
# ═══════════════════════════════════════════════════════

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

MODE="${1:-release}"

banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  @pixagram/pixa-vault                               ║"
    echo "║  Argon2id + ChaCha20-Poly1305 + BLAKE3 (Rust/WASM) ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
}

# Build the WASM module via wasm-pack + copy JS wrapper + TypeScript types
build_wasm() {
    local PROFILE="$1"

    if [[ "$PROFILE" == "dev" ]]; then
        echo "▸ Building WASM (debug)..."
        wasm-pack build --target web --dev --out-dir pkg --out-name pixa_vault
    else
        echo "▸ Building WASM (release, size-optimized)..."
        wasm-pack build --target web --release --out-dir pkg --out-name pixa_vault
    fi

    # wasm-pack generates its own package.json in pkg/ — remove it so our
    # root package.json governs the npm package.
    rm -f pkg/package.json pkg/.gitignore

    # Copy the high-level JS wrapper alongside the WASM glue
    echo "▸ Copying JS wrapper → pkg/pq-secure-vault.js"
    cp js/pq-secure-vault.js pkg/

    # Ensure TypeScript declarations are in place
    if [[ ! -f pkg/pq-secure-vault.d.ts ]]; then
        echo "▸ pq-secure-vault.d.ts not found in pkg/ — checking project root..."
        if [[ -f pq-secure-vault.d.ts ]]; then
            cp pq-secure-vault.d.ts pkg/
        else
            echo "  ⚠ No pq-secure-vault.d.ts found. TypeScript users won't get type info."
        fi
    fi

    # Report sizes
    echo ""
    local WASM="pkg/pixa_vault_bg.wasm"
    if [[ -f "$WASM" ]]; then
        local BYTES
        BYTES=$(wc -c < "$WASM")
        local KIB=$((BYTES / 1024))
        echo "  WASM binary:  ${KIB} KiB  ($WASM)"
    fi
    echo "  JS glue:      $(wc -c < pkg/pixa_vault.js | xargs) bytes"
    echo "  JS wrapper:   $(wc -c < pkg/pq-secure-vault.js | xargs) bytes"
    echo ""
}

# Use the npm-facing README as the root README for publishing
prepare_readme() {
    if [[ -f README.npm.md ]]; then
        echo "▸ Using README.npm.md as package README"
        cp README.npm.md README.md
    fi
}

case "$MODE" in
    test)
        banner
        echo "▸ Running Rust unit tests..."
        cargo test -- --nocapture
        echo ""
        echo "✓ All tests passed."
        ;;

    dev)
        banner
        build_wasm "dev"
        echo "✓ Debug build complete → ./pkg/"
        ;;

    release)
        banner
        build_wasm "release"
        echo "✓ Release build complete → ./pkg/"
        echo ""
        echo "  Import:"
        echo "    import init from '@pixagram/pixa-vault/wasm';"
        echo "    import { PQSecureVault, initPQVault } from '@pixagram/pixa-vault';"
        ;;

    pack)
        banner
        build_wasm "release"
        prepare_readme
        echo "▸ Creating npm tarball..."
        npm pack --dry-run
        echo ""
        echo "  Run 'npm pack' to create the .tgz file."
        echo "✓ Package ready."
        ;;

    publish)
        banner
        build_wasm "release"
        prepare_readme
        echo "▸ Publishing to npm..."
        npm publish --access public
        echo "✓ Published."
        ;;

    clean)
        echo "▸ Cleaning build artifacts..."
        rm -rf pkg/ target/
        echo "✓ Clean."
        ;;

    *)
        echo "Usage: $0 {release|dev|test|pack|publish|clean}"
        exit 1
        ;;
esac
