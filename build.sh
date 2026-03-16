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

# ─── WASM Memory Configuration ───────────────────────────
# Argon2id allocates m_cost KiB as a contiguous block inside WASM linear memory.
# Default WASM initial memory (~1 MiB) is far too small — Argon2id will hit
# "memory access out of bounds" on any allocation above ~700 KiB.
#
# initial-memory = 128 MiB (2048 pages × 64 KiB) — enough for up to ~46 MiB Argon2id + overhead
# max-memory     = 256 MiB — allows memory.grow() up to this ceiling if autoTune picks a larger profile
#
# These flags are passed via RUSTFLAGS and embedded in the WASM binary at link time.
WASM_MEMORY_FLAGS="-C link-arg=--initial-memory=134217728 -C link-arg=--max-memory=268435456"

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

    # Merge memory flags with any existing RUSTFLAGS
    export RUSTFLAGS="${RUSTFLAGS:-} ${WASM_MEMORY_FLAGS}"
    echo "▸ RUSTFLAGS: ${RUSTFLAGS}"

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

    # Report sizes + verify memory configuration
    echo ""
    local WASM="pkg/pixa_vault_bg.wasm"
    if [[ -f "$WASM" ]]; then
        local BYTES
        BYTES=$(wc -c < "$WASM")
        local KIB=$((BYTES / 1024))
        echo "  WASM binary:  ${KIB} KiB  ($WASM)"

        # Verify initial memory was set correctly
        if command -v wasm-objdump &> /dev/null; then
            local MEM_PAGES
            MEM_PAGES=$(wasm-objdump -h "$WASM" 2>/dev/null | grep -oP 'initial=\K[0-9]+' || echo "?")
            local MEM_MIB=$(( MEM_PAGES * 64 / 1024 ))
            echo "  WASM memory:  ${MEM_PAGES} pages = ${MEM_MIB} MiB initial"
            if [[ "$MEM_PAGES" -lt 1024 ]] 2>/dev/null; then
                echo "  ⚠ WARNING: Initial memory < 64 MiB. Argon2id may fail at runtime!"
                echo "    Ensure RUSTFLAGS includes: ${WASM_MEMORY_FLAGS}"
            fi
        fi
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
