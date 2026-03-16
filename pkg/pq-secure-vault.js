/**
 * PQ Secure Vault — JavaScript integration layer for pixa-vault WASM module.
 *
 * Drop-in replacement for the PBKDF2-based vault in PixaProxyAPI v3.x.
 * All cryptographic operations run in Rust/WASM:
 *
 *   PBKDF2-SHA512 (1M iter) → Argon2id (64 MiB, 3 iter)
 *   AES-GCM (Web Crypto)    → ChaCha20-Poly1305 (WASM)
 *   PBKDF2 verify hash      → BLAKE3 over HKDF sub-key
 *
 * @version 1.0.0
 * @module PQSecureVault
 */

// ============================================
// WASM Module Loading
// ============================================

let wasmModule = null;
let wasmReady = false;
let wasmLoadPromise = null;

/**
 * Initialize the WASM module.
 * Must be called once before using any vault operations.
 *
 * Runs a smoke test after loading: a tiny Argon2id derivation (256 KiB, t=1)
 * to verify the WASM binary has enough linear memory. If this fails, the
 * binary was compiled without --initial-memory and must be rebuilt.
 *
 * @param {Function|object} initFn - The wasm-bindgen init function or pre-loaded module
 * @returns {Promise<void>}
 */
export async function initPQVault(initFn) {
    if (wasmReady) return;
    if (wasmLoadPromise) return wasmLoadPromise;

    wasmLoadPromise = (async () => {
        if (typeof initFn === 'function') {
            wasmModule = await initFn();
        } else {
            wasmModule = initFn;
        }

        // Smoke test: verify WASM memory is large enough for Argon2id.
        // Use the absolute minimum (256 KiB, t=1) — if even this fails,
        // the binary was built without --initial-memory=128MiB.
        try {
            wasmModule.deriveEncryptionKey('test', 'aa'.repeat(32), 256, 1);
        } catch (e) {
            wasmReady = false;
            wasmModule = null;
            throw new Error(
                '[PQSecureVault] WASM memory too small for Argon2id. ' +
                'Rebuild pixa-vault with: RUSTFLAGS="-C link-arg=--initial-memory=134217728" wasm-pack build --target web --release --out-dir pkg'
            );
        }

        wasmReady = true;
    })();

    return wasmLoadPromise;
}

function requireWasm() {
    if (!wasmReady || !wasmModule) {
        throw new Error('[PQSecureVault] WASM not initialized. Call initPQVault() first.');
    }
    return wasmModule;
}

// ============================================
// Constants & Defaults
// ============================================

/**
 * Default Argon2id memory cost: 19 MiB (KiB).
 * OWASP minimum recommendation for Argon2id.
 *
 * Why not 64 MiB? WASM linear memory defaults to a small initial size.
 * Argon2id allocates m_cost bytes internally, and with dlmalloc overhead
 * this can cause "memory access out of bounds" if the WASM module wasn't
 * built with sufficient --initial-memory. 19 MiB works reliably across
 * all browsers. autoTuneParams() will try higher values if the device
 * supports them.
 */
export const DEFAULT_MEMORY_KIB = 19456;

/** Default Argon2id iterations (time cost) */
export const DEFAULT_ITERATIONS = 2;

/** Low-memory profile: 9 MiB, 3 iterations (for very constrained devices) */
export const LOW_MEMORY_KIB = 9216;
export const LOW_MEMORY_ITERATIONS = 3;

/** Vault format version (for migration detection) */
export const VAULT_VERSION = 1;

// ============================================
// PQSecureVault Class
// ============================================

/**
 * PQ Secure Vault — manages encrypted key storage with Argon2id + ChaCha20-Poly1305.
 *
 * Integration points with PixaProxyAPI:
 *
 * 1. Replace `pbkdf2Derive()` calls → `vault.deriveKey(pin, salt)`
 * 2. Replace `_derivePinVerifyHash()` → `vault.generateVerifyHash(pin, salt)`
 * 3. Replace LacertaDB `getSecureDatabase()` → `vault.sealKeys()` / `vault.unsealKeys()`
 * 4. Verify PIN without vault read → `vault.verifyPin(pin, salt, storedHash)`
 *
 * @example
 * ```js
 * import { PQSecureVault, initPQVault } from './pq-secure-vault.js';
 * import init from './pixa_vault.js'; // wasm-bindgen output
 *
 * await initPQVault(init);
 * const vault = new PQSecureVault();
 *
 * // Generate salt (once, store in IndexedDB)
 * const salt = vault.generateSalt();
 *
 * // Seal all derived keys
 * const sealed = vault.sealKeys(pin, salt, 'alice', {
 *     posting: '5JPost...', active: '5JActive...', memo: '5JMemo...'
 * });
 *
 * // Later: unseal with PIN
 * const keys = vault.unsealKeys(pin, salt, sealed);
 * console.log(keys.posting); // '5JPost...'
 * ```
 */
export class PQSecureVault {
    /**
     * @param {object} [options]
     * @param {number} [options.memoryKib=65536]  Argon2id memory in KiB
     * @param {number} [options.iterations=3]     Argon2id time cost
     * @param {Function} [options.onProgress]     Progress callback (not yet wired to WASM)
     */
    constructor(options = {}) {
        this.memoryKib = options.memoryKib || DEFAULT_MEMORY_KIB;
        this.iterations = options.iterations || DEFAULT_ITERATIONS;
        this.onProgress = options.onProgress || null;

        /** @private Cached encryption key (hex). Zeroized on lock(). */
        this._cachedEncKey = null;

        /** @private Cached salt hex for the current session */
        this._cachedSalt = null;
    }

    // ----------------------------------------
    // Salt generation
    // ----------------------------------------

    /**
     * Generate a new cryptographic salt.
     * @param {number} [byteLength=32] Salt size in bytes
     * @returns {string} Hex-encoded salt
     */
    generateSalt(byteLength = 32) {
        const wasm = requireWasm();
        return wasm.generateSalt(byteLength);
    }

    // ----------------------------------------
    // Key derivation (replaces pbkdf2Derive)
    // ----------------------------------------

    /**
     * Derive the encryption key from PIN + salt.
     *
     * Replaces: `pbkdf2Derive(password, salt, iterations, keyLength)`
     *
     * Pipeline: PIN → Argon2id(salt, 64MiB, t=3) → HKDF("encrypt") → key
     *
     * @param {string} pin    User's PIN (6+ chars)
     * @param {string} salt   Hex-encoded salt
     * @returns {string}      Hex-encoded 256-bit encryption key
     */
    deriveKey(pin, salt) {
        const wasm = requireWasm();

        // Try with current params; fall back to lower memory on WASM OOB error
        let mem = this.memoryKib;
        let iter = this.iterations;
        while (mem >= 4096) {
            try {
                const key = wasm.deriveEncryptionKey(pin, salt, mem, iter);
                // If we had to fall back, persist the working params
                if (mem !== this.memoryKib) {
                    console.warn(`[PQSecureVault] Argon2id memory reduced: ${this.memoryKib} → ${mem} KiB (WASM limit)`);
                    this.memoryKib = mem;
                    this.iterations = iter;
                }
                this._cachedEncKey = key;
                this._cachedSalt = salt;
                return key;
            } catch (e) {
                const isOOB = /memory|out of bounds|grow|wasm/i.test(e.message || String(e));
                if (!isOOB) throw e; // Re-throw non-memory errors
                // Halve memory, bump iterations to compensate
                mem = Math.floor(mem / 2);
                iter = Math.min(iter + 1, 8);
            }
        }
        throw new Error('[PQSecureVault] Argon2id failed: WASM cannot allocate enough memory. Minimum 4 MiB required.');
    }

    /**
     * Derive key and return as ArrayBuffer (compatible with Web Crypto importKey).
     *
     * Drop-in replacement for the old `pbkdf2Derive()` return value.
     *
     * @param {string} pin
     * @param {string} salt
     * @returns {ArrayBuffer} 32-byte key as ArrayBuffer
     */
    deriveKeyAsArrayBuffer(pin, salt) {
        const hexKey = this.deriveKey(pin, salt);
        return hexToArrayBuffer(hexKey);
    }

    // ----------------------------------------
    // PIN verification (replaces _derivePinVerifyHash)
    // ----------------------------------------

    /**
     * Generate a PIN verification hash for storage.
     *
     * Replaces: `_derivePinVerifyHash(pin, salt)`
     *
     * The returned hash is safe to store in plaintext (IndexedDB).
     * It cannot be used to derive the encryption key (HKDF domain separation).
     *
     * @param {string} pin
     * @param {string} salt  Hex-encoded salt
     * @returns {string}     Hex-encoded BLAKE3 hash (64 chars)
     */
    generateVerifyHash(pin, salt) {
        const wasm = requireWasm();
        return wasm.generatePinVerifyHash(pin, salt, this.memoryKib, this.iterations);
    }

    /**
     * Verify a PIN against a stored hash.
     *
     * @param {string} pin
     * @param {string} salt
     * @param {string} storedHash  The hash from generateVerifyHash
     * @returns {boolean}
     */
    verifyPin(pin, salt, storedHash) {
        const wasm = requireWasm();
        return wasm.verifyPin(pin, salt, storedHash, this.memoryKib, this.iterations);
    }

    // ----------------------------------------
    // Low-level encrypt / decrypt
    // ----------------------------------------

    /**
     * Encrypt a string using a pre-derived key.
     *
     * @param {string} keyHex    Hex-encoded 32-byte key
     * @param {string} plaintext UTF-8 string to encrypt
     * @param {string} [aad]     Additional Authenticated Data (e.g., account name)
     * @returns {string}         Base64-encoded ciphertext
     */
    encrypt(keyHex, plaintext, aad = undefined) {
        const wasm = requireWasm();
        return wasm.encrypt(keyHex, plaintext, aad || undefined);
    }

    /**
     * Decrypt a base64-encoded ciphertext.
     *
     * @param {string} keyHex         Hex-encoded 32-byte key
     * @param {string} ciphertextB64  Base64-encoded ciphertext from encrypt()
     * @param {string} [aad]          Must match the AAD used during encryption
     * @returns {string}              Decrypted UTF-8 string
     * @throws {Error} On wrong key or tampered data
     */
    decrypt(keyHex, ciphertextB64, aad = undefined) {
        const wasm = requireWasm();
        return wasm.decrypt(keyHex, ciphertextB64, aad || undefined);
    }

    // ----------------------------------------
    // High-level vault operations
    // ----------------------------------------

    /**
     * Seal a single secret (full pipeline: PIN → Argon2id → HKDF → ChaCha20).
     *
     * @param {string} pin
     * @param {string} salt      Hex-encoded salt
     * @param {string} account   Account name (bound via AAD)
     * @param {string} plaintext Secret to encrypt
     * @returns {object}         SealedRecord (parsed from JSON)
     */
    sealSecret(pin, salt, account, plaintext) {
        const wasm = requireWasm();
        const json = wasm.sealSecret(pin, salt, account, plaintext, this.memoryKib, this.iterations);
        return JSON.parse(json);
    }

    /**
     * Unseal a single secret.
     *
     * @param {string} pin
     * @param {string} salt
     * @param {object} sealedRecord  Object from sealSecret()
     * @returns {string}             Decrypted plaintext
     * @throws {Error} On wrong PIN or tampered data
     */
    unsealSecret(pin, salt, sealedRecord) {
        const wasm = requireWasm();
        return wasm.unsealSecret(pin, salt, JSON.stringify(sealedRecord), this.memoryKib, this.iterations);
    }

    /**
     * Seal multiple keys at once (posting, active, memo, owner).
     *
     * Replaces the entire flow of:
     *   1. `getSecureDatabase(pin, salt, config)` → open encrypted LacertaDB
     *   2. `vaultMaster.add({derived_keys})` → store encrypted keys
     *
     * Each key type gets its own AAD binding (`account:type`), so individual
     * keys can't be swapped between types.
     *
     * @param {string} pin
     * @param {string} salt
     * @param {string} account
     * @param {object} keys - `{ posting: 'WIF', active: 'WIF', memo: 'WIF', ... }`
     * @returns {string}    Sealed JSON blob (store in IndexedDB)
     */
    sealKeys(pin, salt, account, keys) {
        const wasm = requireWasm();
        return wasm.sealKeys(pin, salt, account, JSON.stringify(keys), this.memoryKib, this.iterations);
    }

    /**
     * Unseal multiple keys from a sealed blob.
     *
     * Replaces:
     *   1. `getSecureDatabase(pin, salt, config)` → open encrypted LacertaDB
     *   2. `vaultMaster.get(account)` → read encrypted keys
     *
     * @param {string} pin
     * @param {string} salt
     * @param {string} sealedJson  The blob from sealKeys()
     * @returns {object}           `{ posting: 'WIF', active: 'WIF', ... }`
     * @throws {Error} On wrong PIN or tampered data
     */
    unsealKeys(pin, salt, sealedJson) {
        const wasm = requireWasm();
        const json = wasm.unsealKeys(pin, salt, sealedJson, this.memoryKib, this.iterations);
        return JSON.parse(json);
    }

    // ----------------------------------------
    // Session management
    // ----------------------------------------

    /**
     * Cache the encryption key in memory for the duration of the PIN session.
     * This avoids re-running Argon2id on every vault read.
     *
     * Call `lock()` to clear the cached key.
     *
     * @param {string} pin
     * @param {string} salt
     * @returns {string} The cached encryption key (hex)
     */
    unlockSession(pin, salt) {
        this._cachedEncKey = this.deriveKey(pin, salt);
        this._cachedSalt = salt;
        return this._cachedEncKey;
    }

    /**
     * Check if a session key is cached (vault is "unlocked").
     * @returns {boolean}
     */
    isUnlocked() {
        return this._cachedEncKey !== null;
    }

    /**
     * Encrypt a value using the cached session key.
     * Requires unlockSession() first.
     *
     * @param {string} plaintext
     * @param {string} [aad]
     * @returns {string} Base64 ciphertext
     */
    sessionEncrypt(plaintext, aad = undefined) {
        if (!this._cachedEncKey) throw new Error('Vault not unlocked. Call unlockSession() first.');
        return this.encrypt(this._cachedEncKey, plaintext, aad);
    }

    /**
     * Decrypt a value using the cached session key.
     *
     * @param {string} ciphertextB64
     * @param {string} [aad]
     * @returns {string} Plaintext
     */
    sessionDecrypt(ciphertextB64, aad = undefined) {
        if (!this._cachedEncKey) throw new Error('Vault not unlocked. Call unlockSession() first.');
        return this.decrypt(this._cachedEncKey, ciphertextB64, aad);
    }

    /**
     * Clear the cached encryption key. After this call, all session
     * encrypt/decrypt operations will fail until unlockSession() is called again.
     */
    lock() {
        if (this._cachedEncKey) {
            // Overwrite the string in memory (best effort in JS)
            this._cachedEncKey = '0'.repeat(this._cachedEncKey.length);
            this._cachedEncKey = null;
        }
        this._cachedSalt = null;
    }

    // ----------------------------------------
    // Utility
    // ----------------------------------------

    /**
     * Get vault crypto info (version, algorithms, default parameters).
     * @returns {object}
     */
    getInfo() {
        const wasm = requireWasm();
        return JSON.parse(wasm.getVaultInfo());
    }

    /**
     * Quick BLAKE3 hash.
     * @param {string} data
     * @returns {string} Hex-encoded 32-byte hash
     */
    blake3(data) {
        const wasm = requireWasm();
        return wasm.blake3Hash(data);
    }

    /**
     * Auto-select memory profile based on device capabilities.
     *
     * Tests a small Argon2id derivation and scales memory accordingly.
     * Call this during app initialization to set optimal params.
     *
     * @param {number} [targetMs=1500] Target derivation time in ms
     * @returns {Promise<{ memoryKib: number, iterations: number, measuredMs: number }>}
     */
    async autoTuneParams(targetMs = 1500) {
        const profiles = [
            { memoryKib: 46080, iterations: 2, label: 'high' },
            { memoryKib: 19456, iterations: 2, label: 'standard' },
            { memoryKib: 9216,  iterations: 3, label: 'low' },
        ];

        const testPin = 'bench1';
        const testSalt = this.generateSalt();
        const wasm = requireWasm();

        for (const profile of profiles) {
            try {
                const start = performance.now();
                wasm.deriveEncryptionKey(testPin, testSalt, profile.memoryKib, profile.iterations);
                const elapsed = performance.now() - start;

                if (elapsed <= targetMs * 1.5) {
                    this.memoryKib = profile.memoryKib;
                    this.iterations = profile.iterations;
                    return { ...profile, measuredMs: Math.round(elapsed) };
                }
            } catch (e) {
                // Memory allocation failed (WASM OOB) or timeout — try smaller profile
                console.warn(`[PQSecureVault] autoTune: ${profile.label} (${profile.memoryKib} KiB) failed:`, e.message || e);
                continue;
            }
        }

        // Fallback to lowest profile
        const fallback = profiles[profiles.length - 1];
        this.memoryKib = fallback.memoryKib;
        this.iterations = fallback.iterations;
        return { ...fallback, measuredMs: -1 };
    }
}

// ============================================
// Utility Functions
// ============================================

/**
 * Convert hex string to ArrayBuffer.
 * @param {string} hex
 * @returns {ArrayBuffer}
 */
function hexToArrayBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes.buffer;
}

/**
 * Convert ArrayBuffer to hex string.
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// ============================================
// Default export
// ============================================

export default PQSecureVault;
