/**
 * @pixagram/pixa-vault — TypeScript declarations
 *
 * Post-quantum hardened secure vault.
 * Argon2id + ChaCha20-Poly1305 + BLAKE3 in Rust/WASM.
 *
 * @packageDocumentation
 */

/**
 * Initialize the pixa-vault WASM module.
 * Must be called once before creating `PQSecureVault` instances.
 *
 * @param initFn - The default export from `@pixagram/pixa-vault/wasm`
 *
 * @example
 * ```ts
 * import init from '@pixagram/pixa-vault/wasm';
 * import { initPQVault, PQSecureVault } from '@pixagram/pixa-vault';
 *
 * await initPQVault(init);
 * const vault = new PQSecureVault();
 * ```
 */
export function initPQVault(initFn: (() => Promise<any>) | object): Promise<void>;

/** Default Argon2id memory cost in KiB (65536 = 64 MiB). */
export const DEFAULT_MEMORY_KIB: 65536;

/** Default Argon2id time cost (iterations). */
export const DEFAULT_ITERATIONS: 3;

/** Low-memory Argon2id cost in KiB (16384 = 16 MiB). */
export const LOW_MEMORY_KIB: 16384;

/** Low-memory Argon2id time cost. */
export const LOW_MEMORY_ITERATIONS: 4;

/** Current vault format version. */
export const VAULT_VERSION: 1;

/** A sealed record returned by `sealSecret()`. */
export interface SealedRecord {
    /** Format version (currently 1). */
    version: number;
    /** Base64-encoded ChaCha20-Poly1305 ciphertext (nonce ‖ ct ‖ tag). */
    ciphertext: string;
    /** Account name used as Additional Authenticated Data. */
    aad_account: string;
    /** BLAKE3 fingerprint of the encryption sub-key. */
    key_fingerprint: string;
    /** Unix timestamp (ms) of encryption. */
    created_at: number;
}

/** Vault info returned by `getInfo()`. */
export interface VaultInfo {
    version: number;
    crate_version: string;
    kdf: 'argon2id';
    cipher: 'chacha20-poly1305';
    hash: 'blake3';
    domain_sep: 'hkdf-sha512';
    default_memory_kib: number;
    default_iterations: number;
    key_size_bits: 256;
    nonce_size_bits: 96;
    tag_size_bits: 128;
}

/** Device profile result from `autoTuneParams()`. */
export interface TuneResult {
    /** Argon2id memory in KiB for this profile. */
    memoryKib: number;
    /** Argon2id iterations for this profile. */
    iterations: number;
    /** Human-readable label: `'standard'` | `'medium'` | `'low'`. */
    label: 'standard' | 'medium' | 'low';
    /** Measured derivation time in ms, or -1 on fallback. */
    measuredMs: number;
}

/** Options for the `PQSecureVault` constructor. */
export interface PQSecureVaultOptions {
    /** Argon2id memory cost in KiB. Default: 65536 (64 MiB). */
    memoryKib?: number;
    /** Argon2id time cost. Default: 3. */
    iterations?: number;
    /** Progress callback (reserved for future use). */
    onProgress?: ((progress: number) => void) | null;
}

/**
 * Post-quantum hardened secure vault.
 *
 * All cryptographic operations execute in Rust/WASM:
 * - **KDF:** Argon2id (memory-hard, GPU/ASIC resistant)
 * - **AEAD:** ChaCha20-Poly1305 (constant-time, no AES-NI dependency)
 * - **Hash:** BLAKE3 (fast, domain-separated via HKDF-SHA512)
 * - **Memory:** `zeroize` on drop for all key material
 *
 * @example
 * ```ts
 * import init from '@pixagram/pixa-vault/wasm';
 * import { initPQVault, PQSecureVault } from '@pixagram/pixa-vault';
 *
 * await initPQVault(init);
 * const vault = new PQSecureVault();
 *
 * const salt = vault.generateSalt();
 * const sealed = vault.sealKeys('123456', salt, 'alice', {
 *     posting: '5JPost...', active: '5JActive...'
 * });
 *
 * const keys = vault.unsealKeys('123456', salt, sealed);
 * ```
 */
export class PQSecureVault {
    /** Active Argon2id memory cost in KiB. */
    memoryKib: number;
    /** Active Argon2id time cost. */
    iterations: number;

    constructor(options?: PQSecureVaultOptions);

    // ── Salt ─────────────────────────────────────────────

    /**
     * Generate a CSPRNG salt.
     * @param byteLength - Salt size in bytes (default: 32 → 64 hex chars).
     * @returns Hex-encoded salt.
     */
    generateSalt(byteLength?: number): string;

    // ── Key derivation ───────────────────────────────────

    /**
     * Derive the encryption key from PIN + salt.
     * Pipeline: PIN → Argon2id → HKDF("encrypt") → 256-bit key.
     *
     * Drop-in replacement for `pbkdf2Derive()`.
     *
     * @returns Hex-encoded 32-byte encryption key.
     */
    deriveKey(pin: string, salt: string): string;

    /**
     * Derive key and return as `ArrayBuffer`.
     * Compatible with `crypto.subtle.importKey()`.
     */
    deriveKeyAsArrayBuffer(pin: string, salt: string): ArrayBuffer;

    // ── PIN verification ─────────────────────────────────

    /**
     * Generate a PIN verification hash for storage.
     * Safe to persist in plaintext — domain-separated from the encryption key.
     *
     * Drop-in replacement for `_derivePinVerifyHash()`.
     *
     * @returns Hex-encoded BLAKE3 hash (64 chars).
     */
    generateVerifyHash(pin: string, salt: string): string;

    /**
     * Verify a PIN against a stored verification hash.
     * Timing is dominated by Argon2id (~1 s), not the comparison.
     */
    verifyPin(pin: string, salt: string, storedHash: string): boolean;

    // ── Low-level encrypt / decrypt ──────────────────────

    /**
     * Encrypt a UTF-8 string with a pre-derived key.
     * @param keyHex - Hex-encoded 32-byte key from `deriveKey()`.
     * @param aad    - Additional Authenticated Data (e.g. account name).
     * @returns Base64-encoded ciphertext (nonce ‖ ct ‖ tag).
     */
    encrypt(keyHex: string, plaintext: string, aad?: string): string;

    /**
     * Decrypt a base64 ciphertext produced by `encrypt()`.
     * @throws On wrong key, wrong AAD, or tampered data.
     */
    decrypt(keyHex: string, ciphertextB64: string, aad?: string): string;

    // ── High-level vault operations ──────────────────────

    /**
     * Seal a single secret. Full pipeline in one call.
     * The `account` string is bound to the ciphertext via AAD.
     */
    sealSecret(pin: string, salt: string, account: string, plaintext: string): SealedRecord;

    /**
     * Unseal a sealed record back to plaintext.
     * @throws On wrong PIN, tampered data, or account mismatch.
     */
    unsealSecret(pin: string, salt: string, sealedRecord: SealedRecord): string;

    /**
     * Seal a key bundle (posting, active, memo, owner).
     * Each key type gets its own AAD binding (`account:type`).
     *
     * Replaces `lacerta.getSecureDatabase()` + `vaultMaster.add()`.
     *
     * @param keys - e.g. `{ posting: '5J...', active: '5J...' }`
     * @returns Sealed JSON blob. Store in IndexedDB.
     */
    sealKeys(pin: string, salt: string, account: string, keys: Record<string, string>): string;

    /**
     * Unseal a key bundle from a sealed JSON blob.
     *
     * Replaces `lacerta.getSecureDatabase()` + `vaultMaster.get()`.
     *
     * @throws On wrong PIN, tampered data, or type mismatch.
     */
    unsealKeys(pin: string, salt: string, sealedJson: string): Record<string, string>;

    // ── Session management ───────────────────────────────

    /**
     * Derive the encryption key and cache it in memory.
     * Avoids re-running Argon2id on every vault operation.
     * Call `lock()` to clear the cached key.
     */
    unlockSession(pin: string, salt: string): string;

    /** Whether a session key is currently cached. */
    isUnlocked(): boolean;

    /** Encrypt using the cached session key. Requires `unlockSession()`. */
    sessionEncrypt(plaintext: string, aad?: string): string;

    /** Decrypt using the cached session key. Requires `unlockSession()`. */
    sessionDecrypt(ciphertextB64: string, aad?: string): string;

    /** Zero-fill and discard the cached session key. */
    lock(): void;

    // ── Utility ──────────────────────────────────────────

    /** Vault version, algorithm identifiers, and default parameters. */
    getInfo(): VaultInfo;

    /** Quick BLAKE3 hash. Returns hex-encoded 32-byte digest. */
    blake3(data: string): string;

    /**
     * Benchmark Argon2id on the current device and select the best
     * memory/iteration profile that completes within `targetMs`.
     * Mutates `this.memoryKib` and `this.iterations`.
     */
    autoTuneParams(targetMs?: number): Promise<TuneResult>;
}

/** Convert an `ArrayBuffer` to a hex string. */
export function arrayBufferToHex(buffer: ArrayBuffer): string;

export default PQSecureVault;
