/* tslint:disable */
/* eslint-disable */

/**
 * Quick BLAKE3 hash of arbitrary data. Returns hex-encoded 32-byte hash.
 * Useful for fingerprinting, integrity checks, etc.
 */
export function blake3Hash(data: string): string;

/**
 * Decrypt a base64-encoded ciphertext back to a string.
 *
 * Returns the plaintext string, or throws on wrong key / tampered data.
 */
export function decrypt(key_hex: string, ciphertext_b64: string, aad?: string | null): string;

/**
 * Derive the encryption key from PIN + salt using Argon2id + HKDF.
 *
 * Returns hex-encoded 32-byte encryption key.
 *
 * Parameters:
 *   - `pin`: User's PIN string (6+ chars)
 *   - `salt_hex`: Hex-encoded salt (from generateSalt)
 *   - `memory_kib`: Argon2 memory cost in KiB (default: 65536 = 64MiB)
 *   - `iterations`: Argon2 time cost (default: 3)
 *
 * This is the core replacement for `pbkdf2Derive()`.
 */
export function deriveEncryptionKey(pin: string, salt_hex: string, memory_kib?: number | null, iterations?: number | null): string;

/**
 * Encrypt a string value using ChaCha20-Poly1305.
 *
 * Parameters:
 *   - `key_hex`: Hex-encoded 32-byte key (from deriveEncryptionKey)
 *   - `plaintext`: UTF-8 string to encrypt
 *   - `aad`: Optional additional authenticated data (e.g., account name)
 *
 * Returns base64-encoded ciphertext (nonce || encrypted || tag).
 */
export function encrypt(key_hex: string, plaintext: string, aad?: string | null): string;

/**
 * Generate a PIN verification hash (hex-encoded BLAKE3).
 *
 * Store this in IndexedDB. It cannot be used to derive the encryption key
 * (domain separation via HKDF).
 *
 * Replaces `_derivePinVerifyHash()`.
 */
export function generatePinVerifyHash(pin: string, salt_hex: string, memory_kib?: number | null, iterations?: number | null): string;

/**
 * Generate a cryptographic salt (hex-encoded).
 * Default: 32 bytes = 64 hex chars.
 */
export function generateSalt(byte_length?: number | null): string;

/**
 * Return the vault version and crypto parameters as JSON.
 *
 * Useful for migration detection: if the stored version differs from
 * the current version, the frontend knows to re-encrypt vault data.
 */
export function getVaultInfo(): string;

/**
 * Seal multiple keys at once (posting, active, memo, owner).
 *
 * Parameters:
 *   - `keys_json`: JSON object `{ "posting": "5J...", "active": "5J...", ... }`
 *
 * Returns a JSON string with sealed records for each key type.
 * Each key type gets its own AAD binding: `{account}:{type}`.
 */
export function sealKeys(pin: string, salt_hex: string, account: string, keys_json: string, memory_kib?: number | null, iterations?: number | null): string;

/**
 * Full vault seal: PIN → Argon2id → HKDF → ChaCha20-Poly1305.
 *
 * Encrypts `plaintext` in one shot, using `account` as AAD binding.
 * Returns a JSON string containing the SealedRecord.
 *
 * This replaces the entire LacertaDB `getSecureDatabase` flow for
 * individual secret storage.
 */
export function sealSecret(pin: string, salt_hex: string, account: string, plaintext: string, memory_kib?: number | null, iterations?: number | null): string;

/**
 * Unseal multiple keys from a sealed JSON blob.
 *
 * Returns a JSON object `{ "posting": "5J...", "active": "5J...", ... }`.
 */
export function unsealKeys(pin: string, salt_hex: string, sealed_json: string, memory_kib?: number | null, iterations?: number | null): string;

/**
 * Full vault unseal: PIN → Argon2id → HKDF → ChaCha20-Poly1305 decrypt.
 *
 * Decrypts a JSON SealedRecord string back to plaintext.
 */
export function unsealSecret(pin: string, salt_hex: string, sealed_json: string, memory_kib?: number | null, iterations?: number | null): string;

/**
 * Verify a PIN against a stored hash.
 *
 * Returns `true` if the PIN matches, `false` otherwise.
 * Timing is dominated by Argon2id (~1s), making timing attacks irrelevant.
 */
export function verifyPin(pin: string, salt_hex: string, stored_hash: string, memory_kib?: number | null, iterations?: number | null): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly blake3Hash: (a: number, b: number, c: number) => void;
    readonly decrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly deriveEncryptionKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly generatePinVerifyHash: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly generateSalt: (a: number, b: number) => void;
    readonly getVaultInfo: (a: number) => void;
    readonly sealKeys: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => void;
    readonly sealSecret: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => void;
    readonly unsealKeys: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly unsealSecret: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly verifyPin: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export2: (a: number, b: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
