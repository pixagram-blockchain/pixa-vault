# @pixagram/pixa-vault

Post-quantum hardened secure vault for [Pixagram](https://pixagram.io) — a blockchain-based Web3 social media platform built on a HIVE/STEEM fork.

All cryptography runs in **Rust compiled to WebAssembly**: Argon2id key derivation, ChaCha20-Poly1305 authenticated encryption, BLAKE3 hashing, and HKDF-SHA512 domain separation. Secret material is `zeroize`d on drop — not left in the JS heap.

Built as a drop-in replacement for PBKDF2-SHA512 when your users authenticate with **short PINs** (6 characters).

## Why not PBKDF2?

PBKDF2 is compute-bound. Every evaluation needs a few kilobytes of state, so a GPU can run hundreds of thousands of them in parallel. For long passwords this is acceptable. For 6-character PINs it is not:

| Metric | PBKDF2-SHA512 (1 M iter) | **Argon2id (64 MiB, t=3)** |
|---|---|---|
| Memory per attempt | ~1 KB | **64 MiB** |
| RTX 4090 throughput | ~500 000 PIN/s | **~375 PIN/s** |
| 6-char alphanumeric (2.2 B) | ~72 minutes | **~67 days** |
| 6-char numeric (1 M) | < 2 seconds | **~44 minutes** |
| ASIC resistance | None | Memory-hard |

Argon2id forces 64 MiB of allocation per evaluation. A 24 GB GPU maxes out at ~375 parallel lanes — a **1 300× throughput reduction** for the same wall-clock cost to the user (~1 s).

## Install

```bash
npm install @pixagram/pixa-vault
```

The package ships a pre-built WASM binary (`pixa_vault_bg.wasm`). No Rust toolchain needed at install time.

### Building from source

```bash
# One-time setup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Build
npm run build          # Release (size-optimized WASM)
npm run build:dev      # Debug (faster compilation)
npm run test           # Rust unit tests
```

## Quick start

```js
import init from '@pixagram/pixa-vault/wasm';
import { initPQVault, PQSecureVault } from '@pixagram/pixa-vault';

// 1. Initialize WASM (once, at app startup)
await initPQVault(init);
const vault = new PQSecureVault();

// 2. Auto-tune Argon2 params for this device (optional, recommended)
const profile = await vault.autoTuneParams(1500);   // target ≤ 1.5 s
console.log(profile);  // { label: 'standard', memoryKib: 65536, iterations: 3, measuredMs: 1120 }

// 3. Generate a salt (once per vault — persist in IndexedDB)
const salt = vault.generateSalt();   // 64 hex chars

// 4. Seal blockchain keys with the user's PIN
const sealed = vault.sealKeys('abc123', salt, 'alice', {
    posting: '5JPostingKeyWIF...',
    active:  '5JActiveKeyWIF...',
    memo:    '5JMemoKeyWIF...',
});
// sealed is a JSON string — store it in IndexedDB

// 5. Later: unseal with the same PIN
const keys = vault.unsealKeys('abc123', salt, sealed);
console.log(keys.posting);  // '5JPostingKeyWIF...'
```

## Architecture

```
PIN (6+ chars)
  │
  ▼
┌────────────────────────────────────────────┐
│  Argon2id  (m=64 MiB, t=3, p=1)           │  ◄── Memory-hard KDF (Rust/WASM)
└─────────────────────┬──────────────────────┘
                      │  master_key  (32 B, zeroized after use)
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
     HKDF-SHA512  HKDF-SHA512  HKDF-SHA512
     "encrypt"    "verify"     "session"
          │           │           │
          ▼           ▼           ▼
   ChaCha20-Poly1305  BLAKE3     Session key
   • Seal/unseal      • Safe to   • In-memory only
     private keys       store      • Ephemeral
   • AAD = account    • Cannot
     (tamper-proof)     derive key
```

HKDF purpose strings provide **domain separation**: the encryption key, verification hash, and session key are cryptographically independent even though they derive from the same master.

### Stack comparison

| Layer | PixaProxyAPI v3.x | **pixa-vault v4.0** |
|---|---|---|
| KDF | PBKDF2-SHA512 (1 M iter) | **Argon2id** (64 MiB, t=3) |
| AEAD | AES-GCM (Web Crypto) | **ChaCha20-Poly1305** (WASM) |
| PIN verify | PBKDF2 + salt‖0x02 | **BLAKE3** over HKDF sub-key |
| Domain separation | Byte suffix | **HKDF-SHA512** purpose strings |
| Memory safety | JS heap (no zeroing) | **`zeroize`** on Rust drop |
| AAD binding | None | **Account name** bound to ciphertext |
| Vault storage | LacertaDB encrypted DB | **Sealed JSON** in regular IndexedDB |

## API

### Initialization

```ts
import init from '@pixagram/pixa-vault/wasm';
import { initPQVault, PQSecureVault } from '@pixagram/pixa-vault';

await initPQVault(init);

const vault = new PQSecureVault({
    memoryKib: 65536,    // Argon2 memory in KiB  (default: 64 MiB)
    iterations: 3,       // Argon2 time cost       (default: 3)
});
```

### Salt generation

```ts
vault.generateSalt(byteLength?: number): string
```

Returns a hex-encoded CSPRNG salt. Default 32 bytes (64 hex chars). Generate once per vault and store alongside the sealed data.

### Key derivation

```ts
vault.deriveKey(pin: string, salt: string): string
vault.deriveKeyAsArrayBuffer(pin: string, salt: string): ArrayBuffer
```

Full pipeline: PIN → Argon2id(salt) → HKDF("encrypt") → 256-bit key.

`deriveKey` returns hex; `deriveKeyAsArrayBuffer` returns an `ArrayBuffer` compatible with `crypto.subtle.importKey()`. Replaces `pbkdf2Derive()`.

### PIN verification

```ts
vault.generateVerifyHash(pin: string, salt: string): string
vault.verifyPin(pin: string, salt: string, storedHash: string): boolean
```

`generateVerifyHash` returns a hex-encoded BLAKE3 digest derived through a separate HKDF branch. It is safe to store in plaintext — it cannot be reversed to obtain the encryption key.

`verifyPin` re-derives the hash and performs a constant-time comparison. Timing is dominated by Argon2id (~1 s), making side-channel attacks on the comparison irrelevant.

Replaces `_derivePinVerifyHash()`.

### Low-level encrypt / decrypt

```ts
vault.encrypt(keyHex: string, plaintext: string, aad?: string): string
vault.decrypt(keyHex: string, ciphertextB64: string, aad?: string): string
```

ChaCha20-Poly1305 AEAD. The optional `aad` (Additional Authenticated Data) binds the ciphertext to a context — decrypting with a different `aad` throws. Output is base64-encoded `nonce(12) ‖ ciphertext ‖ tag(16)`.

### Seal / unseal secrets

```ts
vault.sealSecret(pin, salt, account, plaintext): SealedRecord
vault.unsealSecret(pin, salt, sealedRecord): string

vault.sealKeys(pin, salt, account, keys): string
vault.unsealKeys(pin, salt, sealedJson): Record<string, string>
```

High-level one-shot API. Each call runs the full Argon2id pipeline internally.

`sealKeys` / `unsealKeys` handle a `{ posting, active, memo, owner }` key bundle with per-type AAD binding (`account:type`). The sealed JSON string is ready for IndexedDB storage.

Replaces `lacerta.getSecureDatabase()` + `vaultMaster.add()` / `vaultMaster.get()`.

### Session management

```ts
vault.unlockSession(pin: string, salt: string): string
vault.isUnlocked(): boolean
vault.sessionEncrypt(plaintext: string, aad?: string): string
vault.sessionDecrypt(ciphertextB64: string, aad?: string): string
vault.lock(): void
```

`unlockSession` derives the encryption key once and caches it in memory for fast repeated operations (avoids re-running Argon2id on every read). `lock` zero-fills and discards the cached key.

### Auto-tuning

```ts
vault.autoTuneParams(targetMs?: number): Promise<TuneResult>
```

Benchmarks Argon2id on the current device and selects the largest memory profile that completes within `targetMs` (default: 1500 ms). Profiles tested in order:

| Profile | Memory | Iterations |
|---|---|---|
| `standard` | 64 MiB | 3 |
| `medium` | 32 MiB | 3 |
| `low` | 16 MiB | 4 |

Mutates `vault.memoryKib` and `vault.iterations`. Call during app initialization.

### Utilities

```ts
vault.getInfo(): VaultInfo     // Version, algorithm identifiers, default params
vault.blake3(data: string): string   // Quick BLAKE3 hex digest
```

## TypeScript

Full type declarations ship with the package (`pq-secure-vault.d.ts`). Key types:

```ts
import type { SealedRecord, VaultInfo, TuneResult, PQSecureVaultOptions } from '@pixagram/pixa-vault';
```

## Migration from PixaProxyAPI v3.x

The upgrade is designed to be **automatic and transparent**. A detailed migration module is included:

```js
import { migratePBKDF2ToPQ } from '@pixagram/pixa-vault/migration';
```

### What changes in `pixaproxyapi.js`

| v3.x code | v4.0 replacement |
|---|---|
| `CONFIG.PBKDF2_ITERATIONS` | `CONFIG.ARGON2_MEMORY_KIB` + `CONFIG.ARGON2_ITERATIONS` |
| `pbkdf2Derive(pin, salt, iter, len)` | `vault.deriveKey(pin, salt)` |
| `_derivePinVerifyHash(pin, salt)` | `vault.generateVerifyHash(pin, salt)` |
| `lacerta.getSecureDatabase(name, pin, salt, opts)` | `vault.sealKeys(pin, salt, account, keys)` |
| `vaultMaster.get(account)` | `vault.unsealKeys(pin, salt, sealedJson)` |
| `vaultMaster.add(doc)` | Store `vault.sealKeys()` output in plain IndexedDB |

### Migration flow

On first `initializeVault(pin)` after upgrade:

1. Detects old `vault_config` collection (PBKDF2 salt) in `settingsDb`.
2. Opens old LacertaDB encrypted vault with PBKDF2 using the entered PIN.
3. Reads all master and individual keys from the old vault.
4. Re-seals every key with Argon2id + ChaCha20-Poly1305 into new `sealed_keys` collection.
5. Generates a new BLAKE3 verification hash in `pq_vault_config`.
6. Marks the old vault as migrated (preserved for disaster recovery — never deleted).

All subsequent operations use the PQ vault exclusively. See `js/migration-guide.js` for the complete integration diff with replacement code for `initializeVault`, `unlockWithPin`, `_derivePinVerifyHash`, and `hasVaultConfig`.

### New IndexedDB collections

| Collection | Purpose |
|---|---|
| `pq_vault_config` | Salt, BLAKE3 verify hash, format version |
| `sealed_keys` | ChaCha20-Poly1305 sealed key blobs |

The old `vault_config` and encrypted `pixa_vault` collections are preserved indefinitely.

## Security properties

| Property | Guarantee |
|---|---|
| **Brute-force resistance** | 64 MiB memory per attempt limits GPU parallelism |
| **Side-channel safety** | Constant-time AEAD (ChaCha20) and constant-time hash comparison |
| **Domain separation** | HKDF purpose strings prevent key reuse across roles |
| **Tamper detection** | Poly1305 MAC authenticates all ciphertext |
| **Cross-account binding** | Account name as AAD — keys can't be replayed between users |
| **Cross-type binding** | `account:type` AAD — posting key can't masquerade as active |
| **Memory safety** | Rust `zeroize` crate — all key material zeroed on drop |
| **Forward secrecy** | Session keys are ephemeral, not derived from PIN |
| **No AES-NI dependency** | ChaCha20 performs identically on all WASM hosts |

### Post-quantum considerations

This vault does not use lattice-based schemes (ML-KEM, ML-DSA) because:

1. The vault is **purely symmetric** — no public-key cryptography to attack with Shor's algorithm.
2. Argon2id's security is dominated by **memory cost**, not computational cost. Grover's quadratic speedup is irrelevant when each evaluation requires 64 MiB.
3. 256-bit ChaCha20 provides 128-bit post-quantum security (Grover's halving), which is sufficient.
4. Lattice schemes would add ~2 MB to the WASM binary for no practical security gain in this context.

### Threat model

The vault protects against:

- **Offline brute-force** of a stolen IndexedDB dump (Argon2id memory cost).
- **GPU/ASIC farms** attempting to crack short PINs (memory-hardness).
- **Cross-account replay** where sealed data from one account is injected into another (AAD binding).
- **Key-type confusion** where a posting-key ciphertext is substituted for an active key (per-type AAD).
- **JS heap inspection** by browser extensions or devtools (keys zeroized in Rust, session cache AES-GCM encrypted in JS).
- **Timing attacks** on PIN verification (constant-time BLAKE3 compare, dominated by ~1 s Argon2id).

It does **not** protect against:

- A compromised host page (XSS with full DOM access can intercept the PIN at entry time).
- Physical access to an unlocked session (session keys are in memory by design).
- Quantum computers breaking the entropy of a 6-character PIN itself (expand to 8+ characters for long-term PQ security).

## Project structure

```
@pixagram/pixa-vault/
├── Cargo.toml                 # Rust crate config
├── package.json               # npm package config
├── build.sh                   # Build script (wasm-pack)
├── src/                       # Rust source
│   ├── lib.rs                 # WASM exports (12 functions)
│   ├── kdf.rs                 # Argon2id + HKDF derivation
│   ├── cipher.rs              # ChaCha20-Poly1305 AEAD
│   ├── vault.rs               # Seal / unseal operations
│   ├── verify.rs              # BLAKE3 PIN verification
│   └── error.rs               # Error types
├── js/
│   └── migration-guide.js     # v3 → v4 migration code
└── pkg/                       # Build output (wasm-pack + JS wrapper)
    ├── pixa_vault.js           # WASM-bindgen glue
    ├── pixa_vault_bg.wasm      # WASM binary (~180 KB gzipped)
    ├── pixa_vault.d.ts         # WASM TypeScript types
    ├── pq-secure-vault.js      # High-level JS wrapper
    └── pq-secure-vault.d.ts    # JS wrapper TypeScript types
```

## Related packages

| Package | Role |
|---|---|
| [`@pixagram/dpixa`](https://github.com/nickelpixa/dpixa) | Blockchain client SDK (PrivateKey, Client, broadcast) |
| [`@pixagram/lacerta-db`](https://github.com/nickelpixa/lacerta-db) | Browser database (IndexedDB, collections, queries) |
| [`@pixagram/renderart`](https://github.com/nickelpixa/renderart) | WebGL/WASM pixel art rendering (CRT, hexagon, xBRZ) |

## Acknowledgements

Cryptographic architecture inspired by [anubis-vault](https://docs.rs/anubis-vault/0.2.0/anubis_vault/) (Argon2id + ChaCha20-Poly1305 + BLAKE3 + zeroize), adapted for a browser-WASM environment with short-PIN constraints.

## License

MIT — [Pixagram SA](https://pixagram.io), Zug, Switzerland
