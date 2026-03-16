# pixa-vault — Post-Quantum Hardened Secure Vault

Argon2id + ChaCha20-Poly1305 + BLAKE3 replacement for the PBKDF2-based vault.
Designed specifically for short PINs (6 characters) in a browser/WASM environment.

## Why Replace PBKDF2?

The current PixaProxyAPI vault uses PBKDF2-SHA512 with 1M iterations. For long passwords this is adequate. For 6-character PINs it is dangerously weak against modern GPUs:

| Attack scenario          | PBKDF2 (current)       | Argon2id (new)            |
|--------------------------|------------------------|---------------------------|
| KDF algorithm            | PBKDF2-SHA512, 1M iter | Argon2id, 64 MiB, t=3    |
| RTX 4090 throughput      | ~500K guesses/sec      | ~375 guesses/sec          |
| 6-char alphanumeric      | ~72 minutes            | ~67 days                  |
| 6-char numeric-only      | less than 2 seconds    | ~44 minutes               |
| Memory per attempt       | ~0 (CPU only)          | 64 MiB (GPU-hostile)      |
| ASIC resistance          | None (SHA-512 ASICs)   | Memory-hard (no ASICs)    |

PBKDF2 is compute-bound (parallelizes perfectly on GPUs). Argon2id is memory-bound (each attempt needs 64 MiB, limiting GPU parallelism to ~375 lanes on 24 GB).

## Architecture

```
PIN (6+ chars)
  |
  v
+------------------------------------------+
|  Argon2id(pin, salt, 64MiB, t=3, p=1)   |  <- Memory-hard KDF (Rust/WASM)
+--------------------+---------------------+
                     | master_key (32 bytes, zeroize on drop)
                     |
          +----------+----------+
          v          v          v
    HKDF-SHA512  HKDF-SHA512  HKDF-SHA512
    "encrypt"    "verify"     "session"
          |          |          |
          v          v          v
    ChaCha20-    BLAKE3      Session key
    Poly1305     hash        (in-memory
    (vault       (stored      encryption)
    encrypt)     in IDB)
```

## Crypto Stack Comparison

| Layer              | v3.x (Old)                  | v4.0 (New)                          |
|--------------------|-----------------------------|-------------------------------------|
| KDF                | PBKDF2-SHA512 (1M iter)     | Argon2id (64 MiB, 3 iter)          |
| Encryption         | AES-GCM via Web Crypto      | ChaCha20-Poly1305 (WASM)           |
| PIN verify         | PBKDF2 + 0x02 suffix byte   | BLAKE3 over HKDF sub-key           |
| Domain sep.        | Salt suffix byte (0x02)     | HKDF-SHA512 purpose strings        |
| Memory safety      | None (JS heap)              | zeroize on Rust drop               |
| AAD binding        | None                        | Account name bound to ciphertext   |

## Building

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

chmod +x build.sh
./build.sh          # Release (size-optimized WASM)
./build.sh test     # Run Rust unit tests
```

## JavaScript Quick Start

```js
import init from '@pixagram/pixa-vault/pixa_vault.js';
import { PQSecureVault, initPQVault } from '@pixagram/pixa-vault/pq-secure-vault.js';

await initPQVault(init);
const vault = new PQSecureVault();

// Auto-tune for device
const tune = await vault.autoTuneParams(1500);

// Generate salt (once per vault, store in IndexedDB)
const salt = vault.generateSalt(64);

// Seal all derived keys
const sealed = vault.sealKeys(pin, salt, 'alice', {
    posting: '5JPost...', active: '5JActive...', memo: '5JMemo...'
});

// Unseal with PIN
const keys = vault.unsealKeys(pin, salt, sealed);
```

## Integration Points

| PixaProxyAPI method           | Replacement                                  |
|-------------------------------|----------------------------------------------|
| pbkdf2Derive()                | vault.deriveKey(pin, salt)                   |
| _derivePinVerifyHash()        | vault.generateVerifyHash(pin, salt)          |
| lacerta.getSecureDatabase()   | vault.sealKeys() / vault.unsealKeys()        |
| vaultMaster.add()             | Store vault.sealKeys() output in plain IDB   |
| vaultMaster.get()             | Read sealed blob, vault.unsealKeys()         |
| _generateSessionCryptoKey()   | vault.unlockSession() (optional hybrid)      |

See js/migration-patch.js for the complete integration diff.

## License

MIT — Pixagram SA
