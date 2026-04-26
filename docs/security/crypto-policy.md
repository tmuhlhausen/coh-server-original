# Cryptographic Policy

## Scope
This policy governs encrypted file-at-rest handling in `stoFileCryptFile`.

## File encryption requirements
- **AEAD only** for new encrypted files.
- Required scheme: **AES-256-GCM**.
- Required nonce length: **12 bytes**.
- Required tag length: **16 bytes**.
- Required file header magic: `SCF2`.
- Header fields are **versioned** and are authenticated as AAD.

## Migration compatibility
- Readers must support:
  - `SCF2` + AES-256-GCM (current).
  - Legacy Blowfish CFB payloads for **read-only migration compatibility**.
- Writers must emit only `SCF2` + AES-256-GCM files.

## Crypto dependency baseline
- OpenSSL baseline for supported builds: **1.1.1+**.
- `OPENSSL_VERSION_NUMBER` must be >= `0x1010100fL`.

## Prohibited for new storage encryption
- Blowfish
- CFB without authentication
- Any encryption mode without integrity/authentication

## Automated checks
Use:

```bash
python3 tools/crypto_policy_check.py
```

The check validates the file format marker/version path, AEAD configuration constants, legacy Blowfish decrypt-only behavior, and OpenSSL baseline declaration.
