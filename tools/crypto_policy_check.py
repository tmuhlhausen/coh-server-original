#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CRYPT_FILE = ROOT / "AuthServer/lib/arda2/storage/stoFileCryptFile.cpp"
OPENSSL_V = ROOT / "AuthServer/external/openssl/opensslv.h"


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def main() -> None:
    src = CRYPT_FILE.read_text(encoding="utf-8")

    required = [
        "kMagic[] = { 'S', 'C', 'F', '2' }",
        "kHeaderVersion = 1",
        "kAlgorithmAes256Gcm = 1",
        "kNonceLength = 12",
        "kTagLength = 16",
        "EVP_aes_256_gcm",
        "EVP_CTRL_GCM_GET_TAG",
        "EVP_CTRL_GCM_SET_TAG",
    ]
    for token in required:
        if token not in src:
            fail(f"missing token in stoFileCryptFile.cpp: {token}")

    bf_calls = [m.start() for m in re.finditer(r"EVP_bf_cfb64", src)]
    if len(bf_calls) != 1:
        fail("expected exactly one EVP_bf_cfb64 usage for legacy read-only migration path")

    decrypt_fn = re.search(r"bool\s+DecryptLegacyBlowfishCfb\s*\([^\)]*\)\s*\{", src)
    if not decrypt_fn:
        fail("missing DecryptLegacyBlowfishCfb function")

    if "CryptAes256Gcm(m_key, nonce, &output[0], kHeaderPrefixLength" not in src:
        fail("header AAD binding for write path is missing")

    if "CryptAes256Gcm(m_key, nonce, &encrypted[0], minHeaderSize" not in src:
        fail("header AAD binding for read path is missing")

    ov = OPENSSL_V.read_text(encoding="utf-8")
    m = re.search(r"#define\s+OPENSSL_VERSION_NUMBER\s+0x([0-9a-fA-F]+)L", ov)
    if not m:
        fail("could not parse OPENSSL_VERSION_NUMBER")

    version_num = int(m.group(1), 16)
    baseline = int("1010100f", 16)
    if version_num < baseline:
        fail(
            "vendored OpenSSL baseline is below supported minimum (need >= 1.1.1 / 0x1010100fL)"
        )

    print("PASS: cryptographic policy checks succeeded")


if __name__ == "__main__":
    main()
