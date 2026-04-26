/*****************************************************************************
created:	2005/07/28
copyright:	2005, NCSoft. All Rights Reserved
author(s):	Philip Flesher

purpose:	extension of stoFileOSFile that encrypts/decrypts files

*****************************************************************************/

#include "arda2/core/corFirst.h"

// Note[tcg]: so if you don't have openssl then you can't build this file...
#if CORE_SYSTEM_XENON|CORE_SYSTEM_PS3
#else

#include "./stoFileCryptFile.h"
#include "arda2/storage/stoFileUtils.h"

#include <algorithm>
#include <cstring>

#include "openssl/evp.h"
#include "openssl/rand.h"

namespace
{
    static const unsigned char kMagic[] = { 'S', 'C', 'F', '2' };
    static const unsigned char kHeaderVersion = 1;
    static const unsigned char kAlgorithmAes256Gcm = 1;
    static const unsigned char kNonceLength = 12;
    static const unsigned char kTagLength = 16;
    static const size_t kHeaderPrefixLength = sizeof(kMagic) + 4;

    struct ScopedEvpCipherCtx
    {
        ScopedEvpCipherCtx() : m_ctx(EVP_CIPHER_CTX_new()) {}
        ~ScopedEvpCipherCtx() { if (m_ctx) EVP_CIPHER_CTX_free(m_ctx); }
        EVP_CIPHER_CTX *m_ctx;
    };

    bool CryptAes256Gcm(const std::vector<unsigned char> &key,
                        const unsigned char *nonce,
                        const unsigned char *aad,
                        const size_t aadLength,
                        const std::vector<unsigned char> &input,
                        std::vector<unsigned char> &output,
                        unsigned char *tag,
                        bool encrypt)
    {
        ScopedEvpCipherCtx ctx;
        if (!ctx.m_ctx)
            return false;

        if (EVP_CipherInit_ex(ctx.m_ctx, EVP_aes_256_gcm(), 0, 0, 0, encrypt ? 1 : 0) != 1)
            return false;
        if (EVP_CIPHER_CTX_ctrl(ctx.m_ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLength, 0) != 1)
            return false;
        if (EVP_CipherInit_ex(ctx.m_ctx, 0, 0, &key[0], nonce, -1) != 1)
            return false;
        if (aad && aadLength > 0)
        {
            int aadLen = 0;
            if (EVP_CipherUpdate(ctx.m_ctx, 0, &aadLen, aad, (int)aadLength) != 1)
                return false;
        }

        output.resize(input.size());
        int outLen = 0;
        if (!input.empty() && EVP_CipherUpdate(ctx.m_ctx, &output[0], &outLen, &input[0], (int)input.size()) != 1)
            return false;

        int finalLen = 0;
        if (encrypt)
        {
            if (EVP_CipherFinal_ex(ctx.m_ctx, output.empty() ? 0 : (&output[0] + outLen), &finalLen) != 1)
                return false;
            if (EVP_CIPHER_CTX_ctrl(ctx.m_ctx, EVP_CTRL_GCM_GET_TAG, kTagLength, tag) != 1)
                return false;
        }
        else
        {
            if (EVP_CIPHER_CTX_ctrl(ctx.m_ctx, EVP_CTRL_GCM_SET_TAG, kTagLength, tag) != 1)
                return false;
            if (EVP_CipherFinal_ex(ctx.m_ctx, output.empty() ? 0 : (&output[0] + outLen), &finalLen) != 1)
                return false;
        }

        output.resize((size_t)(outLen + finalLen));
        return true;
    }

    bool DecryptLegacyBlowfishCfb(const std::vector<unsigned char> &key,
                                  const std::vector<unsigned char> &ciphertext,
                                  std::vector<unsigned char> &plaintext)
    {
        ScopedEvpCipherCtx ctx;
        if (!ctx.m_ctx)
            return false;

        unsigned char iv[8] = { 0 };
        if (EVP_DecryptInit_ex(ctx.m_ctx, EVP_bf_cfb64(), 0, &key[0], iv) != 1)
            return false;

        plaintext.resize(ciphertext.size());
        int outLen = 0;
        if (!ciphertext.empty() && EVP_DecryptUpdate(ctx.m_ctx, &plaintext[0], &outLen, &ciphertext[0], (int)ciphertext.size()) != 1)
            return false;

        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx.m_ctx, plaintext.empty() ? 0 : (&plaintext[0] + outLen), &finalLen) != 1)
            return false;

        plaintext.resize((size_t)(outLen + finalLen));
        return true;
    }
}

stoFileCryptFile::stoFileCryptFile() :
    m_readOffset(0),
    m_mode(kAccessNone),
    m_isNewFormat(false),
    m_readInitialized(false),
    m_writeFinalized(false)
{
}

stoFileCryptFile::~stoFileCryptFile()
{
    if (CanWrite())
        FinalizeWriteBuffer();
}

errResult stoFileCryptFile::Open(const char* filename, AccessMode mode, const unsigned char *key, uint keyLength)
{
    if ((key == 0) || (keyLength == 0) || (keyLength > stoFileCryptFile::MAX_KEY_LENGTH))
        return ER_Failure;

    if (stoFileOSFile::Open(filename, mode) == ER_Failure)
        return ER_Failure;

    m_mode = mode;
    m_isNewFormat = false;
    m_readInitialized = false;
    m_writeFinalized = false;
    m_readOffset = 0;
    m_readBuffer.clear();
    m_writeBuffer.clear();

    m_key.assign(32, 0);
    std::memcpy(&m_key[0], key, keyLength);

    return ER_Success;
}

errResult stoFileCryptFile::Close()
{
    if (CanWrite())
    {
        if (ISERROR(FinalizeWriteBuffer()))
            return ER_Failure;
    }

    return stoFileOSFile::Close();
}

errResult stoFileCryptFile::InitializeReadBuffer()
{
    if (m_readInitialized)
        return ER_Success;

    const int encryptedSize = stoFileOSFile::GetSize();
    if (encryptedSize < 0)
        return ER_Failure;

    std::vector<unsigned char> encrypted((size_t)encryptedSize);
    if (!encrypted.empty() && ISERROR(stoFileOSFile::Read(&encrypted[0], encrypted.size())))
        return ER_Failure;

    m_readBuffer.clear();
    m_isNewFormat = false;

    const size_t minHeaderSize = kHeaderPrefixLength;
    if (encrypted.size() >= minHeaderSize && std::memcmp(&encrypted[0], kMagic, sizeof(kMagic)) == 0)
    {
        const unsigned char version = encrypted[4];
        const unsigned char algorithm = encrypted[5];
        const unsigned char nonceLen = encrypted[6];
        const unsigned char tagLen = encrypted[7];

        if (version != kHeaderVersion || algorithm != kAlgorithmAes256Gcm || nonceLen != kNonceLength || tagLen != kTagLength)
            return ER_Failure;

        const size_t headerSize = minHeaderSize + nonceLen;
        if (encrypted.size() < headerSize + tagLen)
            return ER_Failure;

        const unsigned char *nonce = &encrypted[minHeaderSize];
        const unsigned char *tag = &encrypted[encrypted.size() - tagLen];

        std::vector<unsigned char> ciphertext(encrypted.begin() + headerSize, encrypted.end() - tagLen);
        unsigned char mutableTag[kTagLength];
        std::memcpy(mutableTag, tag, kTagLength);

        if (!CryptAes256Gcm(m_key, nonce, &encrypted[0], minHeaderSize, ciphertext, m_readBuffer, mutableTag, false))
            return ER_Failure;

        m_isNewFormat = true;
    }
    else
    {
        if (!DecryptLegacyBlowfishCfb(m_key, encrypted, m_readBuffer))
            return ER_Failure;
    }

    m_readOffset = 0;
    m_readInitialized = true;
    return ER_Success;
}

errResult stoFileCryptFile::Read(void* buffer, size_t size)
{
    if (ISERROR(InitializeReadBuffer()))
        return ER_Failure;

    if (m_readOffset + size > m_readBuffer.size())
        return ER_Failure;

    std::memcpy(buffer, &m_readBuffer[m_readOffset], size);
    m_readOffset += size;
    return ER_Success;
}

errResult stoFileCryptFile::FinalizeWriteBuffer()
{
    if (m_writeFinalized || !CanWrite())
        return ER_Success;

    unsigned char nonce[kNonceLength] = { 0 };
    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        return ER_Failure;

    std::vector<unsigned char> ciphertext;
    unsigned char tag[kTagLength] = { 0 };
    std::vector<unsigned char> output;
    output.reserve(sizeof(kMagic) + 4 + kNonceLength + m_writeBuffer.size() + kTagLength);
    output.insert(output.end(), kMagic, kMagic + sizeof(kMagic));
    output.push_back(kHeaderVersion);
    output.push_back(kAlgorithmAes256Gcm);
    output.push_back(kNonceLength);
    output.push_back(kTagLength);
    output.insert(output.end(), nonce, nonce + kNonceLength);
    if (!CryptAes256Gcm(m_key, nonce, &output[0], kHeaderPrefixLength, m_writeBuffer, ciphertext, tag, true))
        return ER_Failure;
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
    output.insert(output.end(), tag, tag + kTagLength);

    if (ISERROR(stoFileOSFile::Write(&output[0], output.size())))
        return ER_Failure;

    m_writeFinalized = true;
    return ER_Success;
}

errResult stoFileCryptFile::Write(const void* buffer, size_t size)
{
    if (size == 0)
        return ER_Success;

    const unsigned char *begin = static_cast<const unsigned char*>(buffer);
    m_writeBuffer.insert(m_writeBuffer.end(), begin, begin + size);
    return ER_Success;
}

bool stoFileCryptFile::Eof() const
{
    if (!m_readInitialized)
        return false;

    return m_readOffset >= m_readBuffer.size();
}

int stoFileCryptFile::GetSize() const
{
    if (!m_readInitialized)
        return 0;

    return (int)m_readBuffer.size();
}

int stoFileCryptFile::Tell() const
{
    return (int)m_readOffset;
}

stoFileOSFile* stoFileCryptFile::OpenPlaintextOrEncryptedFile(const char *plaintextFilename, const char *encryptedFilename,
                                                              const unsigned char *key, const uint keyLength,
                                                              bool warnIfBothFilesExist, bool warnIfNeitherFileExists)
{
    stoFileOSFile *returnFile = 0;

    bool plaintextExists = stoFileUtils::FileExists(plaintextFilename);
    bool encryptedExists = stoFileUtils::FileExists(encryptedFilename);

    if (plaintextExists)
    {
        returnFile = new stoFileOSFile();
        returnFile->Open(plaintextFilename, stoFileOSFile::kAccessRead);

        if (encryptedExists && warnIfBothFilesExist)
        {
            ERR_REPORTV( ES_Warning, ("Both file %s and file %s exist. Using %s.", plaintextFilename, encryptedFilename, plaintextFilename));
        }
    }
    else if (encryptedExists)
    {
        returnFile = new stoFileCryptFile();
        static_cast<stoFileCryptFile*>(returnFile)->Open(encryptedFilename, stoFileOSFile::kAccessRead, key, keyLength);
    }
    else if (warnIfNeitherFileExists)
    {
        ERR_REPORTV( ES_Warning, ("Neither file %s nor file %s exists.", plaintextFilename, encryptedFilename, plaintextFilename));
    }

    return returnFile;
}


#endif // !(CORE_SYSTEM_XENON|CORE_SYSTEM_PS3)
