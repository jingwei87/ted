/// \file CryptoUtil.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement interfaces defined in CryptoUtil.h
/// \version 0.1
/// \date 2019-03-15
///
/// \copyright Copyright (c) 2019
///

#include "CryptoUtil.h"

#define DEBUG_OUTPUT 1

/**initialize the static variable */
opensslLock_t* CryptoUtil::opensslLock_ = NULL;

void CryptoUtil::opensslLockingCallback_(int mode, int type, const char* file, int line)
{
#if OPENSSL_DEBUG
    CRYPTO_THREADID id;
    CRYPTO_THREADID_current(&id);
    printf("thread=%4ld, mode=%s, lock=%s, %s:%d\n", id.val, (mode & CRYPTO_LOCK) ? "l" : "u", (type & CRYPTO_READ) ? "r" : "w", file, line);
#endif

    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(opensslLock_->lockList[type]));
        CryptoUtil::opensslLock_->cntList[type]++;
    } else {
        pthread_mutex_unlock(&(opensslLock_->lockList[type]));
    }
}

/// \brief get the id of the current thread
///
/// \param id the return id <return>

void CryptoUtil::opensslThreadID_(CRYPTO_THREADID* id)
{
    CRYPTO_THREADID_set_numeric(id, pthread_self());
}

/// \brief set up OpenSSL locks
///
/// \return true succeeds
/// \return false fails

bool CryptoUtil::opensslLockSetup()
{
#if defined(OPENSSL_THREADS)
    printf("OpenSSL lock setup started\n");

    opensslLock_ = (opensslLock_t*)malloc(sizeof(opensslLock_t));

    opensslLock_->lockList = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    opensslLock_->cntList = (long*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

    printf("cntList[i]:CRYPTO_get_lock_name(i)\n");
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&(opensslLock_->lockList[i]), NULL);
        opensslLock_->cntList[i] = 0;
        printf("%8ld:%s\n", opensslLock_->cntList[i], CRYPTO_get_lock_name(i));
    }

    CRYPTO_THREADID_set_callback(&opensslThreadID_);
    CRYPTO_set_locking_callback(&opensslLockingCallback_);

    printf("OpenSSL lock setup done\n");

    return 1;
#else
    printf("Error: OpenSSL was not configured with thread support!\n");

    return 0;
#endif
}
/// \brief clean up OpenSSL locks
///
/// \return true succeeds
/// \return false fails
bool CryptoUtil::opensslLockCleanup()
{
#if defined(OPENSSL_THREADS)
    CRYPTO_set_locking_callback(NULL);

    printf("OpenSSL lock cleanup started\n");

    printf("cntList[i]:CRYPTO_get_lock_name(i)\n");
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(opensslLock_->lockList[i]));
        //printf("%8ld:%s\n", opensslLock_->cntList[i], CRYPTO_get_lock_name(i));
    }

    OPENSSL_free(opensslLock_->lockList);
    OPENSSL_free(opensslLock_->cntList);
    free(opensslLock_);

    printf("OpenSSL lock cleanup done\n");

    return 1;
#else
    printf("Error: OpenSSL was not configured with thread support!\n");

    return 0;
#endif
}

/// \brief Construct a new Crypto Util:: Crypto Util object
///
/// \param cryptoType the type of CryptoUtil

CryptoUtil::CryptoUtil(int cryptoType)
{
    cryptoType_ = cryptoType;
#if defined(OPENSSL_THREADS)
    /**check if opensslLockSetup() has been called to set up OpenSSL locks */
    if (opensslLock_ == NULL) {
        printf("Error: opensslLockSetup() was not called before initializing CryptoUtil instances\n");
        exit(1);
    }

    if (cryptoType_ == HIGH_SEC_PAIR_TYPE) {
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(&mdctx_);

        /**get the MVP_MD structure for SHA-256 */
        md_ = EVP_sha256();
        hashSize_ = 32;

        /**initializes cipher context cipherctx_*/
        EVP_CIPHER_CTX_init(&cipherctx_);

        /**get the EVP_CIPHER structure for AES-256 */
        cipher_ = EVP_aes_256_cbc();
        keySize_ = 32;
        blockSize_ = 16;

        /**allocate a constant IV*/
        iv_ = (unsigned char*)malloc(sizeof(unsigned char) * blockSize_);
        memset(iv_, 0, blockSize_);

        printf("\nA CryptoPrimitive based on a pair of SHA-256 and AES-256 has been constructed! \n");
        printf("Parameters: \n");
        printf("      hashSize_: %d \n", hashSize_);
        printf("      keySize_: %d \n", keySize_);
        printf("      blockSize_: %d \n", blockSize_);
        printf("\n");
    }

    if (cryptoType == LOW_SEC_PAIR_TYPE) {
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(&mdctx_);

        /**get the EVP_MD structure for MD5 */
        md_ = EVP_md5();
        hashSize_ = 16;

        /**get the EVP_CIPHER stucture for AES-128 */
        cipher_ = EVP_aes_128_cbc();
        keySize_ = 16;
        blockSize_ = 16;

        /**allocate a constant IV */
        iv_ = (unsigned char*)malloc(sizeof(unsigned char) * blockSize_);
        memset(iv_, 0, blockSize_);

        printf("\nA CryptoPrimitive based on a pair of MD5 and AES-128 has been constructed! \n");
        printf("Parameters: \n");
        printf("      hashSize_: %d \n", hashSize_);
        printf("      keySize_: %d \n", keySize_);
        printf("      blockSize_: %d \n", blockSize_);
        printf("\n");
    }

    if (cryptoType_ == SHA256_TYPE) {
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(&mdctx_);

        /**get the EVP_MD structure for SHA-256 */
        md_ = EVP_sha256();
        hashSize_ = 32;

        keySize_ = -1;
        blockSize_ = -1;

        printf("\nA CryptoPrimitive based on SHA-256 has been constructed! \n");
        printf("Parameters: \n");
        printf("      hashSize_: %d \n", hashSize_);
        printf("\n");
    }

    if (cryptoType_ == SHA1_TYPE) {
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(&mdctx_);

        /**get the EVP_MD structure for SHA-1 */
        md_ = EVP_sha1();
        hashSize_ = 20;

        keySize_ = -1;
        blockSize_ = -1;

        printf("\nA CryptoPrimitive based on SHA-1 has been constructed! \n");
        printf("Parameters: \n");
        printf("      hashSize_: %d \n", hashSize_);
        printf("\n");
    }

#else
    printf("Error: OpenSSL was not configured with thread support!\n");
    exit(1);
#endif
}

/// \brief Destroy the Crypto Util:: Crypto Util object
///
CryptoUtil::~CryptoUtil()
{
    if ((cryptoType_ == HIGH_SEC_PAIR_TYPE) || (cryptoType_ == LOW_SEC_PAIR_TYPE)) {
        /**clean up the digest context mdctx_ and free up the space allocated to it */
        EVP_MD_CTX_cleanup(&mdctx_);

        /**clean up the cipher context cipherctx_ and free up the space allocated to it */
        EVP_CIPHER_CTX_cleanup(&cipherctx_);
        free(iv_);
    }

    if ((cryptoType_ == SHA256_TYPE) || (cryptoType_ == SHA1_TYPE)) {
        /**clean up the digest context mdctx_ and free up the space allocated to it */
        EVP_MD_CTX_cleanup(&mdctx_);
    }

    printf("\nThe CryptoPrimitive has been destructed! \n");
    printf("\n");
}

/// \brief get the hash size
///
/// \return int the hash size
int CryptoUtil::getHashSize()
{
    return hashSize_;
}

/// \brief get the key size
///
/// \return int the key size
int CryptoUtil::getKeySize()
{
    return keySize_;
}

/// \brief get the size of encryption block unit
///
/// \return int the block size
int CryptoUtil::getBlockSize()
{
    return blockSize_;
}

/// \brief encrypt the data stored in a buffer with a key
///
/// \param dataBuffer the buffer storing the data
/// \param dataSize the size of the data
/// \param key the key used to encrypt the data
/// \param cipherText the generated ciphertext <return>
/// \return true encryption succeeds
/// \return false encryption fails

bool CryptoUtil::encryptWithKey(unsigned char* dataBuffer, const int& dataSize, unsigned char* key,
    unsigned char* cipherText)
{
    int cipherTextSize, cipherTextTailSize;

    if (dataSize % blockSize_ != 0) {
        printf("Error: the size of the input data (%d bytes) is not a multiple of that of encryption block unit (%d bytes)!\n",
            dataSize, blockSize_);
        return false;
    }
    //TODO: this part may be replaced new library
    EVP_EncryptInit_ex(&cipherctx_, cipher_, NULL, key, iv_);
    /*disable padding to ensure that the generated ciphertext has the same size as the input data*/
    EVP_CIPHER_CTX_set_padding(&cipherctx_, 0);
    EVP_EncryptUpdate(&cipherctx_, cipherText, &cipherTextSize, dataBuffer, dataSize);
    EVP_EncryptFinal_ex(&cipherctx_, cipherText + cipherTextSize, &cipherTextTailSize);
    cipherTextSize += cipherTextTailSize;

    if (cipherTextSize != dataSize) {
        printf("Error: the size of the cipher output (%d bytes) does not match with that of the input (%d bytes)!\n",
            cipherTextSize, dataSize);
        return false;
    }

    return true;
}

/// \brief generate the hash for the data stored in a buffer
///
/// \param dataBuffer the buffer that stores the data
/// \param dataSize the size of the data
/// \param hash the generated hash <return>
/// \return true generation succeeds
/// \return false generation fails

bool CryptoUtil::generateHash(unsigned char* dataBuffer, const int& dataSize, unsigned char* hash)
{
    int hashSize;

    EVP_DigestInit_ex(&mdctx_, md_, NULL);
    EVP_DigestUpdate(&mdctx_, dataBuffer, dataSize);
    EVP_DigestFinal_ex(&mdctx_, hash, (unsigned int*)&hashSize);

    if (hashSize != hashSize_) {
        printf("Error: the size of the generated hash (%d bytes) does not match with the expected one (%d bytes)!\n",
            hashSize, hashSize_);

        return false;
    }
    return true;
}

bool CryptoUtil::generateRandom(int randomSize, unsigned char* random)
{
    int ret = RAND_bytes(random, randomSize);
    if (ret != 1) {
        printf("error random\n");
        return false;
    } else
        return true;
}
