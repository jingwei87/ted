/// \file cryptoPrimitive.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement all the interfaces defined in cryptoPrimitive
/// \version 0.1
/// \date 2019-06-23
///
/// \copyright Copyright (c) 2019
///
#include "../../include/cryptoPrimitive.h"

using namespace std;

/**initialize the static variable */
opensslLock_t *CryptoPrimitive::opensslLock_ = NULL;

/// \brief OpenSSL locking callback function
///
/// \param mode 
/// \param type 
/// \param file 
/// \param line 
void CryptoPrimitive::opensslLockingCallback_(int mode, int type, const char *file, int line) {
#if OPENSLL_DEBUG
    CRYPTO_THREADID id;
    CRYPTO_THREADID_current(&id);
    /**file and line are the file number of the function setting the lock, 
    * They can be useful debugging
    */
    fprintf(stderr, "thread=%4ld, mode=%s, lock=%s, %s:%d\n", id.val, 
        (mode&CRYPTO_LOCK)?"l":"u", (type&CRYPTO_READ)?"r":"w", file, line);
#endif

    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(opensslLock_->lockList[type]));
        CryptoPrimitive::opensslLock_->cntList[type]++;
    } else {
        pthread_mutex_unlock(&(opensslLock_->lockList[type]));
    }

}


/// \brief get the id of the current thread
///
/// \param id - the thread id <return>
void CryptoPrimitive::opensslThreadID_(CRYPTO_THREADID *id) {
    CRYPTO_THREADID_set_numeric(id, pthread_self());
}


/// \brief Set up OpenSSL locks
/// 
/// \return true - the setup succeeds
/// \return false - the setup failures
bool CryptoPrimitive::opensslLockSetup() {
#if defined(OPENSSL_THREADS) 
    fprintf(stderr, "OpenSSL lock setup started\n");
    opensslLock_ = (opensslLock_t *) malloc(sizeof(opensslLock_t));
    opensslLock_->lockList = (pthread_mutex_t *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    opensslLock_->cntList = (long *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

    fprintf(stderr,"cntList[i]:CRYPTO_get_lock_name(i)\n");

    for (int i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(opensslLock_->lockList[i]), NULL);
		opensslLock_->cntList[i] = 0;
        
        #if defined(OPENSSL_VERSION_1_1)
		    // fprintf(stderr, "%8ld\n", opensslLock_->cntList[i]);
        #else
            // fprintf(stderr,"%8ld:%s\n", opensslLock_->cntList[i], CRYPTO_get_lock_name(i));
        #endif
	}

    CRYPTO_THREADID_set_callback(&opensslThreadID_);
	CRYPTO_set_locking_callback(&opensslLockingCallback_);

	fprintf(stderr,"OpenSSL lock setup done\n");

	return 1;
#else
    fprintf(stderr, "Error: OpenSSL was not configured with thread support!\n");	

	return 0;
#endif

}


/// \brief clean up OpenSSL locks
///
/// \return true - the cleanup succeeds
/// \return false  - the cleanup failures
bool CryptoPrimitive::opensslLockCleanup() {

#if defined(OPENSSL_THREADS)
    CRYPTO_set_locking_callback(NULL);
    fprintf(stderr,"OpenSSL lock cleanup started\n");

	fprintf(stderr,"cntList[i]:CRYPTO_get_lock_name(i)\n");
	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(opensslLock_->lockList[i]));
		// fprintf(stderr,"%8ld\n", opensslLock_->cntList[i]);
	}

	OPENSSL_free(opensslLock_->lockList);
	OPENSSL_free(opensslLock_->cntList);
	free(opensslLock_);

	fprintf(stderr,"OpenSSL lock cleanup done\n");

	return 1;
#else
    fprintf(stderr, "Error: OpenSSL was not configured with thread support!\n");	
	return 0;
#endif
}


/// \brief Construct a new Crypto Primitive object
///
/// \param cryptoType - the type of Crypto
CryptoPrimitive::CryptoPrimitive(int cryptoType) {
    cryptoType_ = cryptoType;
#if defined(OPENSSL_THREADS)
    /**check if opensslLockSetup() has been called to set up OpenSSL locks*/
	if (opensslLock_ == NULL) {	
		fprintf(stderr, "Error: opensslLockSetup() was not called before initializing CryptoPrimitive instances\n");				
		exit(1);		
	}

    if (cryptoType_ == HIGH_SEC_PAIR_TYPE) {
        /**allocate, initialize and return the digest context mdctx_ */
    #if defined(OPENSSL_VERSION_1_1)
        EVP_MD_CTX_init(mdctx_);
    #else
        EVP_MD_CTX_init(&mdctx_);
    #endif

        /**get the EVP_MD structure for SHA-256 */
        md_ = EVP_sha256();
        hashSize_ = 32;

        /**initializes cipher context cipherctx_ */
    #if defined(OPENSSL_VERSION_1_1)
        EVP_CIPHER_CTX_init(cipherctx_);
    #else 
        EVP_CIPHER_CTX_init(&cipherctx_);
    #endif

        /**get the EVP_CIPHER structure for AES-256 */
        cipher_ = EVP_aes_256_cbc();
        keySize_ = 32;
        blockSize_ = 16;

        /**allocate a constant IV */
        iv_ = (uint8_t*) malloc(sizeof(uint8_t) * blockSize_);
        memset(iv_, 0, blockSize_);

        fprintf(stderr, "\nA CryptoPrimitive based on a pair of SHA-256 and AES-256 has been constructed! \n");		
		fprintf(stderr, "Parameters: \n");			
		fprintf(stderr, "      hashSize_: %d \n", hashSize_);				
		fprintf(stderr, "      keySize_: %d \n", keySize_);			
		fprintf(stderr, "      blockSize_: %d \n", blockSize_);		
		fprintf(stderr, "\n");
    }

    if (cryptoType_ == LOW_SEC_PAIR_TYPE) {
        /**allocate, initialize and return the digest context mdctx_ */
    #if defined(OPENSSL_VERSION_1_1) 
        EVP_MD_CTX_init(mdctx_);
    #else
        EVP_MD_CTX_init(&mdctx_);
    #endif

        /**get the EVP_MD structure for MD5 */
        md_ = EVP_md5();
        hashSize_ =16;

        /**initializes cipher context cipherctx_ */
    #if defined(OPENSSL_VERSION_1_1)
        EVP_CIPHER_CTX_init(cipherctx_);
    #else
        EVP_CIPHER_CTX_init(&cipherctx_);
    #endif

        /**get the EVP_CIPHER structure for AES-128 */
        cipher_ = EVP_aes_128_cbc();
        keySize_ = 16;
        blockSize_ = 16;

        /**allocate a constant IV*/
        iv_ = (uint8_t*) malloc(sizeof(uint8_t) * blockSize_);
        memset(iv_, 0, blockSize_);

        fprintf(stderr, "\nA CryptoPrimitive based on a pair of MD5 and AES-128 has been constructed! \n");		
		fprintf(stderr, "Parameters: \n");			
		fprintf(stderr, "      hashSize_: %d \n", hashSize_);				
		fprintf(stderr, "      keySize_: %d \n", keySize_);			
		fprintf(stderr, "      blockSize_: %d \n", blockSize_);		
		fprintf(stderr, "\n");
    }

    if (cryptoType_ == SHA256_TYPE) {
        /**allocate, initialize and return the digest context mdctx_ */
    #if defined(OPENSSL_VERSION_1_1)
        EVP_MD_CTX_init(mdctx_);
    #else
        EVP_MD_CTX_init(&mdctx_);
    #endif

        /**get the EVP_MD structure for SHA-256 */
        md_ = EVP_sha256();
        hashSize_ = 32;

        keySize_ = -1;
        blockSize_ = -1;

        fprintf(stderr, "\nA CryptoPrimitive based on SHA-256 has been constructed! \n");		
		fprintf(stderr, "Parameters: \n");			
		fprintf(stderr, "      hashSize_: %d \n", hashSize_);	
		fprintf(stderr, "\n");
    }
    
    if (cryptoType_ == SHA1_TYPE) {
        /**allocate, initialize and return the digest context mdctx_ */
    #if defined(OPENSSL_VERSION_1_1)
        EVP_MD_CTX_init(mdctx_);
    #else 
        EVP_MD_CTX_init(&mdctx_);
    #endif

        /**get the EVP_MD structure for SHA-1 */
        md_ = EVP_sha1();
        hashSize_ = 20;

        keySize_ = -1;
        blockSize_ = -1;

        fprintf(stderr, "\nA CryptoPrimitive based on SHA-1 has been constructed! \n");		
		fprintf(stderr, "Parameters: \n");			
		fprintf(stderr, "      hashSize_: %d \n", hashSize_);		
		fprintf(stderr, "\n");
    }
#else
	fprintf(stderr, "Error: OpenSSL was not configured with thread support!\n");				
	exit(1);
#endif
}



/// \brief Destroy the Crypto Primitive object
///
CryptoPrimitive::~CryptoPrimitive() {
    if ((cryptoType_ == HIGH_SEC_PAIR_TYPE) || (cryptoType_ == LOW_SEC_PAIR_TYPE)) {
		
    #if defined(OPENSSL_VERSION_1_1)
        /*clean up the digest context mdctx_ and free up the space allocated to it*/
        EVP_MD_CTX_reset(mdctx_);
        /*clean up the cipher context cipherctx_ and free up the space allocated to it*/
        EVP_CIPHER_CTX_reset(cipherctx_);
        EVP_CIPHER_CTX_cleanup(cipherctx_);
        EVP_CIPHER_CTX_free(cipherctx_);
    #else
        /*clean up the digest context mdctx_ and free up the space allocated to it*/
        EVP_MD_CTX_cleanup(&mdctx_);
        /*clean up the cipher context cipherctx_ and free up the space allocated to it*/
		EVP_CIPHER_CTX_cleanup(&cipherctx_);
    #endif
		free(iv_);	
	}

	if ((cryptoType_ == SHA256_TYPE) || (cryptoType_ == SHA1_TYPE)) {
    #if defined(OPENSSL_VERSION_1_1)
        /*clean up the digest context mdctx_ and free up the space allocated to it*/
		EVP_MD_CTX_reset(mdctx_);
    #else
        /*clean up the digest context mdctx_ and free up the space allocated to it*/
		EVP_MD_CTX_cleanup(&mdctx_);
    #endif
	}
    fprintf(stderr, "\nThe CryptoPrimitive has been destructed! \n");
	fprintf(stderr, "\n");
}

/// \brief generate the hash for the data stored in a buffer
///
/// \param dataBuffer - the buffer that stores the data
/// \param dataSize - the size of the data
/// \param hash - the generated hash <return>
/// \return true the hash generation succeeds
/// \return false the hash generation fails
bool CryptoPrimitive::generateHash(uint8_t *dataBuffer, const int &dataSize, uint8_t *hash) {
    
    int hashSize;
#if defined(OPENSSL_VERSION_1_1)
    EVP_DigestInit_ex(mdctx_, md_, NULL);
    EVP_DigestUpdate(mdctx_, dataBuffer, dataSize);
    EVP_DigestFinal_ex(mdctx_, hash, (uint32_t*) &hashSize);

#else
    EVP_DigestInit_ex(&mdctx_, md_, NULL);
	EVP_DigestUpdate(&mdctx_, dataBuffer, dataSize);
	EVP_DigestFinal_ex(&mdctx_, hash, (uint32_t*) &hashSize);
#endif

    if (hashSize != hashSize_) {
        fprintf(stderr, "Error: the size of the generated hash (%d bytes) does not match with the expected one (%d bytes)!\n", 
				hashSize, hashSize_);
        return 0;
    }

    return 1;
}

/// \brief encrypt the data stored in a buffer with a key
///
/// \param dataBuffer - the buffer that stores the data 
/// \param dataSize - the size of the data 
/// \param key - the key used to encrypt the data
/// \param ciphertext - the generated ciphertext <return>
/// \return true - the encryption succeeds 
/// \return false - the encryption fails
bool CryptoPrimitive::encryptWithKey(uint8_t *dataBuffer, const int &dataSize, 
        uint8_t *key, uint8_t *ciphertext) {
    int ciphertextSize, ciphertextTailSize;

    if (dataSize % blockSize_ != 0) {
        fprintf(stderr, "Error: the size of the input data (%d bytes) is not \
            a multiple of that of encryption block unit (%d bytes)!\n",
            dataSize, blockSize_);

        return 0;
    }

#if defined(OPENSSL_VERSION_1_1)
    EVP_EncryptInit_ex(cipherctx_, cipher_, NULL, key, iv_);
    /*disable padding to ensure that the generated ciphertext has the same size as the input data*/
    EVP_CIPHER_CTX_set_padding(cipherctx_, 0);
    EVP_EncryptUpdate(cipherctx_, ciphertext, &ciphertextSize, dataBuffer, dataSize);
    EVP_EncryptFinal_ex(cipherctx_, ciphertext + ciphertextSize, &ciphertextTailSize);
#else
    EVP_EncryptInit_ex(&cipherctx_, cipher_, NULL, key, iv_);		
	/*disable padding to ensure that the generated ciphertext has the same size as the input data*/
	EVP_CIPHER_CTX_set_padding(&cipherctx_, 0);
	EVP_EncryptUpdate(&cipherctx_, ciphertext, &ciphertextSize, dataBuffer, dataSize);
	EVP_EncryptFinal_ex(&cipherctx_, ciphertext + ciphertextSize, &ciphertextTailSize);

#endif

    ciphertextSize += ciphertextTailSize;

    if (ciphertextSize != dataSize) {
        fprintf(stderr, "Error: the size of the cipher output (%d bytes) \
            does not match with that of the input (%d bytes)!\n",
            ciphertextSize, dataSize);
        return 0;
    }

    return 1;

}


/// \brief decrypt the data stored in a buffer with a key
///
/// \param ciphertext - the buffer that stores the ciphertext
/// \param dataSize - the size of the data
/// \param key - the key used to decrypt the data
/// \param dataBuffer - the original data <return>
/// \return true - the decryption succeeds
/// \return false - the decryption fails

bool CryptoPrimitive::decryptWithKey(uint8_t* ciphertext, const int& dataSize, uint8_t* key,
    uint8_t* dataBuffer)
{
    int plaintextSize, plaintextTailSize;

    if (dataSize % blockSize_ != 0) {
        fprintf(stderr, "Error: the size of the input data (%d bytes) is not a multiple of that of encryption block unit (%d bytes)!\n",
            dataSize, blockSize_);

        return 0;
    }
#if defined(OPENSSL_VERSION_1_1)
    EVP_DecryptInit_ex(cipherctx_, cipher_, NULL, key, iv_);
    EVP_CIPHER_CTX_set_padding(cipherctx_, 0);
    EVP_DecryptUpdate(cipherctx_, dataBuffer, &plaintextSize, ciphertext, dataSize);
    EVP_DecryptFinal_ex(cipherctx_, dataBuffer + plaintextSize, &plaintextTailSize);
#else
    EVP_DecryptInit_ex(&cipherctx_, cipher_, NULL, key, iv_);
    EVP_CIPHER_CTX_set_padding(&cipherctx_, 0);
    EVP_DecryptUpdate(&cipherctx_, dataBuffer, &plaintextSize, ciphertext, dataSize);
    EVP_DecryptFinal_ex(&cipherctx_, dataBuffer + plaintextSize, &plaintextTailSize);
#endif

    plaintextSize += plaintextTailSize;

    if (plaintextSize != dataSize) {
        fprintf(stderr, "Error: the size of the plaintext output (%d bytes) does not match with that of the original data (%d bytes)!\n",
            plaintextSize, dataSize);

        return 0;
    }

    return 1;
}
