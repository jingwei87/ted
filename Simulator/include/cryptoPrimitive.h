/// \file cryptoPrimitive.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface related to cryptography 
/// \version 0.1
/// \date 2019-06-23
///
/// \copyright Copyright (c) 2019
///

#ifndef __CRYPTOPRIMITIVE_H__
#define __CRYPTOPRIMITIVE_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> /**for uint32)t */
#include <string.h>


/**for the use of OpenSSL */
#include <openssl/evp.h>
#include <openssl/crypto.h>
#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>

/**macro for OpenSSL debug */
#define OPENSLL_DEBUG 0
/**for the use of mutex lock */
#include <pthread.h>

/**macro for the type of a high secure pair of hash generation and encryption */
#define HIGH_SEC_PAIR_TYPE 0
/**macro for the type of a low secure pair of hash generation and encryption */
#define LOW_SEC_PAIR_TYPE 1
/**macro for the type of a SHA-256 hash generation */
#define SHA256_TYPE 2
/**macro for the type of a SHA-1 hash generation */
#define SHA1_TYPE 3

/**mark for openssl-1.1.x version */
#define OPENSSL_VERSION_1_1 

using namespace std;

typedef struct {
    pthread_mutex_t *lockList;
    long *cntList;
} opensslLock_t;


class CryptoPrimitive{
    private:
        /**the type of CryptoPrimitive */
        int cryptoType_;

        /**variable used in hash calculation */
        #if defined(OPENSSL_VERSION_1_1)
            EVP_MD_CTX *mdctx_ = EVP_MD_CTX_new();
        #else
            EVP_MD_CTX mdctx_;
        #endif
        const EVP_MD *md_;

        /**the size of the generated hash */
        int hashSize_;

        /**variable used in encryption */
        #if defined(OPENSSL_VERSION_1_1)
            EVP_CIPHER_CTX *cipherctx_ = EVP_CIPHER_CTX_new();
        #else
            EVP_CIPHER_CTX cipherctx_;
        #endif
        const EVP_CIPHER *cipher_;
        uint8_t *iv_;

        /**the size of the key for encryption */
        int keySize_;

        /**the size of the encryption block unit */
        int blockSize_;

        /**OpenSSL lock */
        static opensslLock_t *opensslLock_;

        /// \brief OpenSSL locking callback function
        ///
        /// \param mode 
        /// \param type 
        /// \param file 
        /// \param line 
        static void opensslLockingCallback_(int mode, int type, const char *file, int line);

        /// \brief get the id of the current thread
        ///
        /// \param id - the thread id <return>
        static void opensslThreadID_(CRYPTO_THREADID *id);

    public: 

        /// \brief Construct a new Crypto Primitive object
        ///
        /// \param cryptoType - the type of Crypto
        CryptoPrimitive(int cryptoType = HIGH_SEC_PAIR_TYPE);


        /// \brief Destroy the Crypto Primitive object
        ///
        ~CryptoPrimitive();

        /// \brief Set up OpenSSL locks
        /// 
        /// \return true - the setup succeeds
        /// \return false - the setup failures
        static bool opensslLockSetup();

        /// \brief clean up OpenSSL locks
        ///
        /// \return true - the cleanup succeeds
        /// \return false  - the cleanup failures
        static bool opensslLockCleanup();

        /// \brief Get the Hash Size object
        ///
        /// \return int - the hash size
        int inline getHashSize() {return hashSize_;}

        /// \brief Get the Key Size object
        ///
        /// \return int - the key size
        int inline getKeySize() {return keySize_;}

        /// \brief Get the Block Size object
        ///
        /// \return int - the block size
        int inline getBlockSize() {return blockSize_;}


        /// \brief generate the hash for the data stored in a buffer
        ///
        /// \param dataBuffer - the buffer that stores the data
        /// \param dataSize - the size of the data
        /// \param hash - the generated hash <return>
        /// \return true the hash generation succeeds
        /// \return false the hash generation fails
        bool generateHash(uint8_t *dataBuffer, const int &dataSize, uint8_t *hash);

        
        /// \brief encrypt the data stored in a buffer with a key
        ///
        /// \param dataBuffer - the buffer that stores the data 
        /// \param dataSize - the size of the data 
        /// \param key - the key used to encrypt the data
        /// \param ciphertext - the generated ciphertext <return>
        /// \return true - the encryption succeeds 
        /// \return false - the encryption fails
        bool encryptWithKey(uint8_t *dataBuffer, const int &dataSize, 
            uint8_t *key, uint8_t *ciphertext);

        /// \brief decrypt the data stored in a buffer with a key
        ///
        /// \param ciphertext - the buffer that stores the ciphertext
        /// \param dataSize - the size of the data
        /// \param key - the key used to decrypt the data
        /// \param dataBuffer - the original data <return>
        /// \return true - the decryption succeeds
        /// \return false - the decryption fails
        bool decryptWithKey(uint8_t* ciphertext, const int& dataSize, 
            uint8_t* key, uint8_t* dataBuffer);

};




#endif // __CRYPTOPRIMITIVE_H__