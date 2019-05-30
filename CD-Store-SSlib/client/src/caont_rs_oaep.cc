/// \file caont_rs_oaep.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the API of CaontRSOAEP
/// \version 0.1
/// \date 2019-03-23
///
/// \copyright Copyright (c) 2019
///

#include "caont_rs_oaep.h"

/// \brief Construct a new Caont-RS object
///
/// \param n the total number of shares
/// \param k minimum number of shares for successful reconstruction
/// \param r maximum number of shares that leak nothing about original secret
/// \param cryptoUtil the pointer to the cryptoUtil
CaontRSOAEP::CaontRSOAEP(int n, int k, int r, CryptoPrimitive* cryptoUtil)
    : AontRS(n, k, r, cryptoUtil)
{
    alignedSizeConstant_ = (unsigned char*)malloc(sizeof(unsigned char) * alignedSecretBufferSize_);
    for (int i = 0; i < alignedSecretBufferSize_; i++) {
        alignedSizeConstant_[i] = i & 0xff;
    }
}

/// \brief Destroy the Caont-RS object
///
CaontRSOAEP::~CaontRSOAEP()
{
    free(alignedSizeConstant_);
}

/// \brief Share encode a secret via AONT-RS
///
/// \param secretBuffer a buffer that stores the input secret
/// \param secretSize the size of the input secret
/// \param shareBuffer a buffer that stores all output shares
/// \param shareSize the size of each output share
///
/// \return true if succeed and false otherwise
bool CaontRSOAEP::shareSecret(unsigned char* secretBuffer, int secretSize, unsigned char* shareBuffer, int* shareSize)
{
    if (DEBUG_OUTPUT) {
        printf("Start to generate shares by using CAONT-RS-OAEP.\n");
    }
    int alignedSecretSize;

    /*align the secret size into alignedSecretSize*/
    /**Requirement: (alignedSecretSize + keySize)
     * can be divided by (k * bytesPerSecretWord)
     */

    if (((secretSize + bytesPerSecretWord_) % (bytesPerSecretWord_ * k_)) == 0) {
        alignedSecretSize = secretSize;
    } else {
        alignedSecretSize = (bytesPerSecretWord_ * k_) * (((secretSize + bytesPerSecretWord_) / (bytesPerSecretWord_ * k_)) + 1) - bytesPerSecretWord_;
    }
    if (alignedSecretBufferSize_ < alignedSecretSize) {
        if (DEBUG_OUTPUT) {
            printf("Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes.\n", alignedSecretSize);
        }
        return false;
    }

    /**deduce the share size into shareSize */
    (*shareSize) = bytesPerSecretWord_ * (((alignedSecretSize / bytesPerSecretWord_) + 1) / k_);

    if (DEBUG_OUTPUT) {
        printf("alignedSecretSize = %d\n", alignedSecretSize);
        printf("bytesPerSecretWord = %d\n",
            bytesPerSecretWord_);
        printf("numOfSecretWords = %d\n",
            (alignedSecretSize / bytesPerSecretWord_));
    }

    /**copy the secret from secretBuffer to alignedSecretBuffer */
    memcpy(alignedSecretBuffer_, secretBuffer, secretSize);
    if (alignedSecretSize != secretSize) {

        if (DEBUG_OUTPUT) {
            printf("alignedSecretSize is larger than the size of secretSize panding remaining space with 0. \n");
            printf("padding remaining space: %d\n", (alignedSecretSize - secretSize));
        }

        memset(alignedSecretBuffer_ + secretSize, 0, alignedSecretSize - secretSize);
    }
    /**
     * Step 1:
     * Start to generate the CAONT package from the secret, and store it into erasureCodingData_
     * 
     * Substep 1:
     * Generate the hash h_{key}
     */
    /**generate a hash key from the original aligned secret*/
    if (!cryptoUtil_->generateHash(alignedSecretBuffer_, alignedSecretSize, key_)) {
        printf("Error: the hash calculation fails.\n");
        return false;
    }

    /**encryption alignedSizeConstant_ of size alignedSecretSize with the hash key
     * and temporarily store the ciphertext into erasureCodingData
     */
    if (!cryptoUtil_->encryptWithKey(alignedSizeConstant_, alignedSecretSize, key_, erasureCodingData_)) {
        printf("Error: the data encryption fails.\n");
        return false;
    }

    /**
     * Substep 2: generate the main part of the CAONT package is obtained by XORing the ciphertext with the aligned secret
     */
    rsUtil_->addXOR(erasureCodingData_, alignedSecretBuffer_, alignedSecretSize);

    /**
     * Substep 3: generate the tail part of the CAONT package, 
     * and store it into erasureCodingData_
     */

    if (!cryptoUtil_->generateHash(erasureCodingData_, alignedSecretSize, erasureCodingData_ + alignedSecretSize)) {
        printf("Error: Hash generation fails! (Sharing).\n");

        return false;
    }

    rsUtil_->addXOR(erasureCodingData_ + alignedSecretSize, key_, bytesPerSecretWord_);

    /*directly copy the AONT package from erasureCodingData_ to shareBuffer as the first k shares*/
    memcpy(shareBuffer, erasureCodingData_, alignedSecretSize + bytesPerSecretWord_);

    /**Since using systematic EC, it only needs to generate only the last m shares from AONT package*/
    if (!rsUtil_->reEncoding(erasureCodingData_, shareBuffer, shareSize)) {
        printf("Error: Encoding fails.\n");
        exit(1);
    }
    return true;
}

/// \brief Reconstrct recover the original secret from AONT-RS shares
///
/// \param shareBuffer a buffer that stores the input shares
/// \param shareSize the size of each share
/// \param shareIDList a list of share IDs
/// \param secretBuffer a buffer that stores the output secret
/// \param secretSize the size of recovered secret
///
/// \return true if succeed and false otherwise
bool CaontRSOAEP::reconstructSecret(unsigned char* shareBuffer, int shareSize, int* shareIDList, unsigned char* secretBuffer, int secretSize)
{
    if (DEBUG_OUTPUT) {
        printf("Start ti restore the secret by using CAONT-RS-OAEP.\n");
    }
    int alignedSecretSize;

    if ((shareSize % bytesPerSecretWord_) != 0) {
        printf("Error: the share size (i.e. %d bytes) should be a multiple of secret word size (i.e. %d bytes)!\n",
            shareSize, bytesPerSecretWord_);

        return false;
    }

    if (erasureCodingDataSize_ < shareSize * k_) {
        printf("Error: please use an internal erasureCodingData_[] of size >= %d bytes!\n",
            shareSize * k_);
        return false;
    }

    alignedSecretSize = shareSize * k_ - bytesPerSecretWord_;

    if (alignedSecretBufferSize_ < alignedSecretSize) {
        printf("Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n", alignedSecretSize);

        return false;
    }

    if (secretSize > alignedSecretSize) {
        printf("Error: the input secret size (%d bytes) cannot exceed %d bytes!\n", secretSize, alignedSecretSize);

        return false;
    }

    /**store the k rows (corresponding to the k shares) of the distribution matrix into squareMatrix*/
    //TODO: Move this to RSUtil
    rsUtil_->storeKRowsMatrix(shareIDList);
    /**invert squareMatrix_ into inverseMatrix_ */
    //TODO: Move this to RSUtil
    if (!rsUtil_->squareMatrixInverting()) {
        printf("Error: Decoding Matrix generation fails.\n");
        return false;
    }

    /**perform RS decoding and obtain the CAONT package in erasureCodingData_ */
    //TODO: Move this to RSUtil
    if (!rsUtil_->rsDecoding(shareBuffer, erasureCodingData_, secretSize)) {
        printf("Error: Decoding fails.\n");
        return false;
    }

    /**generate a hash from the main part of the CAONT package, and temporarily store it into key*/
    if (!cryptoUtil_->generateHash(erasureCodingData_, alignedSecretSize, key_)) {
        printf("Error: Hash generation fails (restoring).\n");
        return false;
    }

    /**the key later used for encryption is obtained by XORing the generated hash with the last AONT word */
    rsUtil_->addXOR(key_, erasureCodingData_ + alignedSecretSize, bytesPerSecretWord_);

    /**encrypt alignedSizeConstant_ of size alignedSecretSize with the key, and 
      temporarily store the ciphertext into alignedSecretBuffer*/
    if (!cryptoUtil_->encryptWithKey(alignedSizeConstant_, alignedSecretSize, key_, alignedSecretBuffer_)) {
        printf("Encryption fails (restoring).\n");

        return false;
    }

    /**the aligned secret is obtained by XORing the ciphertext with the main part of the CAONT package stored in erasureCodingData_*/

    rsUtil_->addXOR(alignedSecretBuffer_, erasureCodingData_, alignedSecretSize);

    /**generate a hash from the aligned secret, and temporarily store it in the front end of erasureCodingData_*/

    if (!cryptoUtil_->generateHash(alignedSecretBuffer_, alignedSecretSize, erasureCodingData_)) {
        printf("Error: fail in the hash calculation!\n");

        return false;
    }

    /**check if the generated hash is the same as the previous used key*/

    if (memcmp(erasureCodingData_, key_, bytesPerSecretWord_) != 0) {
        printf("Error: fail in integrity checking!\n");

        return 0;
    }

    memcpy(secretBuffer, alignedSecretBuffer_, secretSize);

    return true;
}
