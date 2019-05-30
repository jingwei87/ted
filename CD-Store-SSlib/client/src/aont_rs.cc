/// \file aont_rs.cpp
/// \brief implementation of AONT-RS
/// \author Jingwei Li, lijw1987@gmail.com
/// \version 0.1
/// \date 2019-03-13

#include "aont_rs.h"

/// \brief AontRS initialize parameters for AONT-RS
///
/// \param n total number of shares
/// \param k minimum number of shares for successful reconstruction
/// \param r maximum number of shares that leak nothing about original secret
/// \param cryptoUtil the pointer to the cyrptoUtil
AontRS::AontRS(int n, int k, int r, CryptoPrimitive* cryptoUtil)
    : AbsSecretSharing(n, k, r, cryptoUtil)
{
    if (n_ <= 0) {
        printf("Error: n should be > 0!\n");
        exit(1);
    }
    if ((m_ <= 0) || (m_ >= n_)) {
        printf("Error: m should be in (0, n)!\n");
        exit(1);
    }
    if (n_ - m_ <= 1) {
        printf("Error: k = n -m should be > 1 for further providing confidentiality!\n");
        exit(1);
    }
    if (r_ != n_ - m_ - 1) {
        printf("Error: r should be = n - m - 1!\n");
        exit(1);
    }

    if (cryptoUtil_->getHashSize() == cryptoUtil->getKeySize()) {
        bytesPerSecretWord_ = cryptoUtil->getHashSize();
    } else {
        printf("Error: the hash size is not equal to the key size in the input cryptoUtil instance.\n");
        exit(1);
    }

    /**allocate the space for key == bytesPerSecretWord_ */
    key_ = (unsigned char*)malloc(sizeof(unsigned char) * bytesPerSecretWord_);

    /**allocate some space for storing the aligned secret */
    alignedSecretBufferSize_ = MAX_SECRET_SIZE + bytesPerSecretWord_ * k_;
    alignedSecretBuffer_ = (unsigned char*)malloc(sizeof(unsigned char) * alignedSecretBufferSize_);

    /**allocate a word of size bytesPerSecretWord_ for storing an index*/
    wordForIndex_ = (unsigned char*)malloc(sizeof(unsigned char) * bytesPerSecretWord_);
    memset(wordForIndex_, 0, bytesPerSecretWord_);

    /**allocate some space for storing k data blocks to be encoded by systematic Cauchy RS code*/
    erasureCodingDataSize_ = (bytesPerSecretWord_ * (((alignedSecretBufferSize_ / bytesPerSecretWord_) + 1) / k_)) * k_;
    erasureCodingData_ = (unsigned char*)malloc(sizeof(unsigned char) * erasureCodingDataSize_);

    if (DEBUG_OUTPUT) {
        rsUtil_->printMtr();
        printf("The initialization of AONT-RS is finished.\n");
        printf("erasureCodingDataSize = %d\n", erasureCodingDataSize_);
        printf("alignedSecretBufferSize = %d\n", alignedSecretBufferSize_);
    }
}

/// \brief Share encode a secret via AONT-RS
///
/// \param secretBuffer a buffer that stores the input secret
/// \param secretSize the size of the input secret
/// \param shareBuffer a buffer that stores all output shares
/// \param shareSize the size of each output share <return>
///
/// \return true if succeed and false otherwise
bool AontRS::shareSecret(unsigned char* secretBuffer, int secretSize,
    unsigned char* shareBuffer, int* shareSize)
{

    if (DEBUG_OUTPUT) {
        printf("Start to generate shares by using AONT-RS.\n");
    }
    int alignedSecretSize, numOfSecretWords;

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
    numOfSecretWords = alignedSecretSize / bytesPerSecretWord_;
    (*shareSize) = bytesPerSecretWord_ * ((numOfSecretWords + 1) / k_);

    if (DEBUG_OUTPUT) {
        printf("alignedSecretSize = %d\n", alignedSecretSize);
        printf("bytesPerSecretWord = %d\n", bytesPerSecretWord_);
        printf("numOfSecretWords = %d\n", numOfSecretWords);
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
     * Start to generate the AONT package 
     * including:
     * a. numOfSecretWords for "original secret"
     * b. one word for (key XOR hash)  
     * 
     * Substep 1: 
     *  Encrypt the index with a random key: E(K, i)
     * Substep 2:
     *  Generate the AONT word: (secret word) XOR (E(K, i)) 
     * 
     * Then, store it into erasureCodingData_
     */

    /**generate a random key */
    srand48(time(0));
    for (int i = 0; i < bytesPerSecretWord_; i++) {
        key_[i] = lrand48() % 256;
    }

    for (int i = 0; i < numOfSecretWords; i++) {

        /**store the index i into wordForIndex_ */

        wordForIndex_[0] = (unsigned char)i;
        wordForIndex_[1] = (unsigned char)(i >> 8);
        wordForIndex_[2] = (unsigned char)(i >> 16);
        wordForIndex_[3] = (unsigned char)(i >> 24);

        /**Substep 1: encrypt the index i with the random key, 
          * and store the cipher text in erasureCodingData_
          */
        if (!cryptoUtil_->encryptWithKey(wordForIndex_, bytesPerSecretWord_, key_,
                erasureCodingData_ + bytesPerSecretWord_ * i)) {
            printf("Error: Encryption fails! (Sharing).\n");
            return false;
        }
        /**Substep 2: generate the AONT word by XORing the ciphertext with the 
         * secret word
        */
        rsUtil_->addXOR(erasureCodingData_ + bytesPerSecretWord_ * i,
            alignedSecretBuffer_ + bytesPerSecretWord_ * i, bytesPerSecretWord_);
    }
    /**for the last AONT word, it is generated by XORing the hash with previous random key for encryption*/
    if (!cryptoUtil_->generateHash(erasureCodingData_, alignedSecretSize, erasureCodingData_ + alignedSecretSize)) {
        printf("Error: Hash generation fails! (Sharing).\n");

        return false;
    }

    rsUtil_->addXOR(erasureCodingData_ + alignedSecretSize, key_, bytesPerSecretWord_);

    /**
     * Step 2:
     * Start to generate the n shares from the AONT packet using
     * systematic RS code
     */

    /*directly copy the AONT package from erasureCodingData_ to shareBuffer as the first k shares*/
    memcpy(shareBuffer, erasureCodingData_, alignedSecretSize + bytesPerSecretWord_);

    //TODO: Since using systematic EC, it only needs to generate only the last m shares from AONT package
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
bool AontRS::reconstructSecret(unsigned char* shareBuffer, int shareSize, int* shareIDList, unsigned char* secretBuffer, int secretSize)
{
    int alignedSecretSize, numOfSecretWords;
    int i;

    if (DEBUG_OUTPUT) {
        printf("Start to restore the secret by using AONT-RS.\n");
    }

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
    numOfSecretWords = alignedSecretSize / bytesPerSecretWord_;

    if (alignedSecretBufferSize_ < alignedSecretSize) {
        printf("Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n",
            alignedSecretSize);
        return false;
    }

    if (secretSize > alignedSecretSize) {
        printf("Error: the input secret size (%d bytes) cannot exceed %d bytes!\n",
            secretSize, alignedSecretSize);
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

    /**perform RS decoding and obtain the AONT package in erasureCodingData_ */
    //TODO: Move this to RSUtil
    if (!rsUtil_->rsDecoding(shareBuffer, erasureCodingData_, secretSize)) {
        printf("Error: Decoding fails.\n");
        return false;
    }

    /**generate a hash from the first numOfSecretWords AONT words, and temporarily store it into key_*/
    if (!cryptoUtil_->generateHash(erasureCodingData_, alignedSecretSize, key_)) {
        printf("Error: Hash generation fails (restoring).\n");
        return false;
    }

    /**the key later used for encryption is obtained by XORing the generated hash with the last AONT word */
    rsUtil_->addXOR(key_, erasureCodingData_ + alignedSecretSize, bytesPerSecretWord_);

    /**generate each of the numOfSecretWords aligned secret words, and store it into alignedSecretBuffer_ */
    for (i = 0; i < numOfSecretWords; i++) {
        /**store the index i into wordForIndex_*/
        wordForIndex_[0] = (unsigned char)i;
        wordForIndex_[1] = (unsigned char)(i >> 8);
        wordForIndex_[2] = (unsigned char)(i >> 16);
        wordForIndex_[3] = (unsigned char)(i >> 24);

        /*encrypt the index i with the key, and temporarily store the cipherText in alignedSecretBuffer_*/
        if (!cryptoUtil_->encryptWithKey(wordForIndex_, bytesPerSecretWord_, key_, alignedSecretBuffer_ + bytesPerSecretWord_ * i)) {
            printf("Error: Encryption fails (restoring).\n");
            return false;
        }

        /**the aligned secret word is obtained by XORing the ciphertext with the AONT word*/
        rsUtil_->addXOR(alignedSecretBuffer_ + bytesPerSecretWord_ * i,
            erasureCodingData_ + bytesPerSecretWord_ * i, bytesPerSecretWord_);
    }

    memcpy(secretBuffer, alignedSecretBuffer_, secretSize);

    return true;
}
