//
// Created by tinoryj on 19-3-27.
//

#include "Rsss.h"

Rsss::Rsss(int n, int k, int r, CryptoPrimitive* cryptoUtil)
    : AbsSecretSharing(n, k, r, cryptoUtil)
{

    /*initialize the secret word size*/
    bytesPerSecretWord_ = cryptoUtil_->getHashSize();

    /*initialize the number of secret words per hash generation group and the
   * number of bytes per group*/
    secretWordsPerGroup_ = k_ - r_;
    bytesPerGroup_ = bytesPerSecretWord_ * secretWordsPerGroup_;

    /*allocate a buffer for storing the input of the hash function*/
    randomInputBuffer_ = (unsigned char*)malloc(bytesPerSecretWord_ * secretWordsPerGroup_ + 1);

    /*allocate some space for storing the r hashes*/
    rRandom_ = (unsigned char*)malloc(sizeof(unsigned char) * bytesPerSecretWord_ * r_);

    /*allocate some space for storing the aligned secret*/
    alignedSecretBufferSize_ = MAX_SECRET_SIZE + bytesPerSecretWord_ * secretWordsPerGroup_;
    alignedSecretBuffer_ = (unsigned char*)malloc(sizeof(unsigned char) * alignedSecretBufferSize_);

    /*allocate some space for storing k data blocks to be encoded by Rabin's
   * IDA*/
    erasureCodingDataSize_ = (bytesPerSecretWord_ * (alignedSecretBufferSize_ / (bytesPerSecretWord_ * secretWordsPerGroup_))) * k_;
    erasureCodingData_ = (unsigned char*)malloc(sizeof(unsigned char) * erasureCodingDataSize_);
}

bool Rsss::shareSecret(unsigned char* secretBuffer, int secretSize,
    unsigned char* shareBuffer, int* shareSize)
{
    int numOfGroups, alignedSecretSize;
    int i, j;

    /*align the secret size into alignedSecretSize*/
    if ((secretSize % bytesPerGroup_) == 0) {
        alignedSecretSize = secretSize;
    } else {
        alignedSecretSize = bytesPerGroup_ * ((secretSize / bytesPerGroup_) + 1);
    }
    if (alignedSecretBufferSize_ < alignedSecretSize) {
        printf("Error: please use an internal alignedSecretBuffer_[] of size >= "
                "%d bytes!\n", alignedSecretSize);
        return 0;
    }

    /*deduce the share size into shareSize*/
    // numOfGroups = alignedSecretSize / bytesPerSecretWord_;
    numOfGroups = alignedSecretSize / bytesPerGroup_;
    (*shareSize) = bytesPerSecretWord_ * numOfGroups;
    if (erasureCodingDataSize_ < (*shareSize) * k_) {
        printf("Error: please use an internal erasureCodingData_[] of size >= %d "
                "bytes!\n", (*shareSize) * k_);
        return 0;
    }

    /*copy the secret from secretBuffer to alignedSecretBuffer_*/
    memcpy(alignedSecretBuffer_, secretBuffer, secretSize);
    if (alignedSecretSize != secretSize) {
        if (DEBUG_OUTPUT) {
            printf("alignedSecretSize is larger than the size of secretSize panding remaining space with 0. \n"); 
            printf("padding remaining space: %d\n", (alignedSecretSize - secretSize));
        }
        memset(alignedSecretBuffer_ + secretSize, 0,
                alignedSecretSize - secretSize);
    }

    /*Step 1: generate r randoms from each group of k - r secret words, and
        append the k - r secret words and the r randoms to k different data blocks,
        respectively*/

    for (i = 0; i < numOfGroups; i++) {
        /*generate r hashes from the group of k - r secret words*/
        for (j = 0; j < r_; j++) {
            memcpy(randomInputBuffer_, alignedSecretBuffer_ + bytesPerGroup_ * i,
                bytesPerGroup_);
            /*add a constant seed for imitating a different random function*/
            randomInputBuffer_[bytesPerSecretWord_] = (unsigned char)j;

            if (!cryptoUtil_->generateRandom(bytesPerSecretWord_,
                    rRandom_ + bytesPerSecretWord_ * j)) {
                printf("Error: fail in the hash calculation!\n");
                return 0;
            }
        }

        /*append the k - r secret words to k - r different data blocks,
        * respectively*/
        for (j = 0; j < secretWordsPerGroup_; j++) {
            memcpy(erasureCodingData_ + (*shareSize) * j + bytesPerSecretWord_ * i,
                alignedSecretBuffer_ + bytesPerGroup_ * i + bytesPerSecretWord_ * j,
                bytesPerSecretWord_);
        }

        /*append the r randomes to other r different data blocks, respectively*/
        for (j = 0; j < r_; j++) {
            memcpy(erasureCodingData_ + (*shareSize) * (secretWordsPerGroup_ + j) + bytesPerSecretWord_ * i,
                rRandom_ + bytesPerSecretWord_ * j, bytesPerSecretWord_);
        }
    }

    /*Step 2: encode the k data blocks of size shareSize into n shares using
   * Rabin's IDA*/
    rsUtil_->reEncoding(erasureCodingData_, shareBuffer, shareSize);
    /*
    for (i = 0; i < n_; i++) {
        for (j = 0; j < k_; j++) {
            coef = rsUtil_->getDistributionMatrix()[k_ * i + j];
            gf_t gfTemp = rsUtil_->getGFObject();
            if (j == 0) {
                rsUtil_->getGFObject().multiply_region.w32(
                    &gfTemp, erasureCodingData_ + (*shareSize) * j,
                    shareBuffer + (*shareSize) * i, coef, (*shareSize), 0);
            } else {
                rsUtil_->getGFObject().multiply_region.w32(
                    &gfTemp, erasureCodingData_ + (*shareSize) * j,
                    shareBuffer + (*shareSize) * i, coef, (*shareSize), 1);
            }
        }
    }
    */
    return 1;
}

bool Rsss::reconstructSecret(unsigned char* shareBuffer, int shareSize,
    int* shareIDList, unsigned char* secretBuffer,
    int secretSize)
{
    int numOfGroups, alignedSecretSize;
    int i, j;

    if ((shareSize % bytesPerSecretWord_) != 0) {
        fprintf(stderr,
            "Error: the share size (i.e. %d bytes) should be a multiple of "
            "secret word size (i.e. %d bytes)!\n",
            shareSize, bytesPerSecretWord_);

        return 0;
    }
    if (erasureCodingDataSize_ < shareSize * k_) {
        fprintf(stderr,
            "Error: please use an internal erasureCodingData_[] of size >= %d "
            "bytes!\n",
            shareSize * k_);

        return 0;
    }

    numOfGroups = shareSize / bytesPerSecretWord_;
    alignedSecretSize = bytesPerSecretWord_ * numOfGroups;
    if (alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr,
            "Error: please use an internal alignedSecretBuffer_[] of size >= "
            "%d bytes!\n",
            alignedSecretSize);

        return 0;
    }
    if (secretSize > alignedSecretSize) {
        fprintf(stderr,
            "Error: the input secret size (%d bytes) cannot exceed %d bytes!\n",
            secretSize, alignedSecretSize);

        return 0;
    }

    /*store the k rows (corresponding to the k shares) of the distribution matrix
   * into squareMatrix_*/

    rsUtil_->storeKRowsMatrix(shareIDList);
    /*
    for (i = 0; i < k_; i++) {
        for (j = 0; j < k_; j++) {
            rsUtil_->getSquareMatrix()[k_ * i + j] = rsUtil_->getDistributionMatrix()[k_ * shareIDList[i] + j];
        }
    }
    */
    /*invert squareMatrix_ into inverseMatrix_*/
    if (!rsUtil_->squareMatrixInverting()) {
        fprintf(stderr, "Error: a k * k submatrix of the distribution matrix is "
                        "noninvertible!\n");

        return 0;
    }

    /*perform IDA decoding*/
    rsUtil_->rsDecoding(shareBuffer, erasureCodingData_, shareSize);
    /*
    for (i = 0; i < k_; i++) {
        for (j = 0; j < k_; j++) {
            coef = rsUtil_->getInverseMatrix()[k_ * i + j];
            gf_t gfTemp = rsUtil_->getGFObject();
            if (j == 0) {
                rsUtil_->getGFObject().multiply_region.w32(
                    &gfTemp, shareBuffer + shareSize * j,
                    erasureCodingData_ + shareSize * i, coef, shareSize, 0);
            } else {
                rsUtil_->getGFObject().multiply_region.w32(
                    &gfTemp, shareBuffer + shareSize * j,
                    erasureCodingData_ + shareSize * i, coef, shareSize, 1);
            }
        }
    }
    */
    /*restore the secret*/
    for (i = 0; i < numOfGroups; i++) {
        /*copy the group of k - r secret words from erasureCodingData_ to
     * alignedSecretBuffer_*/
        for (j = 0; j < secretWordsPerGroup_; j++) {
            memcpy(alignedSecretBuffer_ + bytesPerSecretWord_ * i + bytesPerSecretWord_ * j,
                erasureCodingData_ + shareSize * j + bytesPerSecretWord_ * i,
                bytesPerSecretWord_);
        }
    }

    memcpy(secretBuffer, alignedSecretBuffer_, secretSize);

    return 1;
}

