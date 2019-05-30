//
// Created by tinoryj on 19-3-27.
//

#include "CRsss.h"

CRsss::CRsss(int n, int k, int r, CryptoPrimitive* cryptoUtil)
    : Rsss(n, k, r, cryptoUtil)
{
    cryptoUtil_ = cryptoUtil;
    n_ = n;
    k_ = k;
    r_ = r;
    bytesPerSecretWord_ = cryptoUtil_->getHashSize();
    secretWordsPerGroup_ = k_ - r_;
    bytesPerGroup_ = bytesPerSecretWord_ * secretWordsPerGroup_;
    /*allocate a buffer for storing the input of the hash function*/
    hashInputBuffer_ = (unsigned char*)malloc(bytesPerSecretWord_ * secretWordsPerGroup_ + 1);
    /*allocate some space for storing the r hashes*/
    rHashes_ = (unsigned char*)malloc(sizeof(unsigned char) * bytesPerSecretWord_ * r_);
}

bool CRsss::shareSecret(unsigned char* secretBuffer, int secretSize,
    unsigned char* shareBuffer, int* shareSize)
{
    int numOfGroups, alignedSecretSize;
    int i, j;

    /*align the secret size into alignedSecretSize*/
    if ((secretSize % bytesPerSecretWord_) == 0) {
        alignedSecretSize = secretSize;
    } else {
        alignedSecretSize = bytesPerSecretWord_ * ((secretSize / bytesPerSecretWord_) + 1);
    }
    if (alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr,
            "Error: please use an internal alignedSecretBuffer_[] of size >= "
            "%d bytes!\n",
            alignedSecretSize);

        return 0;
    }

    /*deduce the share size into shareSize*/
    numOfGroups = alignedSecretSize / bytesPerSecretWord_;
    (*shareSize) = bytesPerSecretWord_ * numOfGroups;
    if (erasureCodingDataSize_ < (*shareSize) * k_) {
        fprintf(stderr,
            "Error: please use an internal erasureCodingData_[] of size >= %d "
            "bytes!\n",
            (*shareSize) * k_);

        return 0;
    }

    /*copy the secret from secretBuffer to alignedSecretBuffer_*/
    memcpy(alignedSecretBuffer_, secretBuffer, secretSize);
    if (alignedSecretSize != secretSize) {
        memset(alignedSecretBuffer_ + secretSize, 0,
            alignedSecretSize - secretSize);
    }

    /*Step 1: generate r hashes from each group of k - r secret words, and
  append the k - r secret words and the r hashes to k different data blocks,
  respectively*/

    for (i = 0; i < numOfGroups; i++) {
        /*generate r hashes from the group of k - r secret words*/
        for (j = 0; j < r_; j++) {
            memcpy(hashInputBuffer_, alignedSecretBuffer_ + bytesPerSecretWord_ * i,
                bytesPerSecretWord_);
            /*add a constant seed for imitating a different hash function*/
            hashInputBuffer_[bytesPerSecretWord_] = (unsigned char)j;

            if (!cryptoUtil_->generateHash(hashInputBuffer_, bytesPerSecretWord_ + 1,
                    rHashes_ + bytesPerSecretWord_ * j)) {
                fprintf(stderr, "Error: fail in the hash calculation!\n");

                return 0;
            }
        }

        /*append the k - r secret words to k - r different data blocks,
     * respectively*/
        for (j = 0; j < secretWordsPerGroup_; j++) {
            memcpy(erasureCodingData_ + (*shareSize) * j + bytesPerSecretWord_ * i,
                alignedSecretBuffer_ + bytesPerSecretWord_ * i + bytesPerSecretWord_ * j,
                bytesPerSecretWord_);
        }

        /*append the r hashes to other r different data blocks, respectively*/
        for (j = 0; j < r_; j++) {
            memcpy(erasureCodingData_ + (*shareSize) * (secretWordsPerGroup_ + j) + bytesPerSecretWord_ * i,
                rHashes_ + bytesPerSecretWord_ * j, bytesPerSecretWord_);
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

bool CRsss::reconstructSecret(unsigned char* shareBuffer, int shareSize,
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

    /*check the integrity of each group of k - r secret words using the
   * corresponding r hashes, and also restore the secret*/
    for (i = 0; i < numOfGroups; i++) {
        /*copy the group of k - r secret words from erasureCodingData_ to
     * alignedSecretBuffer_*/
        for (j = 0; j < secretWordsPerGroup_; j++) {
            memcpy(alignedSecretBuffer_ + bytesPerSecretWord_ * i + bytesPerSecretWord_ * j,
                erasureCodingData_ + shareSize * j + bytesPerSecretWord_ * i,
                bytesPerSecretWord_);
        }

        /*generate r hashes from the group of k - r secret words, and then compare
     * them with the stored ones, respectively*/
        for (j = 0; j < r_; j++) {
            /*generate the hash from the group of the k - r secret words*/
            memcpy(hashInputBuffer_, alignedSecretBuffer_ + bytesPerSecretWord_ * i,
                bytesPerSecretWord_);
            /*add a constant seed for imitating a different hash function*/
            hashInputBuffer_[bytesPerSecretWord_] = (unsigned char)j;
            if (!cryptoUtil_->generateHash(hashInputBuffer_, bytesPerSecretWord_ + 1,
                    rHashes_ + bytesPerSecretWord_ * j)) {
                fprintf(stderr, "Error: fail in the hash calculation!\n");

                return 0;
            }

            /*check if the generated hash is the same as the stored hash*/
            if (memcmp(erasureCodingData_ + shareSize * (secretWordsPerGroup_ + j) + bytesPerSecretWord_ * i,
                    rHashes_ + bytesPerSecretWord_ * j,
                    bytesPerSecretWord_)
                != 0) {
                fprintf(stderr, "Error: fail in integrity checking!\n");

                return 0;
            }
        }
    }

    memcpy(secretBuffer, alignedSecretBuffer_, secretSize);

    return 1;
}
