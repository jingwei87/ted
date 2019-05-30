/// \file RSUtil.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interface of RSUtil
/// \version 0.1
/// \date 2019-03-15
///
/// \copyright Copyright (c) 2019
///

#include "RSUtil.h"
#define ULL unsigned long long

RSUtil::RSUtil(int ecK, int ecN)
    : ecK_(ecK)
    , ecN_(ecN)
{

    ecM_ = ecN_ - ecK_;
    /**8 bites for the use of GF(256) */
    bitsPerGFWord_ = 8;
    if (!gf_init_easy(&gfObj_, bitsPerGFWord_)) {
        printf("Error: gfobj initilization fails.\n");
        exit(1);
    }
    /**Initialize the distribution matrix*/
    distributionMatrix_ = (int*)malloc(sizeof(int) * ecN_ * ecK_);

    /**first k rows is a ecK * ecK identical matrix */
    for (int i = 0; i < ecK_; i++) {
        for (int j = 0; j < ecK_; j++) {
            if (i == j) {
                distributionMatrix_[ecK_ * i + j] = 1;
            } else {
                distributionMatrix_[ecK_ * i + j] = 0;
            }
        }
    }

    /**last ecM_ rows is a ecM_ * ecK Cauchy matrix*/
    int sum;
    for (int i = 0; i < ecM_; i++) {
        for (int j = 0; j < ecK_; j++) {
            sum = i ^ (ecM_ + j);
            distributionMatrix_[(ecK_ + i) * ecK_ + j] = gfObj_.divide.w32(&gfObj_, 1, sum);
        }
    }

    /**allocate two ecK_ * ecK_ matrices for decoding */
    squareMatrix_ = (int*)malloc(sizeof(int) * ecK_ * ecK_);
    inverseMatrix_ = (int*)malloc(sizeof(int) * ecK_ * ecK_);

    printf("The RSUtil construction is done with K = %d, N = %d.\n", ecK_, ecN_);
}

/// \brief execute XOR for dst buffer and src buffer (here we suppose length is a multiple of sizeof(unsigned long long)
///
/// \param dst store the XOR result of two buffers <return>
/// \param src store the buf of source data
/// \param length the size of data involved in this XOR operation

void RSUtil::addXOR(unsigned char* dst, unsigned char* src, int length)
{
    ULL* ldst = (ULL*)dst;
    ULL* lsrc = (ULL*)src;
    size_t i = 0;
    size_t llen = length / sizeof(ULL);
    for (i = 0; i < llen; i++) {
        ldst[i] ^= lsrc[i];
    }
}

/// \brief Invert the square matrix squareMatrix_ into inverseMatrix_ in GF
///
/// \return true Inversion succeeds
/// \return false Inversion fails

bool RSUtil::squareMatrixInverting()
{
    int matrixSize;
    int rowStartIndex1, rowStartIndex2;
    int tmp, multFactor;
    int i, j, h, l;

    matrixSize = ecK_ * ecK_;

    /*first store an identity matrix in inverseMatrix_*/
    i = 0;
    while (i < matrixSize) {
        if (i / ecK_ == i % ecK_) {
            inverseMatrix_[i] = 1;
        } else {
            inverseMatrix_[i] = 0;
        }

        i++;
    }

    /*convert squareMatrix_ into an upper triangular matrix*/
    for (i = 0; i < ecK_; i++) {
        rowStartIndex1 = ecK_ * i;

        /*if the i-th element in the i-th row is zero, we need to swap the i-th row with a row (below it) 
          whose i-th element is non-zero*/
        if (squareMatrix_[rowStartIndex1 + i] == 0) {
            j = i + 1;
            while ((j < ecK_) && (squareMatrix_[ecK_ * j + i] == 0))
                j++;
            /*if we cannot find such a row below the i-th row, we can judge that squareMatrix_ is noninvertible*/
            if (j == ecK_) {
                return 0;
            }

            /*swap the i-th row with the j-th row for both squareMatrix_ and inverseMatrix_*/
            rowStartIndex2 = ecK_ * j;

            for (h = 0; h < ecK_; h++) {
                tmp = squareMatrix_[rowStartIndex1 + h];
                squareMatrix_[rowStartIndex1 + h] = squareMatrix_[rowStartIndex2 + h];
                squareMatrix_[rowStartIndex2 + h] = tmp;

                /*do the same for inverseMatrix_*/
                tmp = inverseMatrix_[rowStartIndex1 + h];
                inverseMatrix_[rowStartIndex1 + h] = inverseMatrix_[rowStartIndex2 + h];
                inverseMatrix_[rowStartIndex2 + h] = tmp;
            }
        }

        tmp = squareMatrix_[rowStartIndex1 + i];
        /*if the i-th element in the i-th row is not equal to 1, divide each element in this row by the i-th element*/
        if (tmp != 1) {
            multFactor = gfObj_.divide.w32(&gfObj_, 1, tmp);

            for (j = 0; j < ecK_; j++) {
                squareMatrix_[rowStartIndex1 + j] = gfObj_.multiply.w32(&gfObj_,
                    squareMatrix_[rowStartIndex1 + j], multFactor);

                /*do the same for inverseMatrix_*/
                inverseMatrix_[rowStartIndex1 + j] = gfObj_.multiply.w32(&gfObj_,
                    inverseMatrix_[rowStartIndex1 + j], multFactor);
            }
        }

        /*multiply the i-th row with a factor and add it to each row below it such that the i-th element in each row becomes zero*/
        for (j = i + 1; j < ecK_; j++) {
            rowStartIndex2 = ecK_ * j;
            h = rowStartIndex2 + i;

            if (squareMatrix_[h] != 0) { /*we need to do this when the i-th element in the j-th row is not equal to zero*/
                if (squareMatrix_[h] == 1) {
                    for (l = 0; l < ecK_; l++) {
                        squareMatrix_[rowStartIndex2 + l] ^= squareMatrix_[rowStartIndex1 + l];

                        /*do the same for inverseMatrix_*/
                        inverseMatrix_[rowStartIndex2 + l] ^= inverseMatrix_[rowStartIndex1 + l];
                    }
                } else {
                    multFactor = squareMatrix_[h];

                    for (l = 0; l < ecK_; l++) {
                        squareMatrix_[rowStartIndex2 + l] ^= gfObj_.multiply.w32(&gfObj_,
                            squareMatrix_[rowStartIndex1 + l], multFactor);

                        /*do the same for inverseMatrix_*/
                        inverseMatrix_[rowStartIndex2 + l] ^= gfObj_.multiply.w32(&gfObj_,
                            inverseMatrix_[rowStartIndex1 + l], multFactor);
                    }
                }
            }
        }
    }

    /*based on the upper triangular matrix, make squareMatrix_ become an identity matrix. 
      then, inverseMatrix_ become the final inverse matrix*/
    for (i = ecK_ - 1; i >= 0; i--) {
        rowStartIndex1 = ecK_ * i;

        for (j = 0; j < i; j++) {
            rowStartIndex2 = ecK_ * j;
            h = rowStartIndex2 + i;

            if (squareMatrix_[h] != 0) { /*we need to do this when the i-th element in the j-th row is not equal to zero*/
                if (squareMatrix_[h] == 1) {
                    for (l = 0; l < ecK_; l++) {
                        /*squareMatrix_[rowStartIndex2+l] ^= squareMatrix_[rowStartIndex1+l];*/

                        /*do the same for inverseMatrix_	*/
                        inverseMatrix_[rowStartIndex2 + l] ^= inverseMatrix_[rowStartIndex1 + l];
                    }
                } else {
                    multFactor = squareMatrix_[h];

                    for (l = 0; l < ecK_; l++) {
                        /*squareMatrix_[rowStartIndex2+l] ^= gfObj_.multiply.w32(&gfObj_, 
                          squareMatrix_[rowStartIndex1+l], multFactor);*/

                        /*do the same for inverseMatrix_*/
                        inverseMatrix_[rowStartIndex2 + l] ^= gfObj_.multiply.w32(&gfObj_,
                            inverseMatrix_[rowStartIndex1 + l], multFactor);
                    }
                }

                /*we simply zero this element since squareMatrix_ will eventually become an identity matrix*/
                squareMatrix_[h] = 0;
            }
        }
    }

    return true;
}

/// \brief for the given K shares ID list, store corresponding rows of them
///
/// \param kShareIDList a list that stores the IDs of the k shares
void RSUtil::storeKRowsMatrix(int* kShareIDList)
{
    for (int i = 0; i < ecK_; i++) {
        for (int j = 0; j < ecK_; j++) {
            squareMatrix_[ecK_ * i + j] = distributionMatrix_[ecK_ * kShareIDList[i] + j];
        }
    }
}

/// \brief perform RS decoding
///
/// \param srcBuffer the buffer to store the input data
/// \param dstBuffer  the buffer to store the output data
/// \param length the size of data block in decoding
/// \return true decoding succeeds
/// \return false decoding fails
bool RSUtil::rsDecoding(unsigned char* srcBuffer, unsigned char* dstBuffer, int length)
{
    int coef, i, j;
    for (i = 0; i < ecK_; i++) {
        for (j = 0; j < ecK_; j++) {
            coef = inverseMatrix_[ecK_ * i + j];
            if (j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, srcBuffer + length * j,
                    dstBuffer + length * i, coef, length, 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, srcBuffer + length * j,
                    dstBuffer + length * i, coef, length, 1);
            }
        }
    }

    return 1;
}

/// \brief perform RS encoding to generate last ecM_ shares
///
/// \param srcBuffer the buffer to store the input data
/// \param dstBuffer the buffer to store the output data
/// \param length the size of data block in encoding
/// \return true encoding succeeds
/// \return false encoding fails

bool RSUtil::reEncoding(unsigned char* srcBuffer, unsigned char* dstBuffer, int* length)
{
    int coef, i, j;
    for (i = 0; i < ecM_; i++) {
        for (j = 0; j < ecK_; j++) {
            coef = distributionMatrix_[ecK_ * (ecK_ + i) + j];
            if (j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, srcBuffer + (*length) * j,
                    dstBuffer + (*length) * (ecK_ + i), coef, (*length), 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, srcBuffer + (*length) * j,
                    dstBuffer + (*length) * (ecK_ + i), coef, (*length), 1);
            }
        }
    }
    return 1;
}

/// \brief print the matrix
///
void RSUtil::printMtr()
{
    printf("distributionMatrix_: (see below) \n");
    for (int i = 0; i < ecN_; i++) {
        printf("| ");
        for (int j = 0; j < ecK_; j++) {
            printf("%3d ", distributionMatrix_[ecK_ * i + j]);
        }
        printf("|\n");
    }
    printf("\n");
}

/// \brief Destroy the RSUtil::RSUtil object
///
RSUtil::~RSUtil()
{
    free(distributionMatrix_);
    free(squareMatrix_);
    free(inverseMatrix_);

    /**free the gf_t object*/
    gf_free(&gfObj_, 1);
    printf("RSUtil has been destructed.");
}

gf_t RSUtil::getGFObject()
{

    return gfObj_;
}

int* RSUtil::getDistributionMatrix()
{
    return distributionMatrix_;
}

int* RSUtil::getInverseMatrix()
{
    return inverseMatrix_;
}

int* RSUtil::getSquareMatrix()
{
    return squareMatrix_;
}
