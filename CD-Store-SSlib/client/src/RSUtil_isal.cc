/// \file RSUtil_isal.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief 
/// \version 0.1
/// \date 2019-03-28
///
/// \copyright Copyright (c) 2019
///

#include "RSUtil_isal.h"
#define ULL unsigned long long



/// \brief Construct a new RSUtil object
///
/// \param ecK in RS(n, k)
/// \param ecN in RS(n, k)
RSUtilIsal::RSUtilIsal(int ecK, int ecN) {
    ecK_ = ecK;
    ecN_ = ecN;
    ecM_ = ecN - ecK;

    distributionMatrix_ = (unsigned char *) malloc(ecK_ * ecN_ * sizeof(unsigned char));
    squareMatrix_ = (unsigned char *) malloc(ecK_ * ecK_ * sizeof(unsigned char)); 
    inverseMatrix_ = (unsigned char *) malloc(ecK_ * ecK_ * sizeof(unsigned char));

    gftbl_ = (unsigned char *) malloc(ecK_ * ecN_ * 32 * sizeof(unsigned char));
    
    // generate Cauchy Matrix 
    gf_gen_cauchy1_matrix(distributionMatrix_, ecN_, ecK_);

    ec_init_tables(ecK_, ecM_, &this->distributionMatrix_[ecK_ * ecK_], this->gftbl_);
    printMtr();
}

/// \brief print the matrix 
///
void RSUtilIsal::printMtr() {
    printf("ecN_: %d\n", ecN_);
    printf("ecK_: %d\n", ecK_);
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

/// \brief perform RS encoding to generat
///
/// \param srcBuffer the buffer to store the input data 
/// \param dstBuffer the buffer to store the output data
/// \param length the size of data in decoding
/// \return true encoding succeeds
/// \return false encoding fails
bool RSUtilIsal::reEncoding(unsigned char *srcBuffer, unsigned char *dstBuffer, int *length) {
    // perpare data buffer and code buffer
    unsigned char **dataBuffers = (unsigned char **) calloc(ecK_, sizeof(unsigned char *));
    for (int i = 0; i < ecK_; i++) {
        dataBuffers[i] = (unsigned char *) calloc((*length), sizeof(unsigned char));
         memcpy(dataBuffers[i], dstBuffer + (*length) * i,  (*length)); 
    }
  
    unsigned char **codeBuffers = (unsigned char **) calloc(ecM_, sizeof(unsigned char *));
    for (int i = 0; i < ecM_; i++) {
        codeBuffers[i] = (unsigned char *) calloc((*length), sizeof(unsigned char));
        memset(codeBuffers[i], 0, (*length));
    }


    ec_encode_data((*length), ecK_, ecM_, this->gftbl_, 
                dataBuffers, codeBuffers);
    // append the coded data from the codeBuffers to dstBuffer
    for (int i = 0; i < ecM_; i++) {
        memcpy(dstBuffer + (*length) * (ecK_ + i), codeBuffers[i], (*length));   
    }

    //free buffer
    for (int i = 0; i < ecM_; i++) {
        free(codeBuffers[i]);
    }

    free(codeBuffers);
    return true;
}

/// \brief for the given K shares ID list, store corresponding rows of them
///
/// \param kShareIDList a list that stores the IDs of the k shares
void RSUtilIsal::storeKRowsMatrix(int *kShareIDList) {
    for (int i = 0; i < ecK_; i++) {
        for (int j = 0; j < ecK_; j++) {
            squareMatrix_[ecK_ * i + j] = distributionMatrix_[ecK_ * kShareIDList[i] + j];
        }
    }
}

/// \brief Invert the square matrix squareMatrix_ into inverseMatrix_ in GF
///
/// \return true Inversion succeeds
/// \return false Inversion fails
bool RSUtilIsal::squareMatrixInverting() {
    
    gf_invert_matrix(squareMatrix_, inverseMatrix_, ecK_);

    unsigned char rMat[ecK_ * ecK_];
    memcpy(rMat, distributionMatrix_, ecK_ * ecK_);

    fMat = (unsigned char *) malloc(ecK_ * ecK_ * sizeof(unsigned char));
    for (int i = 0; i < ecK_; i++) {
        for (int j = 0; j < ecK_; j++) {
            fMat[ecK_ * i + j] = 0;
            for (int l = 0; l < ecK_; l++) {
                fMat[ecK_ * i + j] ^= gf_mul(rMat[ecK_ * i + l], inverseMatrix_[l * ecK_ + j]);
            }
        }
    }
    tmpGftbl_ = (unsigned char *) malloc(ecK_ * ecK_ * 32 * sizeof(unsigned char));
    ec_init_tables(ecK_, ecK_, fMat, tmpGftbl_);

    return true;
}
/// \brief perform RS decoding 
///
/// \param srcBuffer the buffer to store the input data  
/// \param dstBuffer  the buffer to store the output data
/// \param length the size of data block in decoding
/// \return true decoding succeeds
/// \return false decoding fails
bool RSUtilIsal::rsDecoding(unsigned char *srcBuffer, unsigned char *dstBuffer, int length) {
    ec_encode_data(length, ecK_, ecK_, tmpGftbl_, 
            (unsigned char **)srcBuffer, (unsigned char **)dstBuffer);
    return true;
}

void RSUtilIsal::addXOR(unsigned char *dst, unsigned char *src, int length) {
    ULL *ldst = (ULL*)dst;
    ULL *lsrc = (ULL*)src;
    size_t i = 0;
    size_t llen = length / sizeof(ULL);
    for (i = 0; i < llen; i ++) {
        ldst[i] ^= lsrc[i];
    }
}

/// \brief Destroy the RSUtilIsal::RSUtilIsal object
///
RSUtilIsal::~RSUtilIsal() {
    free(distributionMatrix_);
    free(squareMatrix_);
    free(inverseMatrix_);
    free(gftbl_);
    free(tmpGftbl_);
    free(fMat);
}