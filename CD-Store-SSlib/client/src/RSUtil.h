/// \file RSUtil.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface using in Erasure Coding
/// \version 0.1
/// \date 2019-03-14
///
/// \copyright Copyright (c) 2019
///
#ifndef SSLIB_RSUTIL_H
#define SSLIB_RSUTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string>

//TODO: replace this library with isl
/// for the use of gf_t object
extern "C" {
#include "gf_complete.h"
}

class RSUtil {
private:
    /// \brief key parameters used in Erasure Coding
    ///
    int ecK_; /// k in RS(n, k)
    int ecN_; /// n in RS(n, k)
    int ecM_; /// m = n - k

    int* distributionMatrix_; /// the distribution matrix of an erasure code (IDA or RS)

    int* squareMatrix_; /// two k * k matrices for decoding
    int* inverseMatrix_; /// store the inverse matrix in decoding

    gf_t gfObj_; /// object for accelerating GF calculation

    int bitsPerGFWord_; /// number of bits per GF word

public:
    /// \brief Construct a new RSUtil object
    ///
    /// \param ecK in RS(n, k)
    /// \param ecN in RS(n, k)
    RSUtil(int ecK, int ecN);

    /// \brief execute XOR for dst buffer and src buffer
    ///
    /// \param dst store the XOR result of two buffers <return>
    /// \param src store the buf of source data
    /// \param length the size of data involved in this XOR operation
    void addXOR(unsigned char* dst, unsigned char* src, int length);

    /// \brief Invert the square matrix squareMatrix_ into inverseMatrix_ in GF
    ///
    /// \return true Inversion succeeds
    /// \return false Inversion fails
    bool squareMatrixInverting();

    /// \brief for the given K shares ID list, store corresponding rows of them
    ///
    /// \param kShareIDList a list that stores the IDs of the k shares
    void storeKRowsMatrix(int* kShareIDList);

    /// \brief perform RS decoding
    ///
    /// \param srcBuffer the buffer to store the input data
    /// \param dstBuffer  the buffer to store the output data
    /// \param length the size of data in decoding
    /// \return true decoding succeeds
    /// \return false decoding fails

    bool rsDecoding(unsigned char* srcBuffer, unsigned char* dstBuffer, int length);

    /// \brief perform RS encoding to generat
    ///
    /// \param srcBuffer the buffer to store the input data
    /// \param dstBuffer the buffer to store the output data
    /// \param length the size of data in decoding
    /// \return true encoding succeeds
    /// \return false encoding fails

    bool reEncoding(unsigned char* srcBuffer, unsigned char* dstBuffer, int* length);

    /// \brief print the matrix
    ///
    void printMtr();

    /// \brief Destroy the RSUtil object
    ///
    ~RSUtil();

    /// \brief get gfObj_ for further compute
    ///
    /// \return gf_t: gfObj_
    gf_t getGFObject();

    /// \brief get int* distributionMatrix_ for compute
    ///
    /// \return int* distributionMatrix_
    int* getDistributionMatrix();

    /// \brief get int* inverseMatrix_ for compute
    ///
    /// \return int* inverseMatrix_
    int* getInverseMatrix();

    /// \brief get int* squareMatrix_ for compute
    ///
    /// \return int* squareMatrix_
    int* getSquareMatrix();
};
#endif
