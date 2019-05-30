/// \file RSUtil_isl.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the API in RSUtilIsl
/// \version 0.1
/// \date 2019-03-28
///
/// \copyright Copyright (c) 2019
///
#ifndef SSLIB_RSUTILISL_H
#define SSLIB_RSUTILISL_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <isa-l.h>



class RSUtilIsal {
    private:
        /// \brief key parameters used in Erasure Coding
        ///
        int ecK_; /// k in RS(n, k)
        int ecN_; /// n in RS(n, k)
        int ecM_; /// m = n - k

        unsigned char *distributionMatrix_; /// the distribution matrix of an erasure code (IDA or RS)
        unsigned char *squareMatrix_; /// two k * k matrices for decoding
        unsigned char *inverseMatrix_; /// store the inverse matrix in decoding

        unsigned char *gftbl_;
        unsigned char *tmpGftbl_;
        unsigned char *fMat;
    
    public:
        /// \brief Construct a new RSUtil object
        ///
        /// \param ecK in RS(n, k)
        /// \param ecN in RS(n, k)
        RSUtilIsal(int ecK, int ecN);

        /// \brief print the matrix 
        ///
        void printMtr();

        /// \brief Invert the square matrix squareMatrix_ into inverseMatrix_ in GF
        ///
        /// \return true Inversion succeeds
        /// \return false Inversion fails
        bool squareMatrixInverting();

        /// \brief for the given K shares ID list, store corresponding rows of them
        ///
        /// \param kShareIDList a list that stores the IDs of the k shares
        void storeKRowsMatrix(int *kShareIDList);

        /// \brief perform RS encoding to generat
        ///
        /// \param srcBuffer the buffer to store the input data 
        /// \param dstBuffer the buffer to store the output data
        /// \param length the size of data block in encoding
        /// \return true encoding succeeds
        /// \return false encoding fails
        bool reEncoding(unsigned char *srcBuffer, unsigned char *dstBuffer, int *length);

        /// \brief perform RS decoding 
        ///
        /// \param srcBuffer the buffer to store the input data  
        /// \param dstBuffer  the buffer to store the output data
        /// \param length the size of data block in decoding
        /// \return true decoding succeeds
        /// \return false decoding fails
        bool rsDecoding(unsigned char *srcBuffer, unsigned char *dstBuffer, int length);

        /// \brief execute XOR for dst buffer and src buffer
        ///
        /// \param dst store the XOR result of two buffers <return> 
        /// \param src store the buf of source data
        /// \param length the size of data involved in this XOR operation
        void addXOR(unsigned char *dst, unsigned char *src, int length);

        /// \brief Destroy the RSUtilIsal object
        ///
        ~RSUtilIsal();

};
#endif
