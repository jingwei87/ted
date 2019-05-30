/// \file absss.h
/// \brief definition of AbsSecretSharing
/// \author Jingwei Li, lijw1987@gmail.com
/// \version 0.1
/// \date 2019-03-13

#ifndef SSLIB_ABSSS_H_
#define SSLIB_ABSSS_H_

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "CryptoPrimitive.hh"

//#include "CryptoPrimitive.hh"
//#include "CryptoUtil.h"
#include "RSUtil.h"
#include "RSUtil_isal.h"

#define MAX_SECRET_SIZE (64 << 10)
#define DEBUG_OUTPUT 0

class AbsSecretSharing {
public:
    /// \brief API of secret sharing algorithms

    /// \brief AbsSecretSharing initialize parameters for secret sharing algorithms
    ///
    /// \param n total number of shares
    /// \param k minimum number of shares for successful reconstruction
    /// \param r maximum number of shares that leak nothing about original secret
    /// \param cryptoUtil the pointer to the cyrptoUtil
    AbsSecretSharing(int n, int k, int r, CryptoPrimitive* cryptoUtil);

    /// \brief Destroy the Abs Secret Sharing object
    ///
    ~AbsSecretSharing();

    /// \brief Share encode a secret into multiple shares
    ///
    /// \param secretBuffer a buffer that stores the input secret
    /// \param secretSize the size of the input secret
    /// \param shareBuffer a buffer that stores all output shares
    /// \param shareSize the size of each output share
    ///
    /// \return true if succeed and false otherwise
    virtual bool shareSecret(unsigned char* secretBuffer, int secretSize, unsigned char* shareBuffer, int* shareSize) = 0;

    /// \brief Reconstruct recover the original secret from a number of shares
    ///
    /// \param shareBuffer a buffer that stores the input shares
    /// \param shareSize the size of each share
    /// \param shareIDList a list of share IDs
    /// \param secretBuffer a buffer that stores the output secret
    /// \param secretSize the size of recovered secret <return>
    ///
    /// \return true if succeed and false otherwise
    virtual bool reconstructSecret(unsigned char* shareBuffer, int shareSize, int* shareIDList, unsigned char* secretBuffer, int secretSize) = 0;

protected:
    /// \brief parameters of secret sharing algorithms
    int n_; /// total number of shares
    int k_; /// minimum number of shares for successful reconstruction
    int r_; /// maximum number of shares that leak nothing about original secret
    int m_; /// m_ = n_ - k_;

    int bytesPerSecretWord_; /// number of bytes per secret word

    RSUtilIsal* rsUtil_; /// the util for Erasure Coding operation
    CryptoPrimitive* cryptoUtil_; /// the util for crypto operation

    int alignedSecretBufferSize_; /// the size of the buffer storing the aligned secret
    unsigned char* alignedSecretBuffer_; /// a buffer to store the aligned secret

    int erasureCodingDataSize_; /// the size of Erasure Coding data buffer
    unsigned char* erasureCodingData_; /// the buffer of Erasure Coding data

    unsigned char* key_; /// store the key using in encryption
    unsigned char* wordForIndex_; /// a word of size bytesPerSecretWord_ for storing an index
};
#endif
