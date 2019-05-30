/// \file absss.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief Implement the interface defined in AbsSecretSharing
/// \version 0.1
/// \date 2019-03-19
///
/// \copyright Copyright (c) 2019
///
#include "absss.h"

/// \brief AbsSecretSharing initialize parameters for secret sharing algorithms
///
/// \param n total number of shares
/// \param k minimum number of shares for successful reconstruction
/// \param r maximum number of shares that leak nothing about original secret
/// \param cryptoUtil the pointer to the cyrptoUtil
AbsSecretSharing::AbsSecretSharing(int n, int k, int r, CryptoPrimitive* cryptoUtil)
    : n_(n)
    , k_(k)
    , r_(r)
{
    m_ = n_ - k_;
    cryptoUtil_ = cryptoUtil;

    if (cryptoUtil_ == NULL) {
        printf("Error: no cryptoUtil for hash generation and data encryption.\n");
        exit(1);
    }

    /**Initialize RSUtil of EC operation*/
    rsUtil_ = new RSUtilIsal(k, n);
}

/// \brief Destroy the Abs Secret Sharing:: Abs Secret Sharing object
///
AbsSecretSharing::~AbsSecretSharing()
{

    free(key_);
    free(alignedSecretBuffer_);
    free(wordForIndex_);
    free(erasureCodingData_);
    free(rsUtil_);
}
