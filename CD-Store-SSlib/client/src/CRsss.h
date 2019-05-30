//
// Created by tinoryj on 19-3-27.
//

/// \file CRsss.h
/// \brief definition of Rsss
/// \author tinoryj, tinoryj@gmail.com
/// \version 0.1
/// \date 2019-03-17

#ifndef SSLIB_CRSSS_H
#define SSLIB_CRSSS_H

#include "RSUtil.h"
#include "Rsss.h"
#include <bits/stdc++.h>

using namespace std;

class CRsss : public Rsss {
private:
    int secretWordsPerGroup_; /// hash generation variables
    int bytesPerGroup_; /// hash generation variables
    unsigned char* hashInputBuffer_; /// temp buffer for generating and storing r hashes from each group of secret
    unsigned char* rHashes_; /// temp buffer for generating and storing r hashes from each group of secret
public:
    /// \brief Rsss initialize parameters for Rsss
    ///
    /// \param n total number of shares
    /// \param k minimum number of shares for successful reconstruction
    /// \param r maximum number of shares that leak nothing about original secret
    /// \param cryptoUtil the pointer to the cyrptoUtil
    CRsss(int n, int k, int r, CryptoPrimitive* cryptoUtil);
    ~CRsss() = default;
    /// \brief Share encode a secret via AONT-RS
    ///
    /// \param secretBuffer a buffer that stores the input secret
    /// \param secretSize the size of the input secret
    /// \param shareBuffer a buffer that stores all output shares
    /// \param shareSize the size of each output share
    ///
    /// \return true if succeed and false otherwise
    bool shareSecret(unsigned char* secretBuffer, int secretSize,
        unsigned char* shareBuffer, int* shareSize);

    /// \brief Reconstrct recover the original secret from RSSS shares
    ///
    /// \param shareBuffer a buffer that stores the input shares
    /// \param shareSize the size of each share
    /// \param shareIDList a list of share IDs
    /// \param secretBuffer a buffer that stores the output secret
    /// \param secretSize the size of recovered secret
    ///
    /// \return true if succeed and false otherwise
    bool reconstructSecret(unsigned char* shareBuffer, int shareSize,
        int* shareIDList, unsigned char* secretBuffer,
        int secretSize);
};

#endif // SSLIB_CRSSS_H
