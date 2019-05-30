/// \file aont_rs.h
/// \brief definition of AontRS
/// \author Jingwei Li, lijw1987@gmail.com
/// \version 0.1
/// \date 2019-03-13

#ifndef SSLIB_AONTRS_H_
#define SSLIB_AONTRS_H_

#include "absss.h"
#include <iostream>
#include <stdlib.h>
#include <string.h>

class AontRS : public AbsSecretSharing {
public:
    /// \brief AontRS initialize parameters for AONT-RS
    ///
    /// \param n total number of shares
    /// \param k minimum number of shares for successful reconstruction
    /// \param r maximum number of shares that leak nothing about original secret
    /// \param cryptoUtil the pointer to the cyrptoUtil
    AontRS(int n, int k, int r, CryptoPrimitive* cryptoUtil);

    /// \brief Share encode a secret via AONT-RS
    ///
    /// \param secretBuffer a buffer that stores the input secret
    /// \param secretSize the size of the input secret
    /// \param shareBuffer a buffer that stores all output shares
    /// \param shareSize the size of each output share
    ///
    /// \return true if succeed and false otherwise
    bool shareSecret(unsigned char* secretBuffer, int secretSize, unsigned char* shareBuffer, int* shareSize);

    /// \brief Reconstrct recover the original secret from AONT-RS shares
    ///
    /// \param shareBuffer a buffer that stores the input shares
    /// \param shareSize the size of each share
    /// \param shareIDList a list of share IDs
    /// \param secretBuffer a buffer that stores the output secret
    /// \param secretSize the size of recovered secret
    ///
    /// \return true if succeed and false otherwise
    bool reconstructSecret(unsigned char* shareBuffer, int shareSize, int* shareIDList, unsigned char* secretBuffer, int secretSize);

protected:
    int type_; /// which type of AONT-RS variant (OAEP-based or Rivest-based)
};

#endif
