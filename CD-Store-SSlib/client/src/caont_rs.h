/// \file caont_rs.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the API of CaontRS
/// \version 0.1
/// \date 2019-03-21
///
/// \copyright Copyright (c) 2019
///

#include "aont_rs.h"

class CaontRS : public AontRS {

public:
    /// \brief Construct a new Caont-RS object
    ///
    /// \param n the total number of shares
    /// \param k minimum number of shares for successful reconstruction
    /// \param r maximum number of shares that leak nothing about original secret
    /// \param cryptoUtil the pointer to the cryptoUtil
    CaontRS(int n, int k, int r, CryptoPrimitive* cryptoUtil)
        : AontRS(n, k, r, cryptoUtil){};

    /// \brief Destroy the Caont-RS object
    ///
    ~CaontRS();

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
};
