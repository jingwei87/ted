/*
 * CDCodec.cc
 */

#include "CDCodec.hh"

using namespace std;

/*
 * constructor of CDCodec
 *
 * @param CDType - convergent dispersal type
 * @param n - total number of shares generated from a secret
 * @param m - reliability degree (i.e. maximum number of lost shares that can be tolerated)
 * @param r - confidentiality degree (i.e. maximum number of shares from which nothing can be derived)
 * @param cryptoObj - the CryptoPrimitive instance for hash generation and data encryption
 */
CDCodec::CDCodec(int CDType, int n, int m, int r, CryptoPrimitive* cryptoObj)
{

    CDType_ = CDType;
    cryptoObj_ = cryptoObj;
    n_ = n;
    m_ = m;
    k_ = n - m;
    r_ = r;

    if (n <= 0) {
        fprintf(stderr, "Error: n should be > 0!\n");
        exit(1);
    }
    if ((m <= 0) || (m >= n)) {
        fprintf(stderr, "Error: m should be in (0, n)!\n");
        exit(1);
    }
    if (n - m <= 1) {
        fprintf(stderr, "Error: k = n -m should be > 1 for further providing confidentiality!\n");
        exit(1);
    }
    if ((r <= 0) || (r >= n - m)) {
        fprintf(stderr, "Error: r should be in (0, n-m)!\n");
        exit(1);
    }

    if (cryptoObj_ == NULL) {
        fprintf(stderr, "Error: no CryptoPrimitive instance for hash generation and data encryption!\n");
        exit(1);
    }

    if (CDType_ == RSSS_TYPE) {
        secretSharing_ = new Rsss(n_, k_, r_, cryptoObj_);
    }

    if (CDType_ == CRSSS_TYPE) {
        secretSharing_ = new CRsss(n_, k_, r_, cryptoObj_);
    }

    if (CDType_ == AONT_RS_TYPE) {
        secretSharing_ = new AontRS(n_, k_, r_, cryptoObj_);
    }

    if (CDType_ == CAONT_RS_TYPE) {
        secretSharing_ = new CaontRS(n_, k_, r_, cryptoObj_);
    }

    if (CDType_ == CAONT_RS_OAEP_TYPE) {
        secretSharing_ = new CaontRSOAEP(n_, k_, r_, cryptoObj_);
    }
}

/*
 * encode a secret into n shares
 *
 * @param secretBuffer - a buffer that stores the secret
 * @param secretSize - the size of the secret
 * @param shareBuffer - a buffer for storing the n generated shares <return>
 * @param shareSize - the size of each share <return>
 *
 * @return - a boolean value that indicates if the encoding succeeds
 */
bool CDCodec::encoding(unsigned char* secretBuffer, int secretSize, unsigned char* shareBuffer, int* shareSize)
{
    bool success = secretSharing_->shareSecret(secretBuffer, secretSize, shareBuffer, shareSize);
    return success;
}

/*
 * decode the secret from k = n - m shares
 *
 * @param shareBuffer - a buffer that stores the k shares 
 * @param kShareIDList - a list that stores the IDs of the k shares
 * @param shareSize - the size of each share 
 * @param secretSize - the size of the secret
 * @param secretBuffer - a buffer for storing the secret <return>
 *
 * @return - a boolean value that indicates if the decoding succeeds
 */
bool CDCodec::decoding(unsigned char* shareBuffer, int* kShareIDList, int shareSize,
    int secretSize, unsigned char* secretBuffer)
{
    bool success = secretSharing_->reconstructSecret(shareBuffer, shareSize, kShareIDList, secretBuffer, secretSize);

    return success;
}
