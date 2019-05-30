/*
 * CDCodec.hh
 */

#ifndef __CDCODEC_HH__
#define __CDCODEC_HH__

#include "CRsss.h"
#include "Rsss.h"
#include "absss.h"
#include "aont_rs.h"
#include "caont_rs.h"
#include "caont_rs_oaep.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/*for the use of CryptoPrimitive*/
#include "CryptoPrimitive.hh"

/*macro for the type of CRSSS*/
#define CRSSS_TYPE 0
/*macro for the type of AONT-RS*/
#define AONT_RS_TYPE 1
/*macro for the type of old CAONT-RS*/
#define CAONT_RS_OAEP_TYPE 2
/*macro for the type of CAONT-RS*/
#define CAONT_RS_TYPE 3
/*macro for the type of RSSS*/
#define RSSS_TYPE 4

#define MAX_SECRET_SIZE (64 << 10)

using namespace std;

class CDCodec {
private:
    /*convergent dispersal type*/
    int CDType_;

    /*total number of shares generated from a secret*/
    int n_;
    /*reliability degree (i.e. maximum number of lost shares that can be tolerated)*/
    int m_;
    /*minimum number of shares for reconstructing the original secret*/
    int k_;
    /*confidentiality degree (i.e. maximum number of shares from which nothing can be derived)*/
    int r_;

    /*variables for hash generation and data encryption*/
    CryptoPrimitive* cryptoObj_;

    AbsSecretSharing* secretSharing_;

public:
    /*
         * constructor of CDCodec
         *
         * @param CDType - convergent dispersal type
         * @param n - total number of shares generated from a secret
         * @param m - reliability degree (i.e. maximum number of lost shares that can be tolerated)
         * @param r - confidentiality degree (i.e. maximum number of shares from which nothing can be derived)
         * @param cryptoObj - the CryptoPrimitive instance for hash generation and data encryption
         */
    CDCodec(int CDType = CAONT_RS_TYPE,
        int n = 4,
        int m = 1,
        int r = 2,
        CryptoPrimitive* cryptoObj = new CryptoPrimitive(HIGH_SEC_PAIR_TYPE));

    /* 
         * destructor of CDCodec 
         */
    ~CDCodec() = default;

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
    bool encoding(unsigned char* secretBuffer, int secretSize, unsigned char* shareBuffer, int* shareSize);

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
    bool decoding(unsigned char* shareBuffer, int* kShareIDList, int shareSize, int secretSize, unsigned char* secretBuffer);
};

#endif
