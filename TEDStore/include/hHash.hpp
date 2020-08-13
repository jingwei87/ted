/**
 * @file hHash.hpp
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the interface of homomorphsim hash 
 * @version 0.1
 * @date 2020-08-11
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#ifndef TEDSTORE_HHASH_HPP
#define TEDSTORE_HHASH_HPP 

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <gmp.h>

#include "configure.hpp"
#include "dataStructure.hpp"

#define BLOCK_NUM 4
#define K 2

class HHash {
private:
    
    // two big prime
    mpz_t p_, q_;

    // g array
    mpz_t g_[BLOCK_NUM];

    // random seed
    uint32_t seed_ = 32;

    // hash and buff 
    mpz_t hash_;
    mpz_t buff_;

    /**
     * @brief generate the g array according p and seed 
     * 
     * @param g 
     * @param p 
     * @param seed 
     */
    void GenerateForG(mpz_t g[BLOCK_NUM], mpz_t p, uint32_t seed);

public:
    /**
     * @brief Construct a new HHash object
     * 
     */
    HHash();

    /**
     * @brief Compute the homomorphism hash of the block
     * 
     * @param result the resultant hash 
     * @param b input block
     */
    void ComputeBlockHash(mpz_t result, mpz_t b[BLOCK_NUM]);

    /**
     * @brief Convert the fp to block
     * 
     * @param result the resultant 
     * @param fp fingerprint
     */
    void CovertFPtoBlocks(mpz_t result[BLOCK_NUM], const char* fp);

    /**
     * @brief Compute the value of multiplication of block and mulVal
     * 
     * @param block the input block (also store the result)
     * @param mulVal another operand 
     */
    void ComputeMulForBlock(mpz_t block[BLOCK_NUM], mpz_t mulVal);

    /**
     * @brief Recover the secret from share hashes
     * 
     * @param hash the array of share hash 
     * @param powVal the array of share parameter 
     * @param secret the recovery secret
     */
    void RecoverySecretFromHash(mpz_t hash[K], mpz_t powVal[K], mpz_t secret);
    

    /**
     * @brief Destroy the HHash object
     * 
     */
    ~HHash();
};

#endif