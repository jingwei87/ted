/**
 * @file hHash.cpp
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief 
 * @version 0.1
 * @date 2020-08-11
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#include "../../include/hHash.hpp"

/**
 * @brief Construct a new HHash::HHash object
 * 
 */
HHash::HHash() {
    // set the init value of p,q
    mpz_init_set_str(p_, "225232741022919503494335621622594011137", 10);
	mpz_init_set_str(q_, "5685673727", 10);

    // initialize the array g_
    for (size_t i = 0; i < BLOCK_NUM; i++) {
        mpz_init(g_[i]);
    }

    // generate the array for g
    GenerateForG(g_, p_, seed_);

    //Curiosity: print g
    fprintf(stderr, "Show the g[BLOCK_NUM] array.\n");
	for (uint32_t i = 0; i < BLOCK_NUM; i++) {
		gmp_printf("g[%d] = %Zd\n", i, g_[i]);
	}

}

/**
 * @brief generate the g array according p and seed 
 * 
 * @param g 
 * @param p 
 * @param seed 
 */
void HHash::GenerateForG(mpz_t g[BLOCK_NUM], mpz_t p, uint32_t seed) {
    // Initialize state
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long int)seed);
    
    // Compute g[i]
    for (size_t i = 0; i < BLOCK_NUM; i++) {
        mpz_urandomm(g[i], state, p);
    }
    gmp_randclear(state);
}


/**
 * @brief Compute the homomorphism hash of the block
 * 
 * @param result the resultant hash 
 * @param p security parameter
 * @param g security parameter
 * @param b input block
 */
void HHash::ComputeBlockHash(mpz_t result, mpz_t p, mpz_t g[BLOCK_NUM], mpz_t b[BLOCK_NUM]) {
	mpz_t hash, buff;
    mpz_init_set_str(hash, "1", 10);
	mpz_init(buff);

    // TODO: reduce the number of memory re-allocation 

	for (uint32_t i = 0; i < BLOCK_NUM; i++) {
		// hash = hash * g[i] ^ bij mod p = hash * buff
		// buff contains g[i] ^ bij mod p
		mpz_powm_sec(buff, g[i], b[i], p);
		//gmp_printf("Value of buff = %Zd\n", buff);
		// Aggregate in hash
		mpz_mul(hash, hash, buff);
		//Mod here may not be optimal from a number-of-operations standpoint, but it does greatly reduce the amount of data in memory
		mpz_mod(hash, hash, p);
	}
	
	//Last modulo (now in loop)
	//mpz_mod(hash, hash, p);
	//copy hash into result
	mpz_set(result, hash);
	//free
	mpz_clear(hash);
	mpz_clear(buff);
}

/**
 * @brief Convert the fp to block
 * 
 * @param result the resultant 
 * @param fp fingerprint
 */
void HHash::CovertFPtoBlocks(mpz_t result[BLOCK_NUM], const char* fp) {
    for (size_t i = 0; i < BLOCK_NUM; i++) {
        uint32_t tmp = 0;
        memcpy(&tmp, fp + i * sizeof(uint32_t), sizeof(uint32_t));
        // TODO: may use the same mpt_z variabel to reduce the memory allocation
        mpz_init_set_ui(result[i], tmp);
    }
}

/**
 * @brief Compute the value of multiplication of block and mulVal
 * 
 * @param block the input block (also store the result)
 * @param mulVal another operand 
 */
void HHash::ComputeMulForBlock(mpz_t block[BLOCK_NUM], mpz_t mulVal) {
    for (size_t i = 0; i < BLOCK_NUM; i++) {
        mpz_mul(block[i], block[i], mulVal);
        mpz_mod(block[i], block[i], p_);
    }
}


/**
 * @brief Destroy the HHash object
 * 
 */
HHash::~HHash() {

    fprintf(stderr, "HHash: start to destory the HHash.\n");

    // clear big primes
    mpz_clear(p_);
    mpz_clear(q_);

    //  clear the parameter vector
    for (size_t i = 0; i < BLOCK_NUM; i++) {
        mpz_clear(g_[i]);
    }
}