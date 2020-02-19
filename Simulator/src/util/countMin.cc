/// \file countMin.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interfaces of CountMin Sketch
/// \version 0.1
/// \date 2019-08-08
///
/// \copyright Copyright (c) 2019
///

#include "countMin.h"
#include <cmath>
#include <cstdlib>
#include <limits>
#include <ctime>

using namespace std;

/// \brief Construct a new Count Min Sketch object
///
/// \param width 
/// \param depth 
CountMinSketch::CountMinSketch(uint32_t width, uint32_t depth) {
    // if (!(0.009 <= eps && eps < 1)) {
    //     fprintf(stderr, "eps must be in this range: [0.01, 1]\n");
    //     exit(EXIT_FAILURE);
    // } else if (!(0 < gamma && gamma < 1)) {
    //     fprintf(stderr, "gamma must be in this range: (0, 1)\n");
    //     exit(EXIT_FAILURE);
    // }

    width_ = width;
    depth_ = depth;
    
    fprintf(stderr, "Width in sketch: %u.\n", width_);
    fprintf(stderr, "Depth in sketch: %u.\n", depth_);

    total_ = 0;

    /**initialize counter array */
    counterArray_ = (uint32_t**) malloc(sizeof(uint32_t*) * depth_);
    size_t i, j;
    for (i = 0; i < depth_; i++) {
        counterArray_[i] = (uint32_t*) malloc(sizeof(uint32_t) * width_);
        for (j = 0; j < width_; j++) {
            counterArray_[i][j] = 0;
        }
    }

    /**initialize depth_ pairwise indepent hashes */
    hashArray_ = (uint32_t**) malloc(sizeof(uint32_t*) * depth_);

    for (i = 0; i < depth_; i++) {
        /**just one seed for each murmurhash */
        hashArray_[i] = (uint32_t*) malloc(sizeof(uint32_t) * NUM_PARAMETER);
        /**
         * 0 for first row hash
         * 1 for second row hash
         * 2 for third row hash
         * 3 for fourth row hash
         */
        hashArray_[i][0] = i;
    }
}

/// \brief estimate the count in sketch
///
/// \param chunkHash 
/// \param chunkHashLen 
/// \return uint32_t 
uint32_t CountMinSketch::Estimate(uint8_t* const chunkHash, size_t chunkHashLen) {
    uint32_t minVal = numeric_limits<uint32_t>::max();
    uint32_t hashVal = 0;
    size_t j = 0;
    size_t pos = 0;
    for (j = 0; j < depth_; j++) {
        MurmurHash3_x86_32(chunkHash, chunkHashLen, hashArray_[j][0], &hashVal);
        pos = hashVal % width_;
        minVal = min(minVal, counterArray_[j][pos]);
    }
    return minVal;
}

/**generate new aj, bj */
void CountMinSketch::GenerateAjBj(uint32_t** hash, uint32_t i) {
    hashArray_[i][0] = static_cast<uint32_t>(static_cast<double>(rand()) *
        static_cast<double>(LONG_PRIME) / static_cast<double>(RAND_MAX) + 1);
    hashArray_[i][1] = static_cast<uint32_t>(static_cast<double>(rand()) *
        static_cast<double>(LONG_PRIME) / static_cast<double>(RAND_MAX) + 1);
}

/// \brief generate a hash value for a string
///
/// \param str 
/// \return uint32_t 
uint32_t CountMinSketch::HashStr(const char* str) {
    uint64_t hash = 5381;
    uint32_t c;
    while (c = *str++) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/// \brief Destroy the Count Min Sketch object
///
CountMinSketch::~CountMinSketch() {
    
    size_t index;
    
    for (index = 0; index < depth_; index++) {
        free(hashArray_[index]);
    }
    free(hashArray_);

    for (index = 0; index < depth_; index++) {
        free(counterArray_[index]);
    }
    free(counterArray_);

}

/// \brief return total count
///
/// \return uint32_t 
uint32_t CountMinSketch::TotalCount() {
    return total_;
}

/// \brief update the count in sketch 
///
/// \param chunkHash 
/// \param chunkHashLen 
/// \param count 
void CountMinSketch::Update(uint8_t* const chunkHash, size_t chunkHashLen, uint32_t count) {
    total_ += count;
    uint32_t hashVal = 0;
    size_t j = 0;
    size_t pos = 0;
    for (j = 0; j < depth_; j++) {
       MurmurHash3_x86_32(chunkHash, chunkHashLen, hashArray_[j][0], &hashVal);
       pos = hashVal % width_;
       counterArray_[j][pos] += count;
    }
}


/// \brief clear all buckets in the sketch
///
void CountMinSketch::ClearUp() {
    size_t indexWidth;
    size_t indexDepth;
    for (indexWidth = 0; indexWidth < width_; indexWidth++) {
        for (indexDepth = 0; indexDepth < depth_; indexDepth++) {
            counterArray_[indexDepth][indexWidth] = 0;
        }
    }
}

/// \brief return the pos of first row
///
/// \param chunkHash 
/// \param chunkHashLen
/// \return uint32_t - the position 
uint32_t CountMinSketch::ReturnFirstRowPos(uint8_t* const chunkHash, size_t chunkHashLen) {
    uint32_t hashVal = 0;
    MurmurHash3_x86_32(chunkHash, chunkHashLen, hashArray_[0][0], &hashVal);
    uint32_t pos = hashVal % width_;
    return pos;
}