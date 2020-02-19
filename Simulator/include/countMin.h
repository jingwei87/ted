/// \file countMin.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of Count-Min sketch 
/// \version 0.1
/// \date 2019-08-08
///
/// \copyright Copyright (c) 2019
///
#ifndef __COUNT_MIN_H__
#define __COUNT_MIN_H__
#include <iostream>
#include <string>
#include <stdio.h>
#include <stdint.h>
#include "murmurHash3.h"

#define LONG_PRIME 4294967311l

#define NUM_PARAMETER 1

/**get minimum value*/
template <typename T>
inline T const& Min(T const& a, T const& b) {
    return a < b ? a : b;
}

class CountMinSketch {
    private:
        /**width, depth */
        uint32_t width_;
        uint32_t depth_;

        /**eps (for error), 0.01 < eps < 1 */
        double eps_;

        /**gamma (probability for accuracy), 0 < gamma < 1 */
        double gamma_;

        /**variables for generate hash function 
         * aj, bj are positive integers
        */
        uint32_t aj_, bj_;

        /**total count */
        uint32_t total_;

        /**array of arrays of counters */
        uint32_t** counterArray_;

        /**array of hash values for a particular item
         * contains two element arrays {aj, bj}
         */
        uint32_t** hashArray_;

        /**generate new aj, bj */
        void GenerateAjBj(uint32_t** hash, uint32_t i);

    public:

        /// \brief return the pos of first row
        ///
        /// \param chunkHash 
        /// \param chunkHashLen 
        /// \return uint32_t - the position 
        uint32_t ReturnFirstRowPos(uint8_t* const chunkHash, size_t chunkHashLen);

        /// \brief Construct a new Count Min Sketch object
        ///
        /// \param width 
        /// \param depth 
        CountMinSketch(uint32_t width, uint32_t depth);

        /// \brief update the count in sketch 
        ///
        /// \param chunkHash 
        /// \param chunkHashLen 
        /// \param count 
        void Update(uint8_t* const chunkHash, size_t chunkHashLen, uint32_t count);

        /// \brief estimate the count in sketch
        ///
        /// \param chunkHash 
        /// \param chunkHashLen 
        /// \return uint32_t 
        uint32_t Estimate(uint8_t* const chunkHash, size_t chunkHashLen);

        /// \brief return total count
        ///
        /// \return uint32_t 
        uint32_t TotalCount();

        /// \brief generate a hash value for a string
        ///
        /// \param str 
        /// \return uint32_t 
        uint32_t HashStr(const char* str);

        /// \brief Destroy the Count Min Sketch object
        ///
        ~CountMinSketch();

        /// \brief clear all buckets in the sketch
        ///
        void ClearUp();

        /// \brief Get the First Row of the sketch
        ///
        /// \return uint32_t* - the pointer points to the first row of sketch
        inline uint32_t* GetFirstRow() {
            return counterArray_[0];
        }
};



#endif // !__COUNT_MIN_H__