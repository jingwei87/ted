/// \file minHashSim.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of MinHash simulator
/// \version 0.1
/// \date 2019-08-12
///
/// \copyright Copyright (c) 2019
///
#ifndef __MIN_HASH_SIM_H__
#define __MIN_HASH_SIM_H__

#include "sim.h"
#include <queue>

/**Variable-size segmentation */
#define AVG_SEGMENT_SIZE ((2<<20)) // 1MB defaults
#define MIN_SEGMENT_SIZE ((2<<19)) // 512KB
#define MAX_SEGMENT_SIZE ((2<<21)) // 2MB

/**assume average chunk size is 8KB */
#define DIVISOR ((AVG_SEGMENT_SIZE - MIN_SEGMENT_SIZE) / (8*(2<<10)))
#define PATTERN 1

class ChunkInfo {
    public:
        uint8_t fp[FP_SIZE+1];
        uint64_t size;

        /**constructers */
        ChunkInfo();
        ChunkInfo(ChunkInfo const &a);
        ChunkInfo(uint8_t const inFp[FP_SIZE+1], uint64_t const inSize);

        /**deconstructor */
        ~ChunkInfo();
};

class MinHashSim : public Simulator {
    private:
        
        /// \brief decide the end of border of the segment
        ///
        /// \param chunkHash - input chunk hash
        /// \param chunkSize - chunk size
        /// \return true - the end
        /// \return false - not the end 
        bool EndOfSegment(uint8_t* const chunkHash, uint64_t const chunkSize);
        
        /// \brief generate MLE key based on minimum chunk fingerprint
        ///
        /// \param chunkHash - hash of the chunk
        /// \param key - encryption key
        void MinHashKeyGen(uint8_t* const chunkHash, uint8_t key[FP_SIZE + 1]);

        /// \brief add chunk into queue
        ///
        /// \param chunkHash - hash of the chunk 
        /// \param chunkSize - size of the chunk
        void MinHashUpdateState(uint8_t* const chunkHash, 
            uint64_t const chunkSize);

        /**queue of chunks in one segment */
        std::queue<ChunkInfo> chunkQueue_;
        uint64_t segmentSize_ = 0UL;
        uint8_t minChunk_[FP_SIZE+1];


    public:

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the output file name
        void ProcessHashFile(std::string const inputFileName, 
          std::string const outputFileName); 
        
        /// \brief Construct a new Min Hash Sim object
        ///
        MinHashSim();

        /// \brief Destroy the Min Hash Sim object
        ///
        ~MinHashSim();
        
};

#endif // ! __MIN_HASH_SIM_H__