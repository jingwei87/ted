/// \file tecSim.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of TEC simulator
/// \version 0.1
/// \date 2019-07-11
///
/// \copyright Copyright (c) 2019
///

#ifndef __TEC_SIM_H__
#define __TEC_SIM_H__

#include "sim.h"
#include "sparsepp/spp.h" /**for in memory hash table */
#include "countMin.h"
#include "randomGen.h"
#include <unordered_set>

class TECSim : public Simulator {
    protected:
        
        /// \brief key generation process
        ///
        /// \param chunkHash - chunk hash
        /// \param chunkHashLen - the length of chunk hash
        /// \param chunkSize - chunk size
        /// \param key - generated encryption key <return>
        void KeyGen(uint8_t* const chunkHash, size_t chunkHashLen, 
            uint64_t const chunkSize, uint8_t key[sizeof(int)]);

        /// \brief update the state according to the incoming chunk
        ///
        /// \param chunkHash - chunk hash
        /// \param chunkHashLen - the length of chunk hash
        /// \param chunkSize - chunk size
        void TECUpdateState(uint8_t* const chunkHash, size_t chunkHashLen, uint64_t const chunkSize);

        /// \brief simulate the encryption process: directly append the (frequency / T) to the 
        /// end of hash
        ///
        /// \param msg - the original input message
        /// \param msgLen - the length of message
        /// \param key - the encryption key 
        /// \param keyLen - the length of the encrytion key
        /// \param output 
        void SimTECEncrypt(uint8_t* const msg, size_t const msgLen, uint8_t* const key,
            size_t const keyLen, uint8_t output[FP_SIZE + sizeof(int) + 1]);

        /**the threshold in TEC */
        uint32_t threshold_;

        /**the hash table for solving the optimization*/
        spp::sparse_hash_map<std::string, uint64_t> keyFreqTable_;
        
        CountMinSketch* cmSketch_;
        
        /**probalisitic option */
        bool enablePro = false;

        /**a random number generator */
        RandomGen* randomNumGen_;

        /**the type of distribution of random number */
        int distriType_;

    public:
        /// \brief Construct a new TECSim object
        ///
        TECSim() { 
            fprintf(stderr, "Initialize Tunable Encryption Simulator.\n");
            cmSketch_ = new CountMinSketch(SKETCH_WIDTH, SKETCH_DEPTH);
        }

        /// \brief Destroy the TECSim object
        ///
        ~TECSim() { 
            fprintf(stderr, "Destory Tunable Encryption Simulator.\n");
            delete cmSketch_;
        }

        void SetThreshold(int threshold) { threshold_ = threshold; }

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the output file name
        void ProcessHashFile(std::string const inputFileName, 
          std::string const outputFileName); 
        
        /// \brief enable probalistic key generation
        ///
        /// \param type 
        inline void EnablePro() {
            enablePro = true;
        }

        /// \brief Set the Probabilistic number generator 
        ///
        inline void SetDistri(int type) {
            distriType_ = type;
            randomNumGen_ = new RandomGen();
        }
};

#endif // !__TEC_SIM_H__
