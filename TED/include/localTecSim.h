/// \file localTecSim.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of local tec simulator
/// \version 0.1
/// \date 2019-07-12
///
/// \copyright Copyright (c) 2019
///
#ifndef __LOCAL_TEC_SIM_H__
#define __LOCAL_TEC_SIM_H__

#include "sim.h"
#include "sparsepp/spp.h" /**for in memory hash table */
#include "optSolver.h"
#include "countMin.h"
#include "randomGen.h"
#include <unordered_set>
#include <sys/time.h>

class LocalTECSim : public Simulator {
    protected:

        /// \brief key generation process according to different threshold in a region
        ///
        /// \param chunkHash - chunk hash
        /// \param chunkHashLen - the length of chunk hash
        /// \param chunkSize - chunk size
        /// \param key - generated encryption key <return>
        /// \param threshold - the threshold during this region
        void LocalKeyGen(uint8_t* const chunkHash, size_t chunkHashLen, 
            uint64_t const chunkSize, uint8_t key[sizeof(int)], uint32_t threshold);

        /// \brief update the state according to the incoming chunk in global hash table
        ///
        /// \param chunkHash - chunk hash
        /// \param chunkHashLen - the length of chunk hash
        /// \param chunkSize - chunk size
        void GlobalUpdateState(uint8_t* const chunkHash, 
            size_t chunkHashLen, uint64_t const chunkSize);

        /// \brief update the state according to the incoming chunk in local hash table
        ///
        /// \param chunkHash - chunk hash
        /// \param chunkHashLen - the length of chunk hash
        /// \param chunkSize - chunk size
        void LocalUpdateState(uint8_t* const chunkHash,
            size_t chunkHashLen, uint64_t const chunkSize);


        inline void LocalHashTableCleanUp() {
            localKeyFreqTable_.clear();
        }

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

        /**the size of the region to do optimization*/
        size_t regionSize_;

        /**the hash table for solving the optimization*/
        spp::sparse_hash_map<std::string, uint64_t> localKeyFreqTable_;

        /**the hash table for fast count information*/
        spp::sparse_hash_map<std::string, uint64_t> globalKeyFreqTable_;

        /**local logical chunk counter*/
        size_t localCounter_;

        /**global logical chunk counter*/
        size_t globalCounter_;

        /**the batch size of each optimization unit*/
        size_t batchSize_ = 0;

        /**the array to store threshold */
        vector<uint32_t> thresholdArray_;

        /**storage blowup rate: [0, 1] */
        double blowUpRate_;

        /**sketch */
        CountMinSketch* cmSketch_;

        /**optimization solving times */
        uint32_t solveTimes_ = 0;

        /**total solving time*/
        uint64_t totalTime_ = 0;

        /**probalisitic option */
        bool enablePro = false;

        /**a random number generator */
        RandomGen* randomNumGen_;

        /**the type of distribution of random number */
        int distriType_;

    public:
        /// \brief Construct a new LocalTECSim object
        ///
        LocalTECSim() { 
            fprintf(stderr, "Initialize Local Tunable Encryption Simulator.\n");
            cmSketch_ = new CountMinSketch(SKETCH_WIDTH, SKETCH_DEPTH);
            
        }

        /// \brief Destroy the LocalTECSim object
        ///
        ~LocalTECSim() { 
            fprintf(stderr, "Start to destory Local Tunable Encryption Simulator.\n");
            delete cmSketch_;
        }
        
        /// \brief Set the Region Size object
        ///
        /// \param regionSize - size of optimization region
        inline void SetRegionSize(int regionSize) { 
            regionSize_ = regionSize; 
        }

        inline void SetBlowUpRate(double blowUpRate) {
            blowUpRate_ = blowUpRate;
        }

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the output file name
        void ProcessHashFile(std::string const inputFileName, 
          std::string const outputFileName); 

        /// \brief process an input hash file of encryption incremental local
        ///
        /// \param inputFileName - the input file name
        /// \param ouputFileName - the output file name
        void ProcessHashFileLocal(std::string const inputFileName, 
            std::string const ouputFileName);
        
        /// \brief Set the Batch Size object
        ///
        /// \param batchSize - the batch size
        inline void SetBatchSize(size_t batchSize) { batchSize_ = batchSize; }

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



#endif // !__LOCAL_TEC_SIM_H__