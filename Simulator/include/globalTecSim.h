/// \file globalTecSim.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of global tec simulator
/// \version 0.1
/// \date 2019-10-09
///
/// \copyright Copyright (c) 2019
///

#ifndef __GLOBAL_TEC_SIM_H__
#define __GLOBAL_TEC_SIM_H__

#include "sim.h"
#include "sparsepp/spp.h"
#include "optSolver.h"
#include "countMin.h"
#include "randomGen.h"
#include <unordered_set>
#include <sys/time.h>

class GlobalTECSim : public Simulator {
    protected:
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

        /**the hash table for fast count information*/
        spp::sparse_hash_map<std::string, uint64_t> globalKeyFreqTable_;

        /**the threshold in TEC */
        uint32_t threshold_;

        /// \brief update the state according to the incoming chunk in global hash table
        ///
        /// \param chunkHash 
        /// \param chunkHashLen 
        /// \param chunkSize 
        void GlobalUpdateState(uint8_t* const chunkHash, 
            size_t chunkHashLen, uint64_t const chunkSize);

        /// \brief key generation process
        ///
        /// \param chunkHash - chunk hash
        /// \param chunkHashLen - the length of chunk hash
        /// \param chunkSize - chunk size
        /// \param key - generated encryption key <return>
        void KeyGen(uint8_t* const chunkHash, size_t chunkHashLen, 
            uint64_t const chunkSize, uint8_t key[sizeof(int)]);
        
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

    public:
        /// \brief Construct a new Global TECSim M object
        ///
        GlobalTECSim() {
            fprintf(stderr, "Initialize Global Tunable Encryption Simulator.\n");
            cmSketch_ = new CountMinSketch(SKETCH_WIDTH, SKETCH_DEPTH);
        }

        /// \brief Destroy the Global TECSim object
        ///
        ~GlobalTECSim() {
            fprintf(stderr, "Start to destory Global Tunable Encryption Simulator.\n");
            delete cmSketch_;
        }

        inline void SetBlowUpRate(double blowUpRate) {
            blowUpRate_ = blowUpRate;
        }

        inline void EnablePro() {
            enablePro = true;
        }

        /// \brief Set the Probabilistic number generator 
        ///
        inline void SetDistri(int type) {
            distriType_ = type;
            randomNumGen_ = new RandomGen();
        }

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the out file name
        void ProcessHashFile(std::string const inputFileName,
            std::string const outputFileName);
};



#endif // !__GLOBAL_TEC_SIM_H__