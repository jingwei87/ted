/// \file SIM.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief 
/// \version 0.1
/// \date 2019-07-09
///
/// \copyright Copyright (c) 2019
///


#include <iostream>
#include <stdio.h>
#include <sstream>
#include <string>
#include <time.h>

#include "../../include/sim.h"
#include "../../include/convSim.h"
#include "../../include/statsRecord.h"
#include "../../include/tecSim.h"
#include "../../include/localTecSim.h"
#include "../../include/proTecSim.h"
#include "../../include/tSim.h"
#include "../../include/intuiSim.h"
#include "../../include/minHashSim.h"
#include "../../include/globalTecSim.h"
#include "../../include/skeSim.h"

using namespace std;


void Usage(char* const program, int operand) {
    fprintf(stderr, "operand number: %d.\n", operand);
    fprintf(stderr, "1. bted (Basic TED): ./TEDSim [inputfile] [outputfile] [threshold] [distribution-type]\n" \
            "2, fted (Full TED):./TEDSim [inputfile] [outputfile] [batch-size] [storage blowup >=1] [distribution type]\n" \
            "3, minhash: ./TEDSim [inputfile] [outputfile]\n" \
            "4, mle: ./TEDSim [inputfile] [outputfile]\n" \
            "5, ske: ./TEDSim [inputfile] [outputfile]\n" \
            "[distribution-type (0) Disable (1)uniform-distribution" \
            "(2)poisson-distribution (3)normal-distribution " \
            "(4)geo-distribution]\n", program);
}

int main(int argc, char* argv[]) {
    
    fprintf(stderr, "Start simulation.\n");

    if (argc < 4) {
        Usage(argv[0], argc);
        return 1;
    }

    string inputFile = string(argv[1]);
    string outputFile = string(argv[2]);
    string method = string(argv[3]);
/**start to test */
    struct timeval startTime;
    gettimeofday(&startTime, NULL);
    StatsRecorder::GetInstance()->OpenStatistics(startTime);

    if (method == "mle") {
        ConvSim* mySim;
        mySim = new ConvSim();
        STAT_TIME_PROCESS(mySim->ProcessHashFile(inputFile, outputFile), 
            StatusType::SIMULATOR_TIME);
        delete mySim;
    } else if (method == "bted") {
        TECSim* mySim;
        mySim = new TECSim();
        if (argc < 5) {
            fprintf(stderr, "please enter the threshold, %s:%d\n", FILE_NAME, CURRENT_LIEN);
            exit(1);
        }
        int threshold = atoi(argv[4]);
        mySim->SetThreshold(threshold);
        if (argc < 6) {
            fprintf(stderr, "please enter the distribution type.\n ");            
            Usage(argv[0], argc);
            exit(1);
        }
        int distriType = atoi(argv[5]);
        if (distriType != 0) {
            mySim->EnablePro();
            mySim->SetDistri(distriType);
        } 
        STAT_TIME_PROCESS(mySim->ProcessHashFile(inputFile, outputFile),
            StatusType::SIMULATOR_TIME);
        delete mySim;
    } else if (method == "fted") {
        LocalTECSim* mySim;
        mySim = new LocalTECSim();
        if (argc < 5) {
            fprintf(stderr, "please enter the batch size, %s:%d\n", FILE_NAME, CURRENT_LIEN);
            Usage(argv[0], argc);
            exit(1);
        }
        size_t batchSize = atol(argv[4]);
        mySim->SetBatchSize(batchSize);

        if (argc < 6) {
            fprintf(stderr, "please enter the blowup rate, %s:%d\n", FILE_NAME, CURRENT_LIEN);
            Usage(argv[0],argc);
            exit(1);
        }
        double blowupRate = atof(argv[5]);
        mySim->SetBlowUpRate(blowupRate);
        
        if (argc < 7) {
            fprintf(stderr, "please enter the distribution type.\n ");            
            Usage(argv[0], argc);
            exit(1);
        }

        int distriType = atoi(argv[6]);
        if (distriType != 0) {
            mySim->EnablePro();
            mySim->SetDistri(distriType);
        } 

        STAT_TIME_PROCESS(mySim->ProcessHashFile(inputFile, outputFile),
            StatusType::SIMULATOR_TIME);
        delete mySim;

    } else if (method == "minhash") {
        MinHashSim* mySim;
        mySim = new MinHashSim();
        STAT_TIME_PROCESS(mySim->ProcessHashFile(inputFile, outputFile),
            StatusType::SIMULATOR_TIME);
        delete mySim;
    } else if (method == "ske") {
        SKESim* mySim;
        mySim = new SKESim();
        STAT_TIME_PROCESS(mySim->ProcessHashFile(inputFile, outputFile),
            StatusType::SIMULATOR_TIME);
        delete mySim;
    } else {
        fprintf(stderr,"method:%s cannot support, %s:%d\n", method.c_str(), FILE_NAME,      
            CURRENT_LIEN);
        Usage(argv[0], argc);
        exit(1);
    }

    double simulateSecond = (StatsRecorder::GetInstance()->GetTime(StatusType::SIMULATOR_TIME)) / 1000000.0;
    fprintf(stderr, "analysis time: %lf\n", simulateSecond);

    return 0;
}