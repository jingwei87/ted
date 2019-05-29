#ifndef SIME_OP_SOLVER_H_
#define SIME_OP_SOLVER_H_
#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <algorithm>
#include <stdio.h>
#include <math.h>
#include <cmath>
#include <fstream>
#include <string.h>
#include <stdint.h>

#define DEBUG 0
/* fingerprint size */
#define FP_SIZE 6

using namespace std;

class OpSolver {
    public:
        OpSolver(int m, vector<pair<string, int> > inputDistribution);
        ~OpSolver();
        void GetOptimal();
        void PrintResult(FILE* fpOut);
        bool CheckConstrain(int startIndex);
        bool Compare(pair<string, int> a, pair<string, int> b);
        void PrintDistri(FILE* outputP, FILE* outputC);
    private:
        int m_;
        int n_;
        int sum_;
        int currentIndex_;
        int remainSum_;
        double storageBlow_;
        double maxEntropy_;
        double originalEntropy_;

        vector<pair<string, int> > inputFeqDistr_;  
        vector<double> outputFeqDistr_;      
};

#endif
