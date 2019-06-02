#ifndef SIME_OP_SOLVER_H_
#define SIME_OP_SOLVER_H_
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#define DEBUG 0
/* fingerprint size */
#define FP_SIZE 32

using namespace std;

class OpSolver {
public:
    OpSolver(int m, vector<pair<string, int>> inputDistribution);
    ~OpSolver();
    double GetOptimal();
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

    vector<pair<string, int>> inputFeqDistr_;
    vector<double> outputFeqDistr_;
};

#endif