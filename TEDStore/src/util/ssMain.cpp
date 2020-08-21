/**
 * @file ssMain.cpp
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief provide the secret share according to the given secret 
 * @version 0.1
 * @date 2020-08-21
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#include <bits/stdc++.h> 
#include <stdio.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric> 
using namespace std;

// Function to calculate the value 
// of y 
// y = poly[0] + x*poly[1] + x^2*poly[2] + ... 
int calculate_Y(int x, vector<int>& poly) 
{ 
    // Initializing y 
    int y = 0; 
    int temp = 1; 
  
    // Iterating through the array 
    for (auto coeff : poly) { 
  
        // Computing the value of y 
        y = (y + (coeff * temp)); 
        temp = (temp * x); 
    } 
    return y; 
} 
  
// Function to perform the secret 
// sharing algorithm and encode the 
// given secret 
void secret_sharing(int S, vector<pair<int, int> >& points, 
                    int N, int K) 
{ 
    // A vector to store the polynomial 
    // cofficient of K-1 degree 
    vector<int> poly(K); 
  
    // Randomly choose K - 1 numbers but 
    // not zero and poly[0] is the secret 
    // create polynomial for this 
  
    poly[0] = S; 
  
    for (int j = 1; j < K; ++j) { 
        int p = 0; 
        while (p == 0) 
  
            // To keep the random values 
            // in range not too high 
            // we are taking mod with a 
            // prime number around 1000 
            p = (rand() % 997); 
  
        // This is to ensure we did not 
        // create a polynomial consisting 
        // of zeroes. 
        poly[j] = p; 
    } 
  
    // Generating N points from the 
    // polynomial we created 
    for (int j = 1; j <= N; ++j) { 
        int x = j; 
        int y = calculate_Y(x, poly); 
  
        // Points created on sharing 
        points[j - 1] = { x, y }; 
    } 
} 
  
// This structure is used for fraction 
// part handling multiplication 
// and addition of fractiontion 
struct fraction { 
    int num, den; 
  
    // A fraction consists of a 
    // numerator and a denominator 
    fraction(int n, int d) 
    { 
        num = n, den = d; 
    } 
  
    // If the fraction is not 
    // in its reduced form 
    // reduce it by dividing 
    // them with their GCD 
    void reduce_fraction(fraction& f) 
    { 
        int gcd = __gcd(f.num, f.den); 
        f.num /= gcd, f.den /= gcd; 
    } 
  
    // Performing multiplication on the 
    // fraction 
    fraction operator*(fraction f) 
    { 
        fraction temp(num * f.num, den * f.den); 
        reduce_fraction(temp); 
        return temp; 
    } 
  
    // Performing addition on the 
    // fraction 
    fraction operator+(fraction f) 
    { 
        fraction temp(num * f.den + den * f.num, 
                      den * f.den); 
  
        reduce_fraction(temp); 
        return temp; 
    } 
}; 
  
// Function to generate the secret 
// back from the given points 
// This function will use Lagrange Basis Polynomial 
// Instead of finding the complete Polynomial 
// We only required the poly[0] as our secret code, 
// thus we can get rid of x terms 
int Generate_Secret(int x[], int y[], int M, int adjust) 
{ 
    fraction ans(0, 1); 
    fraction adjustVal(adjust, 1);
    // Loop to iterate through the given 
    // points 
    for (int i = 0; i < M; ++i) { 
        fraction tmp(1, 1);
        // Initializing the fraction 
        fraction l(y[i], 1); 
        for (int j = 0; j < M; ++j) { 
  
            // Computing the lagrange terms 
            if (i != j) { 
                fraction temp(-x[j], x[i] - x[j]); 
                tmp = tmp * temp; 
            } 
        } 
        tmp = tmp * adjustVal;
        cout << "num: " << tmp.num << " dem: " << tmp.den << endl;  
        l = tmp * l; 
        ans = ans + l; 
    } 
  
    // Return the secret 
    return ans.num / adjustVal.num; 
} 

vector<vector<int>> Comb(int N, int K)
{
    std::string bitmask(K, 1); // K leading 1's
    bitmask.resize(N, 0); // N-K trailing 0's
    vector<vector<int>> res;
    // print integers and permute bitmask
    do {
        vector<int> tempList;
        for (int i = 0; i < N; ++i) // [0..N-1] integers
        {   
            if (bitmask[i]) {
                std::cout << " " << (i + 1);
                tempList.push_back(i + 1);
            }
                
        }
        std::cout << std::endl;
        res.push_back(tempList);
    } while (std::prev_permutation(bitmask.begin(), bitmask.end()));

    return res;
}

int GetMaxDenParam(int x[], int M) {
    int maxDen = 1;
    // Loop to iterate through the given 
    // points 
    for (int i = 0; i < M; ++i) { 
        fraction tmp(1, 1);
        // Initializing the fraction  
        for (int j = 0; j < M; ++j) { 
  
            // Computing the lagrange terms 
            if (i != j) { 
                fraction temp(-x[j], x[i] - x[j]); 
                tmp = tmp * temp; 
            } 
        } 
        int denAbs = abs(tmp.den);
        if (denAbs > maxDen) {
            maxDen = denAbs;
        }
    }

    // Return the secret 
    return maxDen; 
}

int GetLCM(int n1, int n2) {
    int max = (n1 > n2) ? n1 : n2;
 
    do
    {
        if (max % n1 == 0 && max % n2 == 0)
        {
            break;
        }
        else
            ++max;
    } while (true);

    return max;
}

// Driver Code 
int main(int argc, char* argv[]) 
{ 
    if (argc != 4) {
        fprintf(stderr, "./secretShare [K] [N] [secret]\n");
        exit(EXIT_FAILURE);
    }
    
    int K = atoi(argv[1]);

    int N = atoi(argv[2]);

    if (K >= N) {
        fprintf(stderr, "K should be lower than N\n");
        exit(EXIT_FAILURE);
    }

    uint64_t secret = atol(argv[3]);

    // Vector to store the points 
    vector<pair<int, int> > points(N); 
  
    // Sharing of secret Code in N parts 
    secret_sharing(secret, points, N, K); 
  
    cout << "Secret is divided to " << N 
         << " Parts - " << endl; 
  
    for (int i = 0; i < N; ++i) { 
        cout << points[i].first << " "
             << points[i].second << endl; 
    } 

    vector<vector<int>> resList;
    resList = Comb(N, K);

    int adjustVal = 1;
    for (auto it = resList.begin(); it != resList.end(); it++) {
        int tempVal = 0;
        int indexList[K];
        int i = 0;
        for (auto subIt = it->begin(); subIt != it->end(); subIt++) {
            indexList[i] = *subIt;
            i++;
        }
        tempVal = GetMaxDenParam(indexList, K);
        adjustVal = GetLCM(adjustVal, tempVal);
    }
    cout << "The adjustment value: " << adjustVal << endl;

    return 0; 
} 