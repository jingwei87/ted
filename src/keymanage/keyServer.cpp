#include "keyServer.hpp"
#include <sys/time.h>
extern Configure config;

struct timeval timestartKeyServer;
struct timeval timeendKeyServer;

void PRINT_BYTE_ARRAY_KEY_SERVER(
    FILE* file, void* mem, uint32_t len)
{
    if (!mem || !len) {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t* array = (uint8_t*)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for (i = 0; i < len - 1; i++) {
        fprintf(file, "0x%x, ", array[i]);
        if (i % 8 == 7)
            fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

keyServer::keyServer(ssl* keyServerSecurityChannelTemp)
{
    keySecurityChannel_ = keyServerSecurityChannelTemp;
    sketchTableWidith_ = config.getSketchTableWidth();
    sketchTable_ = (u_int**)malloc(sizeof(u_int*) * 4);
    for (int i = 0; i < 4; i++) {
        sketchTable_[i] = (u_int*)malloc(sizeof(u_int) * sketchTableWidith_);
    }
    sketchTableCounter_ = 0;
    T_ = 1;
    opSolverFlag_ = false;
    opm_ = sketchTableWidith_ * (1 + config.getStorageBlowPercent());
    gen_ = mt19937_64(rd_());
    memset(keyServerPrivate_, 1, 64);
    optimalSolverComputeItemNumberThreshold_ = config.getOptimalSolverComputeItemNumberThreshold();
}

keyServer::~keyServer()
{
    for (int i = 0; i < 4; i++) {
        free(sketchTable_[i]);
    }
    free(sketchTable_);
    delete keySecurityChannel_;
}

void keyServer::runKeyGen(SSL* connection)
{
    double keySeedGenTime = 0;
    long diff;
    double second;
    char hash[config.getKeyBatchSize() * 4 * sizeof(uint32_t)];
    u_int hashNumber[4];
    u_char newKeyBuffer[64 + 4 * sizeof(uint32_t) + sizeof(int)];
    while (true) {
        int recvSize = 0;
        if (!keySecurityChannel_->recv(connection, hash, recvSize)) {
            cerr << "KeyServer : client exit" << endl;
            multiThreadEditSketchTableMutex_.lock();
            for (int i = 0; i < sketchTableWidith_; i++) {
                sketchTable_[0][i] = 0;
                sketchTable_[1][i] = 0;
                sketchTable_[2][i] = 0;
                sketchTable_[3][i] = 0;
            }
            multiThreadEditSketchTableMutex_.unlock();
            multiThreadEditTMutex_.lock();
            T_ = 1;
            multiThreadEditTMutex_.unlock();
            cout << "keyServer : generate key seed time = " << keySeedGenTime << " s" << endl;
            return;
        }
        int recvNumber = recvSize / (4 * sizeof(uint32_t));
        cerr << "KeyServer : recv hash number = " << recvNumber << endl;
        u_char key[recvNumber * CHUNK_ENCRYPT_KEY_SIZE];
        multiThreadEditSketchTableMutex_.lock();
        if (BREAK_DOWN_DEFINE) {
            gettimeofday(&timestartKeyServer, NULL);
        }
        for (int i = 0; i < recvNumber; i++) {
            int sketchTableSearchCompareNumber = 0;
            for (int j = 0; j < 4; j++) {
                memcpy(&hashNumber[j], hash + i * 4 * sizeof(uint32_t) + j * sizeof(uint32_t), sizeof(uint32_t));
                sketchTable_[j][hashNumber[j] % sketchTableWidith_]++;
            }
            sketchTableSearchCompareNumber = sketchTable_[0][hashNumber[0] % sketchTableWidith_];
            if (sketchTableSearchCompareNumber > sketchTable_[1][hashNumber[1] % sketchTableWidith_]) {
                sketchTableSearchCompareNumber = sketchTable_[1][hashNumber[1] % sketchTableWidith_];
            }
            if (sketchTableSearchCompareNumber > sketchTable_[2][hashNumber[2] % sketchTableWidith_]) {
                sketchTableSearchCompareNumber = sketchTable_[2][hashNumber[2] % sketchTableWidith_];
            }
            if (sketchTableSearchCompareNumber > sketchTable_[3][hashNumber[3] % sketchTableWidith_]) {
                sketchTableSearchCompareNumber = sketchTable_[3][hashNumber[3] % sketchTableWidith_];
            }

            int param = floor(sketchTableSearchCompareNumber / T_);

            if (KEY_SERVER_RANDOM_TYPE == KEY_SERVER_POISSON_RAND) {
                int lambda = ceil(param / 2.0);
                poisson_distribution<> dis(lambda);
                param = dis(gen_);
            } else if (KEY_SERVER_RANDOM_TYPE == KEY_SERVER_UNIFORM_INT_RAND) {
                uniform_int_distribution<> dis(0, param);
                param = dis(gen_);
            } else if (KEY_SERVER_RANDOM_TYPE == KEY_SERVER_GEOMETRIC_RAND) {
                geometric_distribution<> dis;
                int random = dis(gen_);
                if (param < random)
                    param = 0;
                else
                    param = param - random;
            } else if (KEY_SERVER_RANDOM_TYPE == KEY_SERVER_NORMAL_RAND) {
                normal_distribution<> dis(param, 1);
                int result = round(dis(gen_));
                if (result < 0)
                    param = 0;
                else
                    param = result;
            }
            memcpy(newKeyBuffer, keyServerPrivate_, 64);
            memcpy(newKeyBuffer + 64, hash + i * 4 * sizeof(uint32_t), 4 * sizeof(uint32_t));
            memcpy(newKeyBuffer + 64 + 4 * sizeof(uint32_t), &param, sizeof(int));
            unsigned char currentKeySeed[CHUNK_ENCRYPT_KEY_SIZE];
#ifdef HIGH_SECURITY
            SHA256(newKeyBuffer, 64 + 4 * sizeof(uint32_t) + sizeof(int), currentKeySeed);
#else
            MD5(newKeyBuffer, 64 + 4 * sizeof(uint32_t) + sizeof(int), currentKeySeed);
#endif
            memcpy(key + i * CHUNK_ENCRYPT_KEY_SIZE, currentKeySeed, CHUNK_ENCRYPT_KEY_SIZE);
        }
        sketchTableCounter_ += recvNumber;
        if (BREAK_DOWN_DEFINE) {
            gettimeofday(&timeendKeyServer, NULL);
            diff = 1000000 * (timeendKeyServer.tv_sec - timestartKeyServer.tv_sec) + timeendKeyServer.tv_usec - timestartKeyServer.tv_usec;
            second = diff / 1000000.0;
            keySeedGenTime += second;
        }
        multiThreadEditSketchTableMutex_.unlock();

        if (!keySecurityChannel_->send(connection, (char*)key, recvNumber * CHUNK_ENCRYPT_KEY_SIZE)) {
            cerr << "KeyServer : error send back chunk key to client" << endl;
            multiThreadEditSketchTableMutex_.lock();
            for (int i = 0; i < sketchTableWidith_; i++) {
                sketchTable_[0][i] = 0;
                sketchTable_[1][i] = 0;
                sketchTable_[2][i] = 0;
                sketchTable_[3][i] = 0;
            }
            multiThreadEditSketchTableMutex_.unlock();
            multiThreadEditTMutex_.lock();
            T_ = 1;
            multiThreadEditTMutex_.unlock();
            cout << "keyServer : generate key seed time = " << keySeedGenTime << " s" << endl;
            return;
        }
        if (sketchTableCounter_ >= optimalSolverComputeItemNumberThreshold_) {
            multiThreadEditTMutex_.lock();
            opInput_.clear();
            opInput_.reserve(sketchTableWidith_);
            for (int i = 0; i < sketchTableWidith_; i++) {
                stringstream ss;
                ss << i;
                string strTemp = ss.str();
                opInput_.push_back(make_pair(strTemp, sketchTable_[0][i]));
            }
            cerr << "keyServer : start optimization solver" << endl;
            sketchTableCounter_ = 0;
            opSolverFlag_ = true;
            multiThreadEditTMutex_.unlock();
        }
    }
}

void keyServer::runOptimalSolver()
{
    while (true) {
        if (opSolverFlag_) {
            std::lock_guard<std::mutex> locker(multiThreadEditTMutex_);
            OpSolver* solver = new OpSolver(opm_, opInput_);
            T_ = solver->GetOptimal();
            opSolverFlag_ = false;
            delete solver;
        }
    }
}
