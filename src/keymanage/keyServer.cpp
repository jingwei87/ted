#include "keyServer.hpp"
#include <sys/time.h>
extern Configure config;

struct timeval timestartKeyServer;
struct timeval timeendKeyServer;
struct timeval timestartKeyServerTotal;
struct timeval timeendKeyServerTotal;
struct timeval timestartKeyServerRecv;
struct timeval timeendKeyServerRecv;

keyServer::keyServer(ssl* keyServerSecurityChannelTemp)
{
    cryptoObj_ = new CryptoPrimitive();
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
    delete cryptoObj_;
}

#if SINGLE_THREAD_KEY_MANAGER == 1

void keyServer::runKeyGen(SSL* connection)
{
#if BREAK_DOWN_DEFINE == 1
    double keySeedGenTime = 0;
    double totalThreadTime = 0;
    double optimalComputeTime = 0;
    double totalRecvTime = 0;
    long diff;
    double second;
#endif
    char hash[config.getKeyBatchSize() * 4 * sizeof(uint32_t)];
    u_int hashNumber[4];
    u_char newKeyBuffer[64 + 4 * sizeof(uint32_t) + sizeof(int)];
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartKeyServerTotal, NULL);
#endif
    while (true) {
        int recvSize = 0;
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timestartKeyServerRecv, NULL);
#endif
        bool recvStatus = keySecurityChannel_->recv(connection, hash, recvSize);
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timeendKeyServerRecv, NULL);
        diff = 1000000 * (timeendKeyServerRecv.tv_sec - timestartKeyServerRecv.tv_sec) + timeendKeyServerRecv.tv_usec - timestartKeyServerRecv.tv_usec;
        second = diff / 1000000.0;
        totalRecvTime += second;
#endif
        if (!recvStatus) {
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
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timeendKeyServerTotal, NULL);
            diff = 1000000 * (timeendKeyServerTotal.tv_sec - timestartKeyServerTotal.tv_sec) + timeendKeyServerTotal.tv_usec - timestartKeyServerTotal.tv_usec;
            second = diff / 1000000.0;
            cout << "keyServer : generate key seed time = " << keySeedGenTime << " s" << endl;
            cout << "keyServer : compute optimal time = " << optimalComputeTime << " s" << endl;
            cout << "keyServer : total work time = " << second - totalRecvTime << " s" << endl;
            cout << "keyServer : total recv time = " << totalRecvTime << " s" << endl;
#endif
            return;
        }
        int recvNumber = recvSize / (4 * sizeof(uint32_t));
        cout << "KeyServer : recv hash number = " << recvNumber << endl;
        u_char key[recvNumber * CHUNK_ENCRYPT_KEY_SIZE];
        multiThreadEditSketchTableMutex_.lock();
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timestartKeyServer, NULL);
#endif
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
            cryptoObj_->generateHash(newKeyBuffer, 64 + 4 * sizeof(uint32_t) + sizeof(int), currentKeySeed);
            memcpy(key + i * CHUNK_ENCRYPT_KEY_SIZE, currentKeySeed, CHUNK_ENCRYPT_KEY_SIZE);
        }
        sketchTableCounter_ += recvNumber;
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timeendKeyServer, NULL);
        diff = 1000000 * (timeendKeyServer.tv_sec - timestartKeyServer.tv_sec) + timeendKeyServer.tv_usec - timestartKeyServer.tv_usec;
        second = diff / 1000000.0;
        keySeedGenTime += second;
#endif
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
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timeendKeyServerTotal, NULL);
            diff = 1000000 * (timeendKeyServerTotal.tv_sec - timestartKeyServerTotal.tv_sec) + timeendKeyServerTotal.tv_usec - timestartKeyServerTotal.tv_usec;
            second = diff / 1000000.0;
            cout << "keyServer : generate key seed time = " << keySeedGenTime << " s" << endl;
            cout << "keyServer : compute optimal time = " << optimalComputeTime << " s" << endl;
            cout << "keyServer : total work time = " << second - totalRecvTime << " s" << endl;
            cout << "keyServer : total recv time = " << totalRecvTime << " s" << endl;
#endif
            return;
        }
        if (sketchTableCounter_ >= optimalSolverComputeItemNumberThreshold_) {
            multiThreadEditTMutex_.lock();
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timestartKeyServer, NULL);
#endif

            opInput_.clear();
            opInput_.reserve(sketchTableWidith_);
            for (int i = 0; i < sketchTableWidith_; i++) {
                stringstream ss;
                ss << i;
                string strTemp = ss.str();
                opInput_.push_back(make_pair(strTemp, sketchTable_[0][i]));
            }
            cout << "keyServer : start optimization solver" << endl;
            sketchTableCounter_ = 0;
            OpSolver* solver = new OpSolver(opm_, opInput_);
            T_ = solver->GetOptimal();
            delete solver;
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timeendKeyServer, NULL);
            diff = 1000000 * (timeendKeyServer.tv_sec - timestartKeyServer.tv_sec) + timeendKeyServer.tv_usec - timestartKeyServer.tv_usec;
            second = diff / 1000000.0;
            optimalComputeTime += second;
#endif
            multiThreadEditTMutex_.unlock();
        }
    }
}

#else

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
#if BREAK_DOWN_DEFINE == 1
            cout << "keyServer : generate key seed time = " << keySeedGenTime << " s" << endl;
#endif
            return;
        }
        int recvNumber = recvSize / (4 * sizeof(uint32_t));
        cout << "KeyServer : recv hash number = " << recvNumber << endl;
        u_char key[recvNumber * CHUNK_ENCRYPT_KEY_SIZE];
        multiThreadEditSketchTableMutex_.lock();
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timestartKeyServer, NULL);
#endif

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
            cryptoObj_->generateHash(newKeyBuffer, 64 + 4 * sizeof(uint32_t) + sizeof(int), currentKeySeed);
            memcpy(key + i * CHUNK_ENCRYPT_KEY_SIZE, currentKeySeed, CHUNK_ENCRYPT_KEY_SIZE);
        }
        sketchTableCounter_ += recvNumber;
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timeendKeyServer, NULL);
        diff = 1000000 * (timeendKeyServer.tv_sec - timestartKeyServer.tv_sec) + timeendKeyServer.tv_usec - timestartKeyServer.tv_usec;
        second = diff / 1000000.0;
        keySeedGenTime += second;
#endif

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
#if BREAK_DOWN_DEFINE == 1
            cout << "keyServer : generate key seed time = " << keySeedGenTime << " s" << endl;
#endif
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
            cout << "keyServer : start optimization solver" << endl;
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

#endif
