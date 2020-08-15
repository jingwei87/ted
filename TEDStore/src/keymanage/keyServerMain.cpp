#include "keyServer.hpp"
#include "ssl.hpp"

Configure config("config.json");

#if SINGLE_THREAD_KEY_MANAGER == 1
int main()
{
    ssl* keySecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), SERVERSIDE);
    boost::thread* th;
    keyServer* server = new keyServer(keySecurityChannelTemp);
    while (true) {
        SSL* sslConnection = keySecurityChannelTemp->sslListen().second;
        th = new boost::thread(boost::bind(&keyServer::runKeyGen, server, sslConnection));
        th->detach();
    }
    return 0;
}
#else
int main()
{
    ssl* keySecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), SERVERSIDE);
    boost::thread* th;
    keyServer* server = new keyServer(keySecurityChannelTemp);
    th = new boost::thread(boost::bind(&keyServer::runOptimalSolver, server));
    while (true) {
        SSL* sslConnection = keySecurityChannelTemp->sslListen().second;
        th = new boost::thread(boost::bind(&keyServer::runKeyGenSimple, server, sslConnection));
        th->detach();
    }
    // const char* fp = "1234567891234567";
    // HHash* hashFunction = new HHash();
    // mpz_t result;
    // mpz_init(result);
    // mpz_t inputBlk[BLOCK_NUM];

    // mpz_t s[K_PARA];
    // mpz_t p[K_PARA];
    // mpz_t share[K_PARA];
    // for (size_t i = 0; i < K_PARA; i++) {
    //     mpz_init(share[i]);
    // }
    // mpz_t secret;
    // mpz_init_set_ui(secret, 10);
    // mpz_init_set_str(s[0], "4", 10);
    // mpz_init_set_str(s[1], "2", 10);
    // mpz_init_set_str(p[0], "1", 10);
    // mpz_init_set_str(p[1], "3", 10);

    // hashFunction->CovertFPtoBlocks(inputBlk, fp);
    // hashFunction->ComputeMulForBlock(inputBlk, secret);
    // hashFunction->ComputeBlockHash(result, inputBlk);
    // gmp_printf("Real result: %Zd\n", result);

    // mpz_t inputBlk_1[BLOCK_NUM];
    // mpz_t inputBlk_2[BLOCK_NUM];

    // hashFunction->CovertFPtoBlocks(inputBlk_1, fp);
    // hashFunction->ComputeMulForBlock(inputBlk_1, s[0]);
    // hashFunction->ComputeBlockHash(share[0], inputBlk_1);
    // gmp_printf("Share-1 : %Zd\n", share[0]);

    // hashFunction->CovertFPtoBlocks(inputBlk_2, fp);
    // hashFunction->ComputeMulForBlock(inputBlk_2, s[1]);
    // hashFunction->ComputeBlockHash(share[1], inputBlk_2);
    // gmp_printf("Share-2 : %Zd\n", share[1]);

    // mpz_t proResult;
    // mpz_init(proResult);
    // hashFunction->RecoverySecretFromHash(share, p, proResult);
    // gmp_printf("Product result: %Zd\n", proResult);

    // delete hashFunction;
    return 0;
}
#endif
