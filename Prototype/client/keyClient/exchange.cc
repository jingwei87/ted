#include "exchange.hh"

using namespace std;

/* 
	time measuring functions 
*/
extern void timerStart(double *t);
extern double timerSplit(const double *t);

struct timeval timestartKey;
struct timeval timeendKey;

struct timeval timestartInit;
struct timeval timeendInit;
/* 
	error printing 
*/
void fatalx(char *s)
{
    ERR_print_errors_fp(stderr);
    errx(EX_DATAERR, "%.30s", s);
}

void *KeyEx::threadHandler(void *param_thread)
{
    param_keyex *temp_param = (param_keyex *)param_thread;
    KeyEx *obj = temp_param->obj;
    //free(temp);

    /* hash temp buffer for query hash table */
    unsigned char hash_tmp[32];

    /* hash buffer */
    unsigned char *hashBuffer_1 = (unsigned char *)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);
    unsigned char *hashBuffer_2 = (unsigned char *)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);
    unsigned char *hashBuffer_3 = (unsigned char *)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);
    unsigned char *hashBuffer_4 = (unsigned char *)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);

    /* key buffer */
    unsigned char *keyBuffer = (unsigned char *)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE);

    /* main loop for processing batches */
    while (true)
    {

        int itemCount = 0;
        Chunk_t temp;
        vector<Chunk_t> tempList;
        tempList.reserve(KEY_BATCH_SIZE);
        uint32_t seed1 = 1;
        uint32_t seed2 = 2;
        uint32_t seed3 = 3;
        uint32_t seed4 = 4;
        //Chunk_t tempList[KEY_BATCH_SIZE];
        for (int i = 0; i < KEY_BATCH_SIZE; i++)
        {
            /* getting a batch item from input buffer */
            obj->inputbuffer_->Extract(&temp);

            // gettimeofday(&timestartInit, NULL);

            obj->cryptoObj_->generateHash(temp.data, temp.chunkSize, hash_tmp);
            memcpy(temp.key, hash_tmp, HASH_SIZE);
            tempList.push_back(temp);
            char data1[temp.chunkSize + sizeof(uint32_t)];
            char hash1[16];
            memcpy(data1, temp.data, temp.chunkSize);
            memcpy(data1 + temp.chunkSize, &seed1, sizeof(uint32_t));
            MurmurHash3_x64_128((void const *)data1, temp.chunkSize + sizeof(uint32_t), seed1, (void *)hash1);

            char data2[temp.chunkSize + sizeof(uint32_t)];
            char hash2[16];
            memcpy(data2, temp.data, temp.chunkSize);
            memcpy(data2 + temp.chunkSize, &seed2, sizeof(uint32_t));
            MurmurHash3_x64_128((void const *)data2, temp.chunkSize + sizeof(uint32_t), seed2, (void *)hash2);

            char data3[temp.chunkSize + sizeof(uint32_t)];
            char hash3[16];
            memcpy(data3, temp.data, temp.chunkSize);
            memcpy(data3 + temp.chunkSize, &seed3, sizeof(uint32_t));
            MurmurHash3_x64_128((void const *)data3, temp.chunkSize + sizeof(uint32_t), seed3, (void *)hash3);

            char data4[temp.chunkSize + sizeof(uint32_t)];
            char hash4[16];
            memcpy(data4, temp.data, temp.chunkSize);
            memcpy(data4 + temp.chunkSize, &seed4, sizeof(uint32_t));
            MurmurHash3_x64_128((void const *)data4, temp.chunkSize + sizeof(uint32_t), seed4, (void *)hash4);

            memcpy(hashBuffer_1 + (i * HASH_SIZE_SHORT), hash1, HASH_SIZE_SHORT);
            memcpy(hashBuffer_2 + (i * HASH_SIZE_SHORT), hash2, HASH_SIZE_SHORT);
            memcpy(hashBuffer_3 + (i * HASH_SIZE_SHORT), hash3, HASH_SIZE_SHORT);
            memcpy(hashBuffer_4 + (i * HASH_SIZE_SHORT), hash4, HASH_SIZE_SHORT);

            // gettimeofday(&timeendInit, NULL);
            // long diff = 1000000 * (timeendInit.tv_sec - timestartInit.tv_sec) + timeendInit.tv_usec - timestartInit.tv_usec;
            // double second = diff / 1000000.0;
            // printf("murmurhash time is %ld us = %lf s\n", diff, second);

            itemCount++;
            if (temp.end == 1)
            {
                break;
            }
        }
        // cout << "key exchange for " << itemCount << " chunks" << endl;
        obj->keyExchange(hashBuffer_1, hashBuffer_2, hashBuffer_3, hashBuffer_4, itemCount, keyBuffer);
        cout << "key exchange for " << itemCount << " chunks done" << endl;
        /* get back the keys */

        for (int i = 0; i < itemCount; i++)
        {
            Encoder::Secret_Item_t input;
            input.type = SHARE_OBJECT;
            if (tempList[i].end == 1)
                input.type = SHARE_END;

            /* create encoder input object */
            // gettimeofday(&timestartInit, NULL);
            memcpy(input.secret.data, tempList[i].data, tempList[i].chunkSize);
            unsigned char newKeyBuffer[HASH_SIZE * 2];
            memcpy(newKeyBuffer, tempList[i].key, HASH_SIZE);
            memcpy(newKeyBuffer + HASH_SIZE, keyBuffer + i * HASH_SIZE, HASH_SIZE);
            unsigned char key[HASH_SIZE];
            SHA256(newKeyBuffer, 2 * HASH_SIZE, key);
            memcpy(input.secret.key, key, HASH_SIZE);

            // gettimeofday(&timeendInit, NULL);
            // long diff = 1000000 * (timeendInit.tv_sec - timestartInit.tv_sec) + timeendInit.tv_usec - timestartInit.tv_usec;
            // double second = diff / 1000000.0;
            // printf("update key time is %ld us = %lf s\n", diff, second);

            input.secret.secretID = tempList[i].chunkID;
            input.secret.secretSize = tempList[i].chunkSize;
            input.secret.end = tempList[i].end;

            /* add object to encoder input buffer*/
            obj->encodeObj_->add(&input);
        }
        tempList.clear();
    }

    free(hashBuffer_1);
    free(hashBuffer_2);
    free(hashBuffer_3);
    free(hashBuffer_4);

    return NULL;
}

KeyEx::KeyEx(Encoder *obj, int securetype, string kmip, int kmport, int userID)
{
    // 	initialization
    inputbuffer_ = new RingBuffer<Chunk_t>(CHUNK_RB_SIZE, true, 1);
    cryptoObj_ = new CryptoPrimitive(securetype);
    encodeObj_ = obj;
    param_keyex *temp = (param_keyex *)malloc(sizeof(param_keyex));
    memset(temp, 0, sizeof(param_keyex));
    sock_[0] = new Ssl((char *)kmip.c_str(), kmport, userID);
    cout << "connect to key server done" << endl;
    temp->obj = this;

    int pthread_status = pthread_create(&tid_, 0, &threadHandler, (void *)temp);
    if (pthread_status != 0)
    {
        cout << pthread_status << endl;
        cout << "keyclient thread create failed" << endl;
    }
    else
    {
        cout << pthread_status << endl;
        cout << "keyclient thread create done" << endl;
    }
    free(temp);
}

KeyEx::~KeyEx()
{

    delete (inputbuffer_);
    delete (cryptoObj_);
    pthread_join(tid_, NULL);
}

bool KeyEx::keyExchange(unsigned char *hash_buf_1, unsigned char *hash_buf_2, unsigned char *hash_buf_3, unsigned char *hash_buf_4, int num, unsigned char *key_buf)
{

    char buffer[sizeof(int)];
    memcpy(buffer, &num, sizeof(int));
    // cerr << "Num = " << num << endl;
    //	send hashes to key server
    // gettimeofday(&timestartKey, NULL);
    sock_[0]->genericSend(buffer, sizeof(int));
    sock_[0]->genericSend((char *)hash_buf_1, num * HASH_SIZE_SHORT);
    sock_[0]->genericSend((char *)hash_buf_2, num * HASH_SIZE_SHORT);
    sock_[0]->genericSend((char *)hash_buf_3, num * HASH_SIZE_SHORT);
    sock_[0]->genericSend((char *)hash_buf_4, num * HASH_SIZE_SHORT);
    // gettimeofday(&timeendKey, NULL);
    // long diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
    // double second = diff / 1000000.0;
    // printf("key upload time is %ld us = %lf s\n", diff, second);

    //	get back the blinded keys
    sock_[0]->genericDownload((char *)key_buf, num * HASH_SIZE);
    // gettimeofday(&timeendKey, NULL);
    // diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
    // second = diff / 1000000.0;
    // printf("key downlaod  time is %ld us = %lf s\n", diff, second);
    return true;
}

void KeyEx::add(Chunk_t *item)
{

    inputbuffer_->Insert(item, sizeof(Chunk_t));
}
