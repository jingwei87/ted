#include "exchange.hh"

using namespace std;

/* 
	time measuring functions 
*/
extern void timerStart(double* t);
extern double timerSplit(const double* t);

/* 
	error printing 
*/
void fatalx(char* s)
{

    ERR_print_errors_fp(stderr);
    errx(EX_DATAERR, "%.30s", s);
}
void* KeyEx::threadHandler(void* param_thread)
{
    param_keyex* temp_param = (param_keyex*)param_thread;
    KeyEx* obj = temp_param->obj;
    //free(temp);

    /* hash temp buffer for query hash table */
    unsigned char hash_tmp[32];

    /* hash buffer */
    unsigned char* hashBuffer_1 = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);
    unsigned char* hashBuffer_2 = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);
    unsigned char* hashBuffer_3 = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);
    unsigned char* hashBuffer_4 = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);

    /* key buffer */
    unsigned char* keyBuffer = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE);

    /* main loop for processing batches */
    while (true) {

        int itemCount = 0;
        Chunk_t temp;
        vector<Chunk_t> tempList;
        tempList.reserve(KEY_BATCH_SIZE);
        //Chunk_t tempList[KEY_BATCH_SIZE];
        for (int i = 0; i < KEY_BATCH_SIZE; i++) {
            /* getting a batch item from input buffer */
            obj->inputbuffer_->Extract(&temp);
            obj->cryptoObj_->generateHash(temp.data, temp.chunkSize, hash_tmp);
            memcpy(temp.key, hash_tmp, HASH_SIZE);
            //memcpy(&tempList[i], &temp, sizeof(Chunk_t));
            tempList.push_back(temp);
            memcpy(hashBuffer_1 + (i * HASH_SIZE_SHORT), hash_tmp, HASH_SIZE_SHORT);
            memcpy(hashBuffer_2 + (i * HASH_SIZE_SHORT), hash_tmp + (1 * HASH_SIZE_SHORT), HASH_SIZE_SHORT);
            memcpy(hashBuffer_3 + (i * HASH_SIZE_SHORT), hash_tmp + (2 * HASH_SIZE_SHORT), HASH_SIZE_SHORT);
            memcpy(hashBuffer_4 + (i * HASH_SIZE_SHORT), hash_tmp + (3 * HASH_SIZE_SHORT), HASH_SIZE_SHORT);
            itemCount++;
            if (temp.end == 1) {
                break;
            }
        }
        // cout << "key exchange for " << itemCount << " chunks" << endl;
        obj->keyExchange(hashBuffer_1, hashBuffer_2, hashBuffer_3, hashBuffer_4, itemCount, keyBuffer);
        cout << "key exchange for " << itemCount << " chunks done" << endl;
        /* get back the keys */

        for (int i = 0; i < itemCount; i++) {
            Encoder::Secret_Item_t input;
            input.type = SHARE_OBJECT;
            if (tempList[i].end == 1)
                input.type = SHARE_END;

            /* create encoder input object */
            memcpy(input.secret.data, tempList[i].data, tempList[i].chunkSize);
            unsigned char newKeyBuffer[HASH_SIZE * 2];
            memcpy(newKeyBuffer, tempList[i].key, HASH_SIZE);
            memcpy(newKeyBuffer + HASH_SIZE, keyBuffer + i * HASH_SIZE, HASH_SIZE);
            unsigned char key[HASH_SIZE];
            SHA256(newKeyBuffer, 2 * HASH_SIZE, key);
            memcpy(input.secret.key, key, HASH_SIZE);

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

KeyEx::KeyEx(Encoder* obj, int securetype, string kmip, int kmport, int userID)
{
    // 	initialization
    inputbuffer_ = new RingBuffer<Chunk_t>(CHUNK_RB_SIZE, true, 1);
    cryptoObj_ = new CryptoPrimitive(securetype);
    encodeObj_ = obj;
    param_keyex* temp = (param_keyex*)malloc(sizeof(param_keyex));
    memset(temp, 0, sizeof(param_keyex));
    sock_[0] = new Ssl((char*)kmip.c_str(), kmport, userID);
    cout << "connect to key server done" << endl;
    temp->obj = this;

    int pthread_status = pthread_create(&tid_, 0, &threadHandler, (void*)temp);
    if (pthread_status != 0) {
        cout << pthread_status << endl;
        cout << "keyclient thread create failed" << endl;
    } else {
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

bool KeyEx::keyExchange(unsigned char* hash_buf_1, unsigned char* hash_buf_2, unsigned char* hash_buf_3, unsigned char* hash_buf_4, int num, unsigned char* key_buf)
{

    char buffer[sizeof(int)];
    memcpy(buffer, &num, sizeof(int));
    // cerr << "Num = " << num << endl;
    //	send hashes to key server
    sock_[0]->genericSend(buffer, sizeof(int));
    sock_[0]->genericSend((char*)hash_buf_1, num * HASH_SIZE_SHORT);
    sock_[0]->genericSend((char*)hash_buf_2, num * HASH_SIZE_SHORT);
    sock_[0]->genericSend((char*)hash_buf_3, num * HASH_SIZE_SHORT);
    sock_[0]->genericSend((char*)hash_buf_4, num * HASH_SIZE_SHORT);
    //	get back the blinded keys
    sock_[0]->genericDownload((char*)key_buf, num * HASH_SIZE);
    return true;
}

void KeyEx::add(Chunk_t* item)
{

    inputbuffer_->Insert(item, sizeof(Chunk_t));
}
