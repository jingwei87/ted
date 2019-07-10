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

void* KeyEx::threadHandler(void* param)
{

    KeyEx* obj = ((param_keyex*)param)->obj;
    free(param);

    /* check if cache temp file exists */
    entry_t l;

    /* hash temp buffer for query hash table */
    unsigned char hash_tmp[32];

    /* hash buffer */
    unsigned char* hashBuffer_1 = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);
    unsigned char* hashBuffer_2 = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);
    unsigned char* hashBuffer_3 = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);
    unsigned char* hashBuffer_4 = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE_SHORT);

    /* key buffer */
    unsigned char* keyBuffer = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * sizeof(int));

    /* main loop for processing batches */
    while (true) {

        int itemSize = sizeof(Chunk_t);
        int itemCount = 0;
        int totalCount = 0;
        entry_t e;
        Chunk_t temp;
        double timer;
        chunk_t tempList[KEY_BATCH_SIZE];
        for (int i = 0; i < KEY_BATCH_SIZE; i++) {
            /* getting a batch item from input buffer */
            obj->inputbuffer_->Extract(&temp);
            obj->cryptoObj_->generateHash(temp.data, temp.chunkSize, hash_tmp);
            memcpy(temp.key, hash_tmp, HASH_SIZE_SHORT);
            memcpy(tempList[i], temp, sizeof(chunk_t));
            memcpy(hashBuffer_1 + (i * HASH_SIZE_SHORT), hash_tmp, HASH_SIZE_SHORT);
            memcpy(hashBuffer_2 + (i * HASH_SIZE_SHORT), hash_tmp + (1 * HASH_SIZE_SHORT), HASH_SIZE_SHORT);
            memcpy(hashBuffer_3 + (i * HASH_SIZE_SHORT), hash_tmp + (2 * HASH_SIZE_SHORT), HASH_SIZE_SHORT);
            memcpy(hashBuffer_4 + (i * HASH_SIZE_SHORT), hash_tmp + (3 * HASH_SIZE_SHORT), HASH_SIZE_SHORT);
            itemCount++;
            if (temp.end == 1) {
                break;
            }
        }

        obj->keyExchange(hashBuffer_1, hashBuffer_2, hashBuffer_3, hashBuffer_4, itemCount, keyBuffer);
        /* get back the keys */
        int j = 0;
        for (int i = 0; i < itemCount; i++) {
            Encoder::Secret_Item_t input;
            chunk_t tempChunk;
            memcpy(&tempChunk, tempList[i], sizeof(chunk_t));
            input.type = SHARE_OBJECT;
            if (tempChunk.end == 1)
                input.type = SHARE_END;

            /* create encoder input object */
            memcpy(input.secret.data, tempChunk.data, tempChunk.chunkSize);

            int param = (int)(keyBuffer + i * sizeof(int));
            int randNumber = rand() % (param * 2);
            if (randNumber < param) {
                paramFloor = randNumber;
            }
            unsigned char newKeyBuffer[32 + sizeof(int)];
            memcpy(newKeyBuffer, temp.key, 32);
            memcpy(newKeyBuffer + 32, &param, sizeof(int));
            unsigned char key[32];
            SHA256(newKeyBuffer, 32 + sizeof(int), key);

            memcpy(input.secret.key, key, 32);

            input.secret.secretID = temp.chunkID;
            input.secret.secretSize = temp.chunkSize;
            input.secret.end = temp.end;

            /* add object to encoder input buffer*/
            obj->encodeObj_->add(&input);
        }
    }
    fclose(fp);
    return NULL;
}

KeyEx::KeyEx(Encoder* obj, int securetype, string kmip, int kmport, serverConf serverConf, int chara, int segType)
{

    ksip_ = (char*)serverConf.serverIP.c_str();
    ksport_ = serverConf.keyStorePort;
    rsa_ = RSA_new();
    ctx_ = BN_CTX_new();
    r_ = BN_new();
    inv_ = BN_new();
    mid_ = BN_new();
    h_ = BN_new();
    n_ = KEY_BATCH_SIZE;
    charaType_ = chara;
    if (charaType_ != CHARA_MIN_HASH) {

        segType_ = 0;
    }
    segType_ = segType;
    encodeObj_ = obj;
    record_ = (BIGNUM**)malloc(sizeof(BIGNUM*) * n_);
    for (int i = 0; i < n_; i++) {

        record_[i] = BN_new();
    }
    // 	initialization
    inputbuffer_ = new RingBuffer<Chunk_t>(CHUNK_RB_SIZE, true, 1);
    cryptoObj_ = new CryptoPrimitive(securetype);
    param_keyex* temp = (param_keyex*)malloc(sizeof(param_keyex));
    temp->index = 0;
    temp->obj = this;
    sock_[0] = new Ssl((char*)kmip.c_str(), kmport, 0);
    //	create key generation thread
    if (charaType_ == CHARA_CACHE) {

        pthread_create(&tid_, 0, &threadHandler, (void*)temp);
    } else {

        pthread_create(&tid_, 0, &threadHandlerMin, (void*)temp);
    }
}

KeyEx::~KeyEx()
{

    RSA_free(rsa_);
    BN_CTX_free(ctx_);
    BN_clear_free(r_);
    BN_clear_free(inv_);
    BN_clear_free(mid_);
    BN_clear_free(h_);
    for (int i = 0; i < n_; i++) {

        BN_clear_free(record_[i]);
    }
    free(record_);
    delete (inputbuffer_);
    delete (cryptoObj_);
}

void KeyEx::keyExchange(unsigned char* hash_buf_1, unsigned char* hash_buf_2, unsigned char* hash_buf_3, unsigned char* hash_buf_4, int num, unsigned char* key_buf)
{

    unsigned char buffer[sizeof(int)];
    memcpy(buffer, &num, sizeof(int);
    //	send hashes to key server
    sock_[0]->genericSend((char*)buffer, sizeof(int));
    sock_[0]->genericSend((char*)hash_buf_1, num * HASH_SIZE_SHORT);
    sock_[0]->genericSend((char*)hash_buf_2, num * HASH_SIZE_SHORT);
    sock_[0]->genericSend((char*)hash_buf_3, num * HASH_SIZE_SHORT);
    sock_[0]->genericSend((char*)hash_buf_4, num * HASH_SIZE_SHORT);
    //	get back the blinded keys
    unsigned char bufferKeyTemp[num*sizeof(int)];
    sock_[0]->genericDownload((char*)bufferKeyTemp, num*sizeof(int));
    memcpy(key_buf, bufferKeyTemp,num*sizeof(int));
}

void KeyEx::add(Chunk_t* item)
{

    inputbuffer_->Insert(item, sizeof(Chunk_t));
}
