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
    obj->createTable();
    FILE* fp = fopen("./cache.db", "r");
    if (fp != NULL) {

        /* read cache entries */
        while (!feof(fp)) {

            unsigned char tmp[HASH_SIZE * 2];
            int ret = fread(tmp, 1, HASH_SIZE * 2, fp);
            if (ret < 0) {
                printf("fail to load cache file\n");
            }

            memcpy(l.hash, tmp, HASH_SIZE);
            memcpy(l.key, tmp + HASH_SIZE, HASH_SIZE);
            double now;
            timerStart(&now);
            entry_t* e1 = obj->hashtable_->find(&l, now, true);
            memcpy(e1->hash, l.hash, HASH_SIZE);
            memcpy(e1->key, l.key, HASH_SIZE);
        }

        fclose(fp);
        fp = fopen("./cache.db", "w");
    } else {

        /* otherwise create cache db file */
        fp = fopen("./cache.db", "w");
    }

    /* index recode array */
    int index_rcd[256];
    memset(index_rcd, -1, 256);

    /* hash temp buffer for query hash table */
    unsigned char hash_tmp[32];

    /* batch buffer */
    unsigned char* buffer = (unsigned char*)malloc(sizeof(Chunk_t) * KEY_BATCH_SIZE);

    /* hash buffer */
    unsigned char* hashBuffer = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE);

    /* key buffer */
    unsigned char* keyBuffer = (unsigned char*)malloc(sizeof(unsigned char) * KEY_BATCH_SIZE * HASH_SIZE);

    /* main loop for processing batches */
    while (true) {

        int itemSize = sizeof(Chunk_t);
        int itemCount = 0;
        int totalCount = 0;
        entry_t e;
        Chunk_t temp;
        double timer;

        for (int i = 0; i < KEY_BATCH_SIZE; i++) {
            /* getting a batch item from input buffer */
            obj->inputbuffer_->Extract(&temp);
            obj->cryptoObj_->generateHash(temp.data, temp.chunkSize, hash_tmp);
            memcpy(e.hash, hash_tmp, HASH_SIZE);
            timerStart(&timer);
            /* see if the hash value exists in hash table */
            entry_t* ret = obj->hashtable_->find(&e, timer, false);
            /* cache hits */
            if (ret != NULL) {
                memcpy(temp.key, ret->key, HASH_SIZE);
                memcpy(buffer + i * itemSize, &temp, itemSize);
                totalCount++;
                fwrite(ret->hash, 1, HASH_SIZE, fp);
                fwrite(ret->key, 1, HASH_SIZE, fp);
                if (temp.end == 1)
                    break;
            } else {
                index_rcd[itemCount] = i;
                memcpy(buffer + i * itemSize, &temp, itemSize);
                memcpy(hashBuffer + i * HASH_SIZE, hash_tmp, HASH_SIZE);
                itemCount++;
                totalCount++;
                if (temp.end == 1)
                    break;
            }
        }
        /* if there are some hash value cache miss */
        if (itemCount != 0) {
            /* perform key generation */
            obj->keyExchange(hashBuffer, itemCount * COMPUTE_SIZE, itemCount, keyBuffer, obj->cryptoObj_);
        }
        /* get back the keys */
        int j = 0;
        for (int i = 0; i < totalCount; i++) {
            Encoder::Secret_Item_t input;
            memcpy(&temp, buffer + i * itemSize, itemSize);
            input.type = SHARE_OBJECT;
            if (temp.end == 1)
                input.type = SHARE_END;

            /* create encoder input object */
            memcpy(input.secret.data, temp.data, temp.chunkSize);

            if (index_rcd[j] == i) {
                memcpy(input.secret.key, keyBuffer + j * HASH_SIZE, HASH_SIZE);
                j++;
            } else {
                memcpy(input.secret.key, temp.key, HASH_SIZE);
            }
            input.secret.secretID = temp.chunkID;
            input.secret.secretSize = temp.chunkSize;
            input.secret.end = temp.end;

            /* add object to encoder input buffer*/
            obj->encodeObj_->add(&input);

            /* add key into hash table */
            memcpy(e.hash, hashBuffer + i * HASH_SIZE, HASH_SIZE);
            memcpy(e.key, keyBuffer + i * HASH_SIZE, HASH_SIZE);

            /* write cache file */
            fwrite(e.hash, 1, HASH_SIZE, fp);
            fwrite(e.key, 1, HASH_SIZE, fp);

            /* update hash entry */
            timerStart(&timer);
            entry_t* e1 = obj->hashtable_->find(&e, timer, true);
            memcpy(e1->hash, e.hash, HASH_SIZE);
            memcpy(e1->key, e.key, HASH_SIZE);
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

void KeyEx::keyExchange(unsigned char* hash_buf, int size, int num, unsigned char* key_buf, CryptoPrimitive* obj)
{

    unsigned char buffer[sizeof(int) + size];
    memcpy(buffer, &num, sizeof(int));
    //	blind all hashes
    for (int i = 0; i < num; i++) {

        decoration(hash_buf + i * HASH_SIZE, HASH_SIZE, buffer + sizeof(int) + i * COMPUTE_SIZE, i);
    }
    //	send hashes to key server
    sock_[0]->genericSend((char*)buffer, size + sizeof(int));
    //	get back the blinded keys
    sock_[0]->genericDownload((char*)buffer, size);
    //	remove the blind in returned keys
    for (int i = 0; i < num; i++) {

        elimination(buffer + i * COMPUTE_SIZE, COMPUTE_SIZE, i);
        // 	hash 1024bit value back to 256bit
        obj->generateHash(buffer + i * COMPUTE_SIZE, COMPUTE_SIZE, key_buf + i * HASH_SIZE);
    }
}

void KeyEx::add(Chunk_t* item)
{

    inputbuffer_->Insert(item, sizeof(Chunk_t));
}
