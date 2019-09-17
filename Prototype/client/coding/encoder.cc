/*
 * encoder.cc
 *
 */

#include "encoder.hh"

using namespace std;

/*
 * thread handler for encoding each secret into shares
 *
 * @param param - parameters for encode thread
 */
void* Encoder::thread_handler(void* param)
{
    int index = ((param_encoder*)param)->index;
    Encoder* obj = ((param_encoder*)param)->obj;
    free(param);
    /* main loop for getting secrets and encode them into shares*/
    while (true) {

        Secret_Item_t temp;
        Secret_Item_t input;
        obj->inputbuffer_[index]->Extract(&temp);

        /* get the object type */
        input.type = temp.type;

        /* copy content into input object */
        if (input.type == FILE_OBJECT) {

            memcpy(&input.file_header, &temp.file_header, sizeof(fileHead_t));
        } else {

            obj->cryptoObj_[index]->encryptWithKey(temp.secret.data, temp.secret.secretSize, temp.secret.key, input.secret.data);
            input.secret.secretID = temp.secret.secretID;
            input.secret.secretSize = temp.secret.secretSize;
            input.secret.end = temp.secret.end;
        }

        /* add the object to output buffer */
        obj->outputbuffer_[index]->Insert(&input, sizeof(input));
    }
    return NULL;
}

void* Encoder::collect(void* param)
{
    /* index for sequencially collect shares */
    int nextBufferIndex = 0;

    /* parse parameters */
    Encoder* obj = (Encoder*)param;

    /* main loop for collecting shares */
    while (true) {

        /* extract an object from a certain ringbuffer */
        Secret_Item_t temp;
        obj->outputbuffer_[nextBufferIndex]->Extract(&temp);
        nextBufferIndex = (nextBufferIndex + 1) % NUM_THREADS;

        /* get the object type */
        int type = temp.type;

        Uploader::Item_t input;
        if (type == FILE_OBJECT) {

            /* if it's file header, directly transform the object to uploader */
            input.type = FILE_HEADER;

            /* copy file header information */
            input.fileObj.file_header.fileSize = temp.file_header.fileSize;
            input.fileObj.file_header.numOfPastSecrets = 0;
            input.fileObj.file_header.sizeOfPastSecrets = 0;
            input.fileObj.file_header.numOfComingSecrets = 0;
            input.fileObj.file_header.sizeOfComingSecrets = 0;
            unsigned char key[32];
            SHA256(temp.file_header.data, temp.file_header.fullNameSize, key);
            input.fileObj.file_header.fullNameSize = 32;
            memcpy(input.fileObj.data, key, input.fileObj.file_header.fullNameSize);
            obj->uploadObj_->add(&input, sizeof(input));

        } else {
                input.type = SHARE_OBJECT;

                /* copy share info */
                int shareSize = temp.secret.shareSize;
                input.shareObj.share_header.secretID = temp.secret.secretID;
                input.shareObj.share_header.secretSize = temp.secret.secretSize;
                input.shareObj.share_header.shareSize = shareSize;
                memcpy(input.shareObj.data, temp.secret.data + (i * shareSize), shareSize);
                if (temp.secret.end == 1)
                    input.type = SHARE_END;
                obj->uploadObj_->add(&input, sizeof(input), i);
        }
    }
    return NULL;
}

/*
 * see if it's end of encoding file
 *
 */
void Encoder::indicateEnd()
{
    pthread_join(tid_[NUM_THREADS], NULL);
}

/*
 * constructor
 *    
 * @param type - convergent dispersal type
 * @param n - total number of shares generated from a secret
 * @param m - reliability degree
 * @param r - confidentiality degree
 * @param securetype - encryption and hash type
 * @param uploaderObj - pointer link to uploader object
 *
 */
Encoder::Encoder(int type, int n, int m, int r, int securetype, Uploader* uploaderObj)
{

    /* initialization of variables */
    int i;
    n_ = n;
    nextAddIndex_ = 0;
    cryptoObj_ = (CryptoPrimitive**)malloc(sizeof(CryptoPrimitive*) * NUM_THREADS);
    inputbuffer_ = (RingBuffer<Secret_Item_t>**)malloc(sizeof(RingBuffer<Secret_Item_t>*) * NUM_THREADS);
    outputbuffer_ = (RingBuffer<ShareChunk_Item_t>**)malloc(sizeof(RingBuffer<ShareChunk_Item_t>*) * NUM_THREADS);

    /* initialization of objects */
    for (i = 0; i < NUM_THREADS; i++) {
        inputbuffer_[i] = new RingBuffer<Secret_Item_t>(RB_SIZE, true, 1);
        outputbuffer_[i] = new RingBuffer<ShareChunk_Item_t>(RB_SIZE, true, 1);
        cryptoObj_[i] = new CryptoPrimitive(securetype);
        encodeObj_[i] = new CDCodec(type, n, m, r, cryptoObj_[i]);
        param_encoder* temp = (param_encoder*)malloc(sizeof(param_encoder));
        temp->index = i;
        temp->obj = this;

        /* create encoding threads */
        pthread_create(&tid_[i], 0, &thread_handler, (void*)temp);
    }

    uploadObj_ = uploaderObj;

    /* create collect thread */
    pthread_create(&tid_[NUM_THREADS], 0, &collect, (void*)this);
}

/*
 * destructor
 *
 */
Encoder::~Encoder()
{
    for (int i = 0; i < NUM_THREADS; i++) {
        delete cryptoObj_[i];
        delete encodeObj_[i];
        delete inputbuffer_[i];
        delete outputbuffer_[i];
    }
    free(inputbuffer_);
    free(outputbuffer_);
    free(cryptoObj_);
}

/*
 * add function for sequencially add items to each encode buffer
 *
 * @param item - input object
 *
 */
int Encoder::add(Secret_Item_t* item)
{
    inputbuffer_[nextAddIndex_]->Insert(item, sizeof(Secret_Item_t));
    nextAddIndex_ = (nextAddIndex_ + 1) % NUM_THREADS;
    return 1;
}
