#ifndef __EXCHANGE_HH__
#define __EXCHANGE_HH__

#include <bits/stdc++.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <utility>

#include "BasicRingBuffer.hh"
#include "CryptoPrimitive.hh"
#include "HashTable.hh"
#include "conf.hh"
#include "encoder.hh"
#include "socket.hh"
#include "ssl.hh"

/* init constants */
#define HASH_SIZE_SHORT 4
#define COMPUTE_SIZE 128

#define MAX_CMD_LENGTH 65535
#define CHUNK_DATA_SIZE (16 * 1024)
#define CHUNK_RB_SIZE 1024

#define HASH_TABLE_SIZE (32 * 1024 * 1024)
#define SEND_THREADS 2

#define KEY_BATCH_SIZE_MAX (4096 * 1024 * 2)
#define KEY_BATCH_SIZE_MIN (2048 * 1024)
#define BATCH_COUNT 4100

#define VAR_SEG 77
#define FIX_SEG 88

#define CHARA_MIN_HASH 1007
#define CHARA_FIRST_HASH 1008
#define CHARA_FIRST_64 1009
#define CHARA_CACHE 1010

#define KEY_NEW 1
#define KEY_UPDATE 2
#define DOWNLOAD_KEY 3

using namespace std;

class KeyEx {
private:
    // total chunk number
    int n_;
    // array for SSL structures
    Ssl* sock_[SEND_THREADS];
    //key store ip
    char* ksip_;
    //key store port
    int ksport_;
    //type setting
    int charaType_;
    int segType_;

public:
    // thread handler structure
    typedef struct {
        int index;
        KeyEx* obj;
    } param_keyex;
    // ring buffer item structure
    typedef struct {
        unsigned char data[CHUNK_DATA_SIZE];
        unsigned char key[HASH_SIZE];
        int chunkID;
        int chunkSize;
        int end;
    } Chunk_t;
    // encoder object
    Encoder* encodeObj_;
    // input ring buffer
    RingBuffer<Chunk_t>* inputbuffer_;
    // thread id
    pthread_t tid_;
    //temp current key
    char current_key[32];
    // crpyto object
    CryptoPrimitive* cryptoObj_;

    /*
			function : constructor of key exchange
		 	input : encoder(obj) securetype (int [macro]) key manager IP(char *) key manager port (int)
					key store IP(char *) key store port (int) chara type (int [macro])
		*/
    KeyEx(Encoder* obj, int securetype, string kmip, int kmport, serverConf serverConf, int chara, int segType);

    /*
			function : destructor of key exchange
		*/
    ~KeyEx();

    /*
			function : read rsa keys from key file
			input : filename (char *)
			output : read success / failure
		*/
    bool readKeyFile(char* filename);

    /*
			function : Chunk_t struct -> input Ring Buffer
			input : item (Chunk_t struct)
		*/
    void add(Chunk_t* item);

    /*
			function : main procedure for init key generation with key server
			input :  
		  		@param hash_buf - the buffer holding hash values
		  		@param size - the size of data
		  		@param num - the number of hashes
		  		@param key_buf - the returned buffer contains keys
		  		@param obj - the pointer to crypto object
		*/
    void keyExchange(unsigned char* hash_buf_1, unsigned char* hash_buf_2, unsigned char* hash_buf_3, unsigned char* hash_buf_4, int num, unsigned char* key_buf);

    /*
			function : thread handler

			note : do the main jobs of key manmger
		*/
    static void* threadHandler(void* param);
};

#endif
