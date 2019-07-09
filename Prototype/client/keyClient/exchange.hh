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
    // key file object
    BIO* key_;
    // RSA object
    RSA* rsa_;
    // BN ctx
    BN_CTX* ctx_;
    // random number
    BIGNUM* r_;
    // inverse
    BIGNUM* inv_;
    // temp
    BIGNUM* mid_;
    // hash value convert to BN
    BIGNUM* h_;
    // array for record random numbers for each chunk
    BIGNUM** record_;
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
    // hash table entry pair
    typedef struct {
        unsigned char hash[HASH_SIZE];
        unsigned char key[HASH_SIZE];
    } entry_t;
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
    // hash table for cache keys
    HashTable<entry_t>* hashtable_;
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
			function : procedure for print a big number in hex
			input : input(BIGNUM)
			output : display the BIGNUM
		*/
    void printBN(BIGNUM* input);

    /*
			function : procedure for print a buffer content
		*/
    void printBuf(unsigned char* buff, int size);

    /*
			function : procedure for remove blind in returned keys 
			input : 
				@param buff - input big number buffer
				@param size - input big number size
		 		@param index - the index of recorded random number r
		*/
    void elimination(unsigned char* buff, int size, int index);

    /*
			function : procedure for blind hash value
			input :
				@param hash_buf - input buffer storing hash
				@param size - the size of input hash
				@param ret_buf - the returned buffer holding blinded hash
				@param index - the index of record random number r
		*/
    void decoration(unsigned char* hash_buf, int size, unsigned char* ret_buf, int index);

    /*
			function : procedure for verify returned keys
			input : 
		 		@param original - the original hash value buffer
		 		@param buff - the buffer contains returned blinded key
		  		@param size - the size of hash value
		 	output : 
		  		verify pass -> 0, verification fails -> others
		*/
    int verify(unsigned char* original, unsigned char* buff, int size);

    /*
			function : main procedure for init key generation with key server
			input :  
		  		@param hash_buf - the buffer holding hash values
		  		@param size - the size of data
		  		@param num - the number of hashes
		  		@param key_buf - the returned buffer contains keys
		  		@param obj - the pointer to crypto object
		*/
    void keyExchange(unsigned char* hash_buf, int size, int num, unsigned char* key_buf, CryptoPrimitive* obj);

    /*
			function : hash table initiation

			note : init Hash Table for key cache
		*/
    void createTable();

    /*
			function : thread handler

			note : do the main jobs of key manmger
		*/
    static void* threadHandlerMin(void* param);
    static void* threadHandler(void* param);
    /*
			function : make hash in hash table   
			input : the hash table entry need to hash 
		*/
    static unsigned int keyHashFcn(const entry_t*);

    /*
			function : compare hash table item  
			input : the two hash table entry need to compare
			output : same-> true | different -> false
		*/
    static bool keyCmpFcn(const entry_t*, const entry_t*);

    /*
			function : init hash table item  
			input : the hash table entry need to init
		*/
    static void keyInitFcn(entry_t*, void*);

    /*
			function : free hash table item  
			input : the hash table entry need to free 
		*/
    static void keyFreeFcn(entry_t*, void*);

    /*
			function : insert new key to key store
			input : user ID(int) file path(char *) file path size (int)
			
		 	note : called when upload first secerts
		*/
    void newFile(int user, char* filePath, int pathSize, char* policy);

    /*
			function : update existing file's state cipher
			input : user ID(int) file path(char *) file path size (int)
			
		 	note : called when update secrets
		*/
    int updateFileByPolicy(int user, char* filePath, int pathSize, char* oldPk, char* policy);

    int downloadFile(int user, char* filePath, int pathSize, char* pk);
};

void cpabeKeygen(char* pk, char* policy);
#endif
