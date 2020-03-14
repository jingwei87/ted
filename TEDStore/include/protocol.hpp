#ifndef TEDSTORE_PROTOCOL_HPP
#define TEDSTORE_PROTOCOL_HPP

#include <bits/stdc++.h>
//client-server network protocol
#define CLIENT_UPLOAD_CHUNK 7
#define CLIENT_DOWNLOAD_CHUNK_WITH_RECIPE 8
#define SERVER_REQUIRED_CHUNK 9
#define CLIENT_UPLOAD_ENCRYPTED_RECIPE 10
#define CLIENT_DOWNLOAD_ENCRYPTED_RECIPE 11
#define ERROR_RESEND 12
#define ERROR_CLOSE 13
#define SUCCESS 14
#define SGX_SIGNED_HASH_TO_DEDUPCORE 15
#define ERROR_FILE_NOT_EXIST 16
#define ERROR_CHUNK_NOT_EXIST 17
#define ERROR_CLIENT_CLOSE_CONNECT 18
#define CLIENT_EXIT 19
#define CLIENT_UPLOAD_DECRYPTED_RECIPE 20
#define CLIENT_DOWNLOAD_RECIPE_SIZE 21

using namespace std;

#endif //TEDSTORE_PROTOCOL_HPP