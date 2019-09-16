/*
 * server.cc
 */

#include "server.hh"
#include <string>
#include <string.h>
#include <sys/time.h>

DedupCore* dedupObj_;

using namespace std;

/*
 * constructor: initialize host socket
 *
 * @param port - port number
 * @param dedupObj - dedup object passed in
 *
 */
Server::Server(int dataPort, int keyPort, DedupCore* dedupObj){
	//dedup. object
	dedupObj_ = dedupObj;

	//server port
	dataHostPort_ = dataPort;
	keyHostPort_ = keyPort;

	//server socket initialization
	dataHostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (dataHostSock_ == -1) {

		printf("Error initializing socket %d\n", errno);
	}

	keyHostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (keyHostSock_ == -1) {
		
		printf("Error initializing socket %d\n", errno);
	}
		
	//set data socket options
	int *p_int = (int*)malloc(sizeof(int));
	*p_int = 1;

	if ((setsockopt(dataHostSock_, SOL_SOCKET, SO_REUSEADDR, (char*)p_int, sizeof(int))==-1)||(setsockopt(dataHostSock_, SOL_SOCKET, SO_KEEPALIVE, (char*)p_int, sizeof(int)) == -1)){
		
		printf("Error setting options %d\n", errno);
		free(p_int);
	}

	//set key socket options
	*p_int = 1;

	if ((setsockopt(keyHostSock_, SOL_SOCKET, SO_REUSEADDR, (char*)p_int, sizeof(int))==-1)||(setsockopt(keyHostSock_, SOL_SOCKET, SO_KEEPALIVE, (char*)p_int, sizeof(int)) == -1)){
		
		printf("Error setting options %d\n", errno);
		free(p_int);
	}
	free(p_int);

	//initialize address struct
	dataAddr_.sin_family = AF_INET;
	dataAddr_.sin_port = htons(dataHostPort_);

	memset(&(dataAddr_.sin_zero),0,8);
	dataAddr_.sin_addr.s_addr = INADDR_ANY;

	//bind port
	if(bind(dataHostSock_, (sockaddr*)&dataAddr_, sizeof(dataAddr_)) == -1){
		fprintf(stderr, "Error binding to socket %d\n", errno);
	}

	//start to listen
	if(listen(dataHostSock_, 10) == -1){
		fprintf(stderr, "Error listening %d\n", errno);
	}

	keyAddr_.sin_family = AF_INET;
	keyAddr_.sin_port = htons(keyHostPort_);

	memset(&(dataAddr_.sin_zero),0,8);
	keyAddr_.sin_addr.s_addr = INADDR_ANY;

	//bind port
	if(bind(keyHostSock_, (sockaddr*)&keyAddr_, sizeof(keyAddr_)) == -1){
		fprintf(stderr, "Error binding to socket %d\n", errno);
	}

	//start to listen
	if(listen(keyHostSock_, 10) == -1){
		fprintf(stderr, "Error listening %d\n", errno);
	}


}

void timerStart(double *t){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	*t = (double)tv.tv_sec+(double)tv.tv_usec*1e-6;
}

double timerSplit(const double *t){
	struct timeval tv;
	double cur_t;
	gettimeofday(&tv, NULL);
	cur_t = (double)tv.tv_sec + (double)tv.tv_usec*1e-6;
	return (cur_t - *t);		
}

/*
 * Thread function: each thread maintains a socket from a certain client
 *
 * @param lp - input parameter structure
 *
 */
void* SocketHandler(void* lp){
	//double timer,split,bw;

	//get socket from input param
	int *clientSock = (int*)lp;

	//variable initialization
	int bytecount;
	char * buffer = (char*)malloc(sizeof(char)*BUFFER_LEN);
	char * metaBuffer = (char *)malloc(sizeof(char)*META_LEN);
	bool* statusList = (bool*)malloc(sizeof(bool)*BUFFER_LEN);
	memset(statusList,0,sizeof(bool)*BUFFER_LEN);
	int metaSize;
	int user = 0;
	int dataSize = 0;
	//double first_total = 0;
	//double second_total = 0;


	//get user ID
	if ((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1){
		fprintf(stderr, "Error recv userID %d\n",errno);
	}
	user = ntohl(*(int*)buffer);
	
	memset(buffer, 0, BUFFER_LEN);
	int numOfShare = 0;

	//initialize hash object
	CryptoPrimitive* hashObj = new CryptoPrimitive(SHA256_TYPE);

	//main loop for recv data package
	while(true){

		/*recv indicator first*/
		if ((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {

			fprintf(stderr, "Error receiving data %d\n", errno);
		}
		/*if client closes, break loop*/
		if (bytecount == 0) 
			break;
		int indicator = *(int*)buffer;
		cout<<"indicator = "<<indicator<<endl;
		/* if it's comming stub file */
		if (indicator == STUB) {

			/* get stub file size */
			if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			int length = *(int*)buffer;
			/* get file name size */
			if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			int namesize = *(int*)buffer;

			char* stubbuffer = (char*)malloc(sizeof(char)*length);

			char namebuffer[namesize+1];
			if ((bytecount = recv(*clientSock, namebuffer, namesize, 0)) == -1) {

				fprintf(stderr, "Error receiving data %d\n", errno);
			}

			namebuffer[namesize] = '\0';
			int id = 0;
			while(namebuffer[id] != '\0'){
				id++;
				if(namebuffer[id] == '/') {
					namebuffer[id] = '_';
				}
			}
			/* create a new cipher file */
			char name[256];
			sprintf(name, "stubStore/%s.stub", namebuffer);

			FILE* wp = fopen(name,"w");
			if (wp == NULL) {
				cout<<"stub file can not creat"<<endl;
			}
			/* get stub */
			int total = 0;
			cout<<length<<endl;
			while (total < length) {

				if ((bytecount = recv(*clientSock, stubbuffer+total, length-total, 0)) == -1) {

					fprintf(stderr, "Error receiving data %d\n", errno);
				}
				total+=bytecount;
			}

			fwrite(stubbuffer, 1, length, wp);
			fclose(wp);
			free(stubbuffer);
			break;
		}

		/* if it's stub download */
		if (indicator == GETSTUB) {

			cout<<"name size"<<endl;
			/* get file name size */
			if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			int namesize = *(int*)buffer;
			char namebuffer[namesize+1];
			if ((bytecount = recv(*clientSock, namebuffer, namesize, 0)) == -1) {

				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			namebuffer[namesize] = '\0';
			int id = 0;
			while(namebuffer[id] != '\0'){
				id++;
				if(namebuffer[id] == '/') {
					namebuffer[id] = '_';
				}
			}
			/* find stub file */
			char name[256];
			sprintf(name, "stubStore/%s.stub", namebuffer);
			cout<<name<<endl;
			FILE* rp = fopen(name,"r");
			if (rp == NULL) {

				cout<<"file not exist"<<endl;
				cout<<"download fail"<<endl;
				break;
			}

			fseek(rp, 0, SEEK_END);
			int length = ftell(rp);
			fseek(rp, 0, SEEK_SET);
			char* stubtemp = (char*)malloc(sizeof(char)*length);

			int ret;
			ret = fread(stubtemp, 1, length, rp);
			if (ret != length){
				printf("error reading cipher file\n");
			}
			/* send stub size back */
			if ((bytecount = send(*clientSock, &length, sizeof(int), 0)) == -1){
				
				fprintf(stderr, "Error sending data %d\n", errno);
			}
			int total = 0;
			cout<<length<<endl;

			while (total < length) {

				if ((bytecount = send(*clientSock, stubtemp+total, length-total, 0)) == -1) {

					fprintf(stderr, "Error receiving data %d\n", errno);
				}
				total+=bytecount;
			}

			cout<<"stub over : "<<total<<endl;
			free(stubtemp);
			fclose(rp);
			continue;
		}

		/*recv following package size*/
		if ((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {

			fprintf(stderr, "Error receiving data %d\n", errno);
		}

		int packageSize = *(int*)buffer;
		cout<<"next package size = "<<packageSize<<endl;
		int count = 0;

		/*recv following data*/
		while (count < packageSize){
			if((bytecount = recv(*clientSock, buffer+count, packageSize-count, 0)) == -1){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			count += bytecount;
		}
		cout<<"count = "<<count<<endl;
		/*while download request recv.ed, perform restore*/
		if (indicator == DOWNLOAD) {
			
			cout<<"starting download files"<<endl;

			std::string fullFileName;
			fullFileName.assign(buffer, count);
			cout<<"full file name = "<<fullFileName<<endl;
			if (dedupObj_->restoreShareFile(user, fullFileName, 0, *clientSock, hashObj)) {
				cout<<"download success & done" <<endl;
			}
			else {
				cout<<"an err in dudupcore"<<endl;
			}
		}
		/*while metadata recv.ed, perform first stage deduplication*/
		if (indicator == META) {
			memcpy(metaBuffer, buffer, count);
			metaSize = count;
			dedupObj_->firstStageDedup(user,(unsigned char*)metaBuffer, count, statusList, numOfShare, dataSize);
		}

		/*while data recv.ed, perform second stage deduplication*/
		if (indicator == DATA) {

			memset(statusList, 0, sizeof(bool)*BUFFER_LEN);
			dedupObj_->secondStageDedup(user, (unsigned char*)metaBuffer, metaSize, statusList, (unsigned char*)buffer, hashObj);
		}

	}
	/*free objects*/
	delete hashObj;
	free(buffer);
	free(statusList);
	free(metaBuffer);
	free(clientSock);
	cout<<"data socket end"<<endl;
	return 0;
}

void* SocketHandlerKey(void* lp){
	//double timer,split,bw;

	//get socket from input param
	int *clientSock = (int*)lp;

	//variable initialization
	int bytecount;
	char * buffer = (char*)malloc(sizeof(char)*BUFFER_LEN);
	char * metaBuffer = (char *)malloc(sizeof(char)*META_LEN);
	bool* statusList = (bool*)malloc(sizeof(bool)*BUFFER_LEN);
	memset(statusList,0,sizeof(bool)*BUFFER_LEN);
	int user = 0;

	//get user ID
	if ((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1){
		fprintf(stderr, "Error recv userID %d\n",errno);
	}
	user= ntohl(*(int*)buffer);
	cout<<"get connection from user : "<<user<<endl;
	memset(buffer, 0, BUFFER_LEN);

	//initialize hash object
	CryptoPrimitive* hashObj = new CryptoPrimitive(SHA256_TYPE);

	//main loop for recv data package
	while(true){

		/*recv indicator first*/
		if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1){
			fprintf(stderr, "Error receiving data %d\n", errno);
		}

		/*if client closes, break loop*/
		if(bytecount == 0) break;

		int indicator = *(int*)buffer;


		/* New file coming, store the new cipher and cipher meta */
		if (indicator == NEW){

			/*recv following package size*/
			if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1)    {
				fprintf(stderr, "Error receiving data %d\n", errno);
			}

			/* get file name */
			int namesize = *(int*)buffer;

			char namebuffer[33];
			if((bytecount = recv(*clientSock, namebuffer, namesize, 0)) == -1    ){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			namebuffer[32] = '\0';

			/* create a new cipher file */
			char name[256];
			sprintf(name, "keystore/%s.cipher", namebuffer);

			FILE* fp = fopen(name, "w");

			/* recv cipher size */
			if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1)    {
				fprintf(stderr, "Error receiving data %d\n", errno);
			}

			int ciphersize = *(int*)buffer;

			/* recv cipher */
			int total = 0;
			while (total < ciphersize) {
				
				if((bytecount = recv(*clientSock, buffer+total, ciphersize-total, 0)) == -1){
					fprintf(stderr, "Error receiving data %d\n", errno);
				}
				total+=bytecount;
			}

			fwrite(buffer, 1, ciphersize, fp);
			fclose(fp);

			/* recv meta size */
			if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1)    {
				fprintf(stderr, "Error receiving data %d\n", errno);
			}

			int metasize = *(int*)buffer;

			/* recv meta */
			total = 0;
			while (total < metasize) {
				
				if((bytecount = recv(*clientSock, buffer+total, metasize-total, 0)) == -1){
					fprintf(stderr, "Error receiving data %d\n", errno);
				}
				total+=bytecount;
			}
			sprintf(name, "keystore/%s.meta", namebuffer);

			fp = fopen(name, "w");
			fwrite(buffer, 1, metasize, fp);

			fclose(fp);


			break;

		}

		if (indicator == DOWNLOAD_KEY) {
			if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}

			/* get file name */
			int namesize = *(int*)buffer;

			char namebuffer[33];
			if((bytecount = recv(*clientSock, namebuffer, namesize, 0)) == -1){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			namebuffer[32] = '\0';

			/* read the target cipher file */
			char name[256];
			sprintf(name, "keystore/%s.cipher", namebuffer);

			FILE* fp = fopen(name, "r");
			fseek(fp, 0, SEEK_END);
			int length = ftell(fp);
			fseek(fp, 0, SEEK_SET);

			char* cipher = (char*)malloc(sizeof(char)*length+sizeof(int));
			memcpy(cipher, &length, sizeof(int));

			int ret;
			ret = fread(cipher+4, 1, length, fp);
			if (ret != length){
				printf("error reading cipher file\n");
			}
			fclose(fp);
			/* send back cipher */
			if ((bytecount = send(*clientSock, cipher, length+4, 0)) == -1){
				fprintf(stderr, "Error sending data %d\n", errno);
			}
			free(cipher);
			break;
		}

		/* update cipher and cipher meta */
		if(indicator == UPDATE){
			if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}

			/* get file name */
			int namesize = *(int*)buffer;

			char namebuffer[33];
			if((bytecount = recv(*clientSock, namebuffer, namesize, 0)) == -1){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			namebuffer[32] = '\0';

			/* read the target cipher file */
			char name[256];
			sprintf(name, "keystore/%s.cipher", namebuffer);

			FILE* fp = fopen(name, "r");
			fseek(fp, 0, SEEK_END);
			int length = ftell(fp);
			fseek(fp, 0, SEEK_SET);

			char* cipher = (char*)malloc(sizeof(char)*length+sizeof(int));
			memcpy(cipher, &length, sizeof(int));

			int ret;
			ret = fread(cipher+4, 1, length, fp);
			if (ret != length){
				printf("error reading cipher file\n");
			}
			fclose(fp);
			/* send back cipher */
			if ((bytecount = send(*clientSock, cipher, length+4, 0)) == -1){
				fprintf(stderr, "Error sending data %d\n", errno);
			}
			free(cipher);
			/* read meta */
			sprintf(name, "keystore/%s.meta", namebuffer);
			fp = fopen(name, "r");
			fseek(fp, 0, SEEK_END);
			length = ftell(fp);
			fseek(fp, 0, SEEK_SET);
			char* meta = (char*)malloc(sizeof(char)*length+sizeof(int));
			memcpy(meta, &length, sizeof(int));
			ret = fread(meta+4, 1, length, fp);
			if (ret != length) {

				printf("error reading meta file\n");
			}
			fclose(fp);
			/* send back meta */
			if ((bytecount = send(*clientSock, meta, length+4, 0)) == -1) {

				fprintf(stderr, "Error sending data %d\n", errno);
			}
			free(meta);
			/* get back updated cipher */
			sprintf(name, "keystore/%s.cipher", namebuffer);
			fp = fopen(name, "w");
			if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1){
				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			int ciphersize = *(int*)buffer;
			int total = 0;
			while (total < length) {
				
				if ((bytecount = recv(*clientSock, buffer+total, ciphersize-total, 0)) == -1) {
	
					fprintf(stderr, "Error receiving data %d\n", errno);
				}
				total+=bytecount;
			}
			fwrite(buffer, 1, ciphersize, fp);
			fclose(fp);
			/* get back meta */
			if ((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {

				fprintf(stderr, "Error receiving data %d\n", errno);
			}
			int metasize = *(int*)buffer;
			total = 0;
			while (total < length) {
				
				if ((bytecount = recv(*clientSock, buffer+total, metasize-total, 0)) == -1) {
	
					fprintf(stderr, "Error receiving data %d\n", errno);
				}
				total+=bytecount;
			}
			sprintf(name, "keystore/%s.meta", namebuffer);
			fp = fopen(name, "w");
			fwrite(buffer, 1, metasize, fp);
			fclose(fp);
			break;
		}
	}
	
	/*free objects*/
	delete hashObj;
	free(buffer);
	free(statusList);
	free(metaBuffer);
	free(clientSock);
	cout<<"key socket end"<<endl;
	return 0;
}

/*
 * main procedure for receiving data
 * 
 */
void Server::runReceive() {

	addrSize_ = sizeof(sockaddr_in);

	//create a thread whenever a client connects
	while (true) {

		printf("waiting for a connection\n");
		clientSock_ = (int*)malloc(sizeof(int));
		keyclientSock_ = (int*)malloc(sizeof(int));
		
		if ((*clientSock_ = accept(dataHostSock_, (sockaddr*)&sadr_, &addrSize_)) != -1) {
		
			printf("Received data connection from %s\n", inet_ntoa(sadr_.sin_addr));
			pthread_create(&threadId_, 0, &SocketHandler, (void*)clientSock_);
			pthread_detach(threadId_);
		}
		else {

			fprintf(stderr, "Error accepting %d\n", errno);
		}
		
		if ((*keyclientSock_ = accept(keyHostSock_, (sockaddr*)&sadr_, &addrSize_)) != -1) {
		
			printf("Received Key connection from %s\n", inet_ntoa(sadr_.sin_addr));
			pthread_create(&threadId_, 0, &SocketHandlerKey, (void*)keyclientSock_);
			pthread_detach(threadId_);
		}
		else {

			fprintf(stderr, "Error accepting %d\n", errno);
		}
	}
}

