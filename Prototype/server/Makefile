CC = g++
CFLAGS = -O3 -Wall
LIBS = -lcrypto -lssl -lpthread -lsnappy 
INCLUDES = -I./lib/leveldb-1.15.0/include -I./backend/ -I./utils/  -I./comm/ -I./dedup/ 
MAIN_OBJS = ./utils/CryptoPrimitive.o ./dedup/DedupCore.o ./backend/BackendStorer.o ./comm/server.o

all: leveldb server

	$(shell ! test -d "DedupDB" && mkdir DedupDB)
	$(shell ! test -d "ShareContainers" && mkdir ShareContainers)
	$(shell ! test -d "RecipeFiles" && mkdir RecipeFiles)
	$(shell ! test -d "keystore" && mkdir keystore)
	$(shell ! test -d "stubStore" && mkdir stubStore)

leveldb:
	make -C ./lib/leveldb-1.15.0

%.o: %.cc %.hh
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

server: main.cc $(MAIN_OBJS)  
	$(CC) $(CFLAGS) $(INCLUDES) -o SERVER main.cc $(MAIN_OBJS) ./lib/leveldb-1.15.0/libleveldb.a $(LIBS)

clean:
	@rm -f SERVER
	@rm -f $(MAIN_OBJS)
	@rm -rf DedupDB/
	@rm -rf ShareContainers/
	@rm -rf RecipeFiles/
	@rm -rf keystore/
	@rm -rf stubStore/
	@rm -rf datacurrent.meta
	@rm -rf keycurrent.meta
	@rm -rf shareFileBuffer
	


