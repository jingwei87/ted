CC = g++
CFLAGS = -O3 -Wall -Werror -Wunreachable-code -Wshadow -DLINUX -Wno-write-strings
LIBS = -lcrypto -lssl -lpthread 
INCLUDES = -I./comm/
JERASURE_OBJS = 
MAIN_OBJS = ./comm/keyserver.o 

all: server

%.o: %.cc %.hh
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

server: main.cc $(MAIN_OBJS)  
	$(CC) $(CFLAGS) $(INCLUDES) -o KEYMANAGER main.cc $(MAIN_OBJS) $(LIBS)


clean:
	@rm -f KEYMANAGER
	@rm -f $(MAIN_OBJS)
