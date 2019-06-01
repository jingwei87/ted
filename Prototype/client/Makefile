CC = g++
CFLAGS = -O3 -Wall -fno-operator-names #-g2 -ggdb
LIBS = -lcrypto -lssl -lpthread -lgf_complete#-pg -lc
INCLUDES = -I./comm -I./coding -I./chunking -I./utils -I./keyClient -I./lib
MAIN_OBJS = ./chunking/chunker.o ./utils/CryptoPrimitive.o ./coding/CDCodec.o ./coding/encoder.o  ./comm/uploader.o  ./utils/socket.o ./comm/downloader.o ./coding/decoder.o

all: client

%.o: %.cc %.hh
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

client: ./main.cc $(MAIN_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o CLIENT ./main.cc $(MAIN_OBJS)  $(LIBS) 

clean:
	@rm -f CLIENT
	@rm -f $(MAIN_OBJS)
	rm -rf *.key
	rm -rf *.d
