CC = clang++
CFLAGS = -O3 -std=c++11# -g -ggdb -fsanitize=address
LIBS = -lcrypto -lssl -lpthread -lgf_complete#-pg -lc
INCLUDES = -I./comm -I./coding -I./chunking -I./utils -I./keyClient -I./lib
MAIN_OBJS = ./chunking/chunker.o ./utils/CryptoPrimitive.o ./coding/CDCodec.o ./coding/encoder.o  ./comm/uploader.o  ./utils/socket.o ./utils/ssl.o ./comm/downloader.o ./coding/decoder.o ./keyClient/exchange.o ./keyClient/MurmurHash3.o

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
