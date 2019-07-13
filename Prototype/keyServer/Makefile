CC = clang++
CFLAGS = -O3 -std=c++1z -g -ggdb
LIBS = -lcrypto -lssl -lpthread 
INCLUDES = -I./comm/
JERASURE_OBJS = 
MAIN_OBJS = ./comm/keyserver.o ./comm/solver.o

all: KEYMANAGER

%.o: %.cc %.hh
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

KEYMANAGER: main.cc $(MAIN_OBJS)  
	$(CC) $(CFLAGS) $(INCLUDES) -o KEYMANAGER main.cc $(MAIN_OBJS) $(LIBS)


clean:
	@rm -f KEYMANAGER
	@rm -f $(MAIN_OBJS)
