CC = g++
CFLAGS = -O3 -std=c++11# -g -ggdb -fsanitize=address
LIBS = -lcrypto -lssl -ljemalloc # -lpthread -lgf_complete -pg -lc
INCLUDES = -I./lib
MAIN_OBJS = 
all: SelfUpdate

%.o: %.cc %.hh
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

SelfUpdate: ./main.cc $(MAIN_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o SelfUpdate ./main.cc $(MAIN_OBJS)  $(LIBS) 

clean:
	@rm -f SelfUpdate
	@rm -f $(MAIN_OBJS)
