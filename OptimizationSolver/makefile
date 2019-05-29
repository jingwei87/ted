# NOTE: ensure main function is included in main.cc 
EXEC_TARGET = main

# compiler & flags
CXX = g++
CPPFLAGS = -g -O3 -Wall -fno-operator-names -std=c++1y 
LDFLAGS = -lcrypto -pthread -lsnappy  -lmbedcrypto   

# directory structure
BUILD_DIR = ./build
SRC_DIRS = ./src
LIB_DIR = ./lib
OUTPUT_DIRS = ./tmp

# include & libraries
INC_DIRS := $(shell find $(LIB_DIR) -type d -and -name *include)
INC_LIBS := $(shell find $(LIB_DIR) -name *.a)
INC_LIBS := $(dir $(INC_LIBS))
INC_FLAGS := $(addprefix -L,$(INC_LIBS))
INC_FLAGS += $(addprefix -I,$(INC_DIRS))

SRCS := $(shell find $(SRC_DIRS) -name *.cpp -or -name *.c -or -name *.cc)

SRCS_TARGET := $(filter-out %_unittest.cpp %_unittest.c %_unittest.cc, $(SRCS))
OBJS_TARGET := $(SRCS_TARGET:$(SRC_DIRS)/%=$(BUILD_DIR)/%.o)

SRCS_TEST := $(filter-out %main.cpp %main.c %main.cc, $(SRCS))
OBJS_TEST := $(SRCS_TEST:$(SRC_DIRS)/%=$(BUILD_DIR)/%.o)

all: $(EXEC_TARGET)

$(EXEC_TARGET): $(OBJS_TARGET)
	$(MKDIR_P) $(OUTPUT_DIRS)
	$(CXX) -o $@ $^ $(INC_FLAGS) $(LDFLAGS) 

# c++ source
$(BUILD_DIR)/%.cc.o: $(SRC_DIRS)/%.cc
	$(MKDIR_P) $(dir $@)
	$(CXX) $(CPPFLAGS)  -c $< -o $@ $(INC_FLAGS) $(LDFLAGS)

.PHONY: all clean 

clean:
	$(RM) -r $(BUILD_DIR)
	$(RM) -r $(OUTPUT_DIRS)
	$(RM) $(EXEC_TARGET) $(EXEC_TEST) $(LOG)

-include $(DEPS)

MKDIR_P = mkdir -p