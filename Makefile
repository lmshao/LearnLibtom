CC = cc
LD = cc
SRCS = $(wildcard *.cpp)
OBJS = $(patsubst %.cpp, %.o, $(SRCS))

CFLAGS = -Wall -O2
INCLUDE = -I./include

OS = $(shell uname -s | tr [A-Z] [a-z])
#$(info OS=$(OS))

ifeq ($(OS), darwin)
LIB = -L./libs/mac -ltomcrypt
endif

ifeq ($(OS), linux)
LIB = -L./libs/linux -ltomcrypt
endif

TARGET = LibtomDemo

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) -o $@ $^ $(LIB)
	@echo "\033[0m\033[1A"

%.o:%.cpp
	@echo "\033[32m\033[1A"
	$(CC) -c $^ $(INCLUDE) $(CFLAGS)

clean:
	@echo "\033[32m\033[1A"
	rm -f $(OBJS) $(TARGET)
	@echo "\033[0m\033[1A"
