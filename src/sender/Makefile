CXX = g++
INCLUDE = "../include/"
CPPFLAGS = -std=c++11 -Wall -Wextra -g -I$(INCLUDE)
LDFLAGS = -lbotan-1.11 -lpthread
BIN = "send"

RM = rm -f

all: main

auth.o: auth.cpp auth.h
connections.o: connections.cpp connections.h
main: auth.o connections.o ../common/message.o
	$(CXX) $(CPPFLAGS) main.cpp auth.o connections.o ../common/message.o \
	$(LDFLAGS) -o $(BIN)

.PHONY: clean

clean:
	$(RM) $(BIN) *.o
