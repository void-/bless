CXX = g++
INCLUDE = "../include/"
CPPFLAGS = -std=c++11 -Wall -Wextra -g -I$(INCLUDE)
LDFLAGS = -lbotan-1.11 -lpthread
BIN = "bless"

RM = rm -f

all: main

authKeys.o: authKeys.cpp authKeys.h
connections.o: connections.cpp connections.h
persistentStore.o: persistentStore.cpp persistentStore.h
main: authKeys.o connections.o persistentStore.o
	$(CXX) $(CPPFLAGS) main.cpp authKeys.o connections.o persistentStore.o \
	$(LDFLAGS) -o $(BIN)

.PHONY: clean

clean:
	$(RM) $(BIN) *.o
