CXX = g++
CPPFLAGS = -std=c++11 -Wall -Wextra -g
LDFLAGS = -lbotan-1.11 -lpthread
BIN = "listen"

RM = rm -f

all: main

auth.o: auth.cpp auth.h
connections.o: connections.cpp connections.h
main: auth.o connections.o
	$(CXX) $(CPPFLAGS) main.cpp auth.o connections.o $(LDFLAGS) -o $(BIN)

.PHONY: clean

clean:
	$(RM) $(BIN) *.o
