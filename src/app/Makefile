CXX = g++
INCLUDE = "../include/"
CPPFLAGS = -std=c++11 -Wall -Wextra -g -I$(INCLUDE)
LDFLAGS = -lbotan-1.11 -lpthread
KEYGEN = "keygen"

RM = rm -f

keygen: keygen.cpp
	$(CXX) $(CPPFLAGS) keygen.cpp $(LDFLAGS) -o $(KEYGEN)

.PHONY: clean

clean:
	$(RM) $(KEYGEN) *.o
