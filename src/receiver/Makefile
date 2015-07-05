CC = "gcc"
CFLAGS =
LDFLAGS =
BIN = "listen"

RM = rm -f

all: main

auth.o: auth.c auth.h
connections.o: connections.c connections.h
main: auth.o connections.o
	$(CC) $(CFLAGS) main.c auth.o connections.o $(LDFLAGS) -o $(BIN)

.PHONY: clean

clean:
	$(RM) $(BIN) *.o
