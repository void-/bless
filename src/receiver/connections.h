#ifndef CONNECTIONS_H
#define CONNECTIONS_H

int tcpBootstrap(char const * host, unsigned short port, struct sessionKeys *);
int udpBootstrap(char const * host, unsigned short port, int *socket);
#endif //CONNECTIONS_H
