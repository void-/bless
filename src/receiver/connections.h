#ifndef CONNECTIONS_H
#define CONNECTIONS_H

int tcpBootstrap(char const *host, unsigned short port,
  struct serverAuthKeys const *, struct sessionKeys *);

int udpBootstrap(char const *host, unsigned short port,
  struct sessionKeys const *, int *socket);

int listenLoop(int socket, struct sessionKeys const *, struct messageKeys *);
#endif //CONNECTIONS_H
