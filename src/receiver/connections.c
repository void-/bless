/**
 * @file connections.c
 * @brief manage network connections for the Receiver.
 */

#include "connections.h"

int tcpBootstrap(char const *host, unsigned short port,
    struct serverAuthKeys const *, struct sessionKeys *)
{

}

int udpBootstrap(char const *host, unsigned short port,
    struct sessionKeys const *, int *socket)
{

}

int listenLoop(int socket, struct sessionKeys const *, struct messageKeys *)
{

}
