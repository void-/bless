/**
 * @file main.c
 * @brief run as the Receiver role in the protocol.
 */

#include "auth.h"
#include "connections.h"

/**
 * @brief setup and run the Receiver client.
 *
 * Steps:
 * -# parse arguments
 * -# load persistent keys
 * -# register signal handlers for interupting
 * -# call tcpBootstrap()
 * -# call udpBootstrap()
 * -# call listenLoop()
 * -# write back to persistent storage
 *
 * @param argc length of \p argv.
 * @param argv argument vector to run the Receiver in the form of:
 *  @code binary serverAddress privateKey @endcode
 * @return non-zero on failure.
 */
int main(int argc, char **argv)
{
}
