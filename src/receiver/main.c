/**
 * @file main.c
 * @brief run as the Receiver role in the protocol.
 */

#include "auth.h"
#include "connections.h"

/**
 * @struct listenArgs
 * @brief parsed command lines arguments.
 *
 * @var char *listenArgs::serverAddress
 * @brief ip address of the Server
 */
struct listenArgs
{
  char *serverAddress;
};

/**
 * @brief parse the arguments passed into main().
 *
 * Parse command line arguments and write them out to an argument structure.
 *
 * @param argc argc from main().
 * @param argv argv from main().
 * @param argOut pointer to the structure to write parsed arguments to.
 * @return zero on success, non-zero on failure.
 */
int argParser(int argc, char **argv, struct listenArgs *argOut)
{

}

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
