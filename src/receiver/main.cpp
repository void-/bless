/**
 * @file
 * @brief run as the Receiver role in the protocol.
 */

#include "auth.h"
#include "connections.h"

#include <string>

/**
 * @struct listenArgs
 * @brief parsed command lines arguments.
 *
 * @var std::string listenArgs::serverAddress
 * @brief ip address of the Server
 */
struct ListenArgs
{
  std::string serverAddress;
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
int argParser(int argc, char **argv, ListenArgs *argOut)
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
 * -# write back Sender to Receiver key data to persistent storage
 *
 * @param argc length of \p argv.
 * @param argv argument vector to run the Receiver in the form of:
 *  @code binary serverAddress privateKey @endcode
 * @return non-zero on failure.
 */
int main(int argc, char **argv)
{
}
