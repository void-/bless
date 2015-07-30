/**
 * @file
 * @brief run as the Receiver role in the protocol.
 */

#include "auth.h"
#include "connections.h"

#include <string>
#include <iostream>
#include <fstream>

#include <botan/auto_rng.h>

/**
 * Directory path to default resources.
 */
#define RESOURCE_PATH "./"

using namespace Bless;

/**
 * @struct ListenArgs
 * @brief parsed command lines arguments.
 *
 * @var std::string ListenArgs::serverAddress
 * @brief ip address of the Server
 *
 * @var std::string ListenArgs::receiverKeyFile
 * @brief path to the Receiver's private key on disk
 *
 * @var std::string ListenArgs::serverKeyFile
 * @brief path to the Server's public key on disk
 *
 * @var unsigned short ListenArgs::port
 * @brief udp port to connect to the Server on
 *
 * @var std::string ListenArgs::defaultServerKeyFile
 * @brief default file to load the Server's public key from
 *
 * @var unsigned short ListenArgs::defaultPort
 * @brief default port to use to connect to the Server
 */
struct ListenArgs
{
  int init(int argc, char **argv);
  void usage() const;

  std::string serverAddress;
  std::string receiverKeyFile;
  std::string serverKeyFile;
  unsigned short port;

  static const std::string defaultServerKeyFile;
  static const unsigned short defaultPort = 8675;
};

const std::string ListenArgs::defaultServerKeyFile = RESOURCE_PATH"server.pem";

/**
 * @brief parse the arguments passed into main().
 *
 * Parse command line arguments and write them out to an argument structure.
 * \p argv should take the form:
 *  @code binary serverAddress receiverPrivateKey [ServerPublicKey]@endcode
 *
 * @param argc argc from main().
 * @param argv argv from main().
 * @return zero on success, non-zero on failure.
 */
int ListenArgs::init(int argc, char **argv)
{
  if(argc < 3)
  {
    //too few arguments
    return -1;
  }

  if(argc > 4)
  {
    //too many arguments
    return -2;
  }

  //pull out the required arguments
  serverAddress = std::string(argv[1]);
  receiverKeyFile = std::string(argv[2]);

  //check for optional argument
  if(argc > 3)
  {
    serverKeyFile = std::string(argv[3]);
  }
  else
  {
    serverKeyFile = defaultServerKeyFile;
  }

  //no parsing for port yet
  port = defaultPort;

  return 0;
}

/**
 * @brief write the expected argument format to stderr.
 */
void ListenArgs::usage() const
{
  std::cerr <<
    "usage: ./binary serverAddress receiverPrivateKey [ServerPublicKey]" <<
    std::endl;
}

/**
 * @brief setup and run the Receiver client.
 *
 * Steps:
 * -# parse arguments
 * -# load persistent keys
 * -# register signal handlers for interupting
 * -# create a new Channel(), listening for messages
 * -# write back Sender to Receiver key data to persistent storage
 *
 * @param argc length of \p argv.
 * @param argv argument vector to run the Receiver, parsed by argParser().
 * @return non-zero on failure.
 */
int main(int argc, char **argv)
{
  int error = 0;
  ListenArgs args;
  AuthKeys authKeys;
  Channel chan;
  Botan::AutoSeeded_RNG rng;

  //parse the arguments
  if((error = args.init(argc, argv)))
  {
    args.usage();
    goto fail;
  }

  //stage in the authentication keys
  if((error = authKeys.init(args.serverKeyFile, args.receiverKeyFile, rng)))
  {
    std::cerr << "Failed to load authentication keys" << std::endl;
    goto fail;
  }

  //initialize the channel, but don't connect it yet
  if((error = chan.init(&authKeys, args.serverAddress, args.port)))
  {
    std::cerr << "Failed to initialize channel" << std::endl;
    goto fail;
  }

fail:
  return error;
}
