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
#ifndef RESOURCE_PATH
#define RESOURCE_PATH "./"
#endif //RESOURCE_PATH

using namespace Bless;

int getMessage(unsigned char const *const, std::size_t);

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
 * @var std::string ListenArgs::receiverCertFile
 * @brief path to the Receiver's certificate exchanged with the Server
 *
 * @var std::string ListenArgs::serverCertFile
 * @brief path to the Server's certificate key on disk
 *
 * @var unsigned short ListenArgs::port
 * @brief udp port to connect to the Server on
 *
 * @var std::string ListenArgs::defaultServerCertFile
 * @brief default file to load the Server's certificate key from
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
  std::string receiverCertFile;
  std::string serverCertFile;
  unsigned short port;

  static const std::string defaultReceiverCertFile;
  static const std::string defaultServerCertFile;
  static const unsigned short defaultPort = 9549;
};

const std::string ListenArgs::defaultReceiverCertFile =
  RESOURCE_PATH"receiverCert.pem";
const std::string ListenArgs::defaultServerCertFile =
  RESOURCE_PATH"serverCert.pem";

/**
 * @brief parse the arguments passed into main().
 *
 * Parse command line arguments and write them out to an argument structure.
 * \p argv should take the form:
 *  @code binary serverAddress receiverPrivateKey [receiverCertificate]
 *    [serverCertificate] [port]@endcode
 *
 *  @bug the optional arguments are not parsed.
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

  if(argc > 5)
  {
    //too many arguments
    return -2;
  }

  //pull out the required arguments
  serverAddress = std::string(argv[1]);
  receiverKeyFile = std::string(argv[2]);

  //check for optional argument
  receiverCertFile = defaultReceiverCertFile;
  serverCertFile = defaultServerCertFile;

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
    "usage: ./binary serverAddress receiverPrivateKey [receiverCertificate] "
    "[serverCertificate] [port]" <<
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
  if((error = authKeys.init(args.serverCertFile, args.receiverCertFile,
      args.receiverKeyFile, rng)))
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

  //establish the message channel: connect to the Server
  if((error = chan.connect(rng, getMessage)))
  {
    std::cerr << "Failed to connect" << std::endl;
    goto fail;
  }

  //listen for messages from the Sender
  if((error = chan.listen()))
  {
    std::cerr << "listen() failed." << std::endl;
    goto fail;
  }

fail:
  return error;
}

/**
 * @brief callback when a new message is received from the Sender.
 *
 * This follows the interface for Channel::recvCallback.
 *
 * XXX: Is \p payload secure memory?
 *
 * @todo this is the raw data from the Sender; authenticate it
 *
 * @param payload message data from the Sender.
 * @param len the length, in bytes, of \p payload.
 * @return non-zero on error.
 */
int getMessage(unsigned char const *const payload, std::size_t len)
{
    for(std::size_t i = 0; i < len; ++i)
    {
      std::cout << payload[i];
    }
    std::cout.flush();

    return 0;
}
