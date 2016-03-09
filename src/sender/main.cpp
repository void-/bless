/**
 * @file
 * @brief send a message, as the Sender, to a Receiver's Server.
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

/**
 * @struct SendArgs
 * @brief parsed command lines arguments.
 *
 * @var std::string SendArgs::serverAddress
 * @brief ip address of the Server
 *
 * All key and certificate strings are file paths.
 *
 * @var std::string SendArgs::senderReceiverCert
 * @brief the certificate the Receiver has for the Sender.
 *
 * @var std::string SendArgs::senderServerCert
 * @brief certificate the Sender uses for a TLS connection to the Server.
 *
 * @var std::string SendArgs::serverCert
 * @brief the expected certificate the Server will use in the TLS connection.
 *
 * @var std::string SendArgs::receiverCert
 * @brief contains the public key of the Receiver. For encryption.
 *
 * @var std::string SendArgs::senderReceiverKey
 * @brief private half of senderReceiverCert.
 *
 * @var std::string SendArgs::senderServerKey
 * @brief private half of senderServerCert.
 *
 * @var unsigned short SendArgs::port
 * @brief tcp port to connect to the Server on
 *
 * @var std::string SendArgs::defaultSenderReceiverCert
 * @brief default path for senderReceiverCert if unspecified in arguments.
 *
 * @var std::string SendArgs::defaultSenderServerCert
 * @brief default path for senderServerCert if unspecified in arguments.
 *
 * @var std::string SendArgs::defaultServerCert
 * @brief default path for serverCert if unspecified in arguments.
 *
 * @var std::string SendArgs::defaultReceiverCert
 * @brief default path for receiverCert if unspecified in arguments.
 *
 * @var std::string SendArgs::defaultSenderReceiverKey
 * @brief default path for senderReceiverKey if unspecified in arguments.
 *
 * @var std::string SendArgs::defaultSenderServerKey
 * @brief default path for senderServerKey if unspecified in arguments.
 * 
 * @var unsigned short SendArgs::defaultPort
 * @brief default port to use to connect to the Server
 */
struct SendArgs
{
  int init(int argc, char **argv);
  void usage() const;

  std::string serverAddress;
  std::string senderReceiverCert;
  std::string senderServerCert;
  std::string serverCert;
  std::string receiverCert;
  std::string senderReceiverKey;
  std::string senderServerKey;
  unsigned short port;

  static const std::string defaultSenderReceiverCert;
  static const std::string defaultSenderServerCert;
  static const std::string defaultServerCert;
  static const std::string defaultReceiverCert;
  static const std::string defaultSenderReceiverKey;
  static const std::string defaultSenderServerKey;
  static const unsigned short defaultPort = 9548;
};

const std::string SendArgs::defaultSenderReceiverCert =
  RESOURCE_PATH"senderCert.pem";
const std::string SendArgs::defaultSenderServerCert =
  RESOURCE_PATH"senderCert.pem";
const std::string SendArgs::defaultServerCert =
  RESOURCE_PATH"serverCert.pem";
const std::string SendArgs::defaultReceiverCert =
  RESOURCE_PATH"receiverCert.pem";
const std::string SendArgs::defaultSenderReceiverKey =
  RESOURCE_PATH"sender.pem";
const std::string SendArgs::defaultSenderServerKey =
  RESOURCE_PATH"sender.pem";

/**
 * @brief parse the arguments passed into main().
 *
 * Parse command line arguments and write them out to an argument structure.
 * \p argv should take the form:
 * @todo actualy parse arguments; only defaults are currently set.
 *
 * @param argc argc from main().
 * @param argv argv from main().
 * @return zero on success, non-zero on failure.
 */
int SendArgs::init(int argc, char **argv)
{
  if(argc < 2)
  {
    //too few arguments
    return -1;
  }

  //pull out the required arguments
  serverAddress = std::string(argv[1]);

  //check for optional argument
  senderReceiverCert = defaultSenderReceiverCert;
  senderServerCert = defaultSenderServerCert;
  serverCert = defaultServerCert;
  receiverCert = defaultReceiverCert;
  senderReceiverKey = defaultSenderReceiverKey;
  senderServerKey = defaultSenderServerKey;

  //no parsing for port yet
  port = defaultPort;

  return 0;
}

/**
 * @brief write the expected argument format to stderr.
 */
void SendArgs::usage() const
{
  std::cerr << "usage: ./binary serverAddress" << std::endl;
}

/**
 * @brief setup and run the Receiver client.
 *
 * Steps:
 * -# parse arguments
 * -# load persistent keys
 * -# get message from user
 * -# make a connection to Server
 *
 * @param argc length of \p argv.
 * @param argv argument vector to run the Receiver, parsed by argParser().
 * @return non-zero on failure.
 */
int main(int argc, char **argv)
{
  int error = 0;
  SendArgs args;
  AuthKeys authKeys;
  Channel chan;
  Botan::AutoSeeded_RNG rng;
  std::string message;
  EphemeralKey receiverKey;
  Message msg;

  //parse the arguments
  if((error = args.init(argc, argv)))
  {
    args.usage();
    goto fail;
  }

  //stage in the authentication keys
  if((error = authKeys.init(args.senderReceiverCert, args.senderServerCert,
      args.serverCert, args.receiverCert, args.senderReceiverKey,
      args.senderServerKey, rng)))
  {
    std::cerr << "Failed to load authentication keys" << std::endl;
    goto fail;
  }

  //initialize the channel, but don't connect it yet
  if((error = chan.init(&authKeys, args.serverAddress, args.port, &rng)))
  {
    std::cerr << "Failed to initialize channel" << std::endl;
    goto fail;
  }

  //get a message from the user
  if((error = msg.init(std::cin, *authKeys.getSenderReceiverKey(),
      *authKeys.getSenderReceiverCert(), rng)))
  {
    std::cerr << "Failed to read message data or generate Sender key" <<
      std::endl;
    goto fail;
  }

  //connect to the Server
  if((error = chan.connect()))
  {
    std::cerr << "Failed to connect" << std::endl;
    goto fail;
  }

  //receive an ephemeral key from the Server on behalf of the Receiver
  if((error =
      chan.recvKey(receiverKey,
        *authKeys.getReceiverCert()->subject_public_key())))
  {
    std::cerr << "Failed to receive or verify ephemeral key" << std::endl;
    goto fail;
  }

  //encrypt message in place with received Sender key
  if((error = msg.encrypt(receiverKey)))
  {
    std::cerr << "Failed to encrypt under ephemeral key" << std::endl;
    goto fail;
  }

  //send the message to Server
  if((error = chan.sendMessage(msg)))
  {
    std::cerr << "Failed to send message" << std::endl;
    goto fail;
  }

fail:
  return error;
}
