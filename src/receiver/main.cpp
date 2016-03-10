/**
 * @file
 * @brief run as the Receiver role in the protocol.
 */

#include "auth.h"
#include "connections.h"
#include "persistentStore.h"

#include <string>
#include <iostream>
#include <fstream>
#include <functional>

#include <botan/auto_rng.h>

/**
 * Directory path to default resources.
 */
#ifndef RESOURCE_PATH
#define RESOURCE_PATH "./"
#endif //RESOURCE_PATH

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
  std::string senderCertsPath;
  std::string ephemeralKeysPath;
  unsigned short port;

  static const std::string defaultReceiverCertFile;
  static const std::string defaultServerCertFile;
  static const std::string defaultSenderCerts;
  static const std::string defaultEphemeralKeys;
  static const unsigned short defaultPort = 9549;
};

const std::string ListenArgs::defaultReceiverCertFile =
  RESOURCE_PATH"receiverCert.pem";
const std::string ListenArgs::defaultServerCertFile =
  RESOURCE_PATH"serverCert.pem";
const std::string ListenArgs::defaultSenderCerts = RESOURCE_PATH;
const std::string ListenArgs::defaultEphemeralKeys =
  RESOURCE_PATH"/keys/priv/";

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

  if(argc > 7)
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
  senderCertsPath = defaultSenderCerts;
  ephemeralKeysPath = defaultEphemeralKeys;

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
    "[serverCertificate] [senderCertificatesPath] [ephemeralKeys] [port]" <<
    std::endl;
}

/**
 * @brief use certificates and ephemeral keys to deserialize and decrypt
 * messages.
 *
 */
class MessageReceiver
{
  public:
    int init(KeyStore *certs_, EphemeralKeyStore *keys_);

    int receiveMessage(OpaqueMessage &msg);

  private:
    KeyStore *certs;
    EphemeralKeyStore *keys;
};

int MessageReceiver::init(KeyStore *certs_, EphemeralKeyStore *keys_)
{
  certs = certs_;
  keys = keys_;

  return 0;
}

/**
 * @brief use as a callback
 *
 * - deserialize \p msg into Message
 * - determine which certificate+keys to use
 * - decrypt message
 * - write to stdout
 *
 * @param msg opaque message off the wire
 */
int MessageReceiver::receiveMessage(OpaqueMessage &msg)
{
  int error = 0;
  Message m;
  Botan::X509_Certificate *cert;
  EphemeralKey *key;

  //deserialize opaque message
  if(m.deserialize(msg))
  {
    error = -8;
    goto fail;
  }

  //lookup Sender's certificate
  if(!(cert = certs->getCert(m.senderId)))
  {
    //unknown Sender
    error = -9;
    goto fail;
  }

  //lookup Receiver ephemeral key used
  if(!(key = keys->getKey(m.keyId)))
  {
    //key unknown or already deleted
    error = -10;
    goto fail;
  }

  //decrypt message
  if((error = m.decrypt(cert, key)))
  {
    goto fail;
  }

  //data is in m.data, dataSize bytes long
  for(std::size_t i = 0; i < Message::dataSize; ++i)
  {
    std::cerr << m.data[i];
  }

  //decryption successful, free ephemeral key
  if(keys->free(key))
  {
    error = -12;
  }

fail:
  std::cerr << "Message decryption failed, error: " << error << std::endl;
  if(error && key)
  {
    //some error, reuse key later
    if(keys->release(key))
    {
      //unknown key
      error = -11;
    }
  }
  return error;
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
  FileSystemStore senderCerts;
  FileSystemEphemeralStore ephemeralKeys;
  MessageReceiver recv;

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

  //load Sender certificate store
  if((error = senderCerts.init(args.senderCertsPath)))
  {
    std::cerr << "Failed to load Sender certificate store" << std::endl;
    goto fail;
  }

  //load Receiver ephemeral key store
  if((error = ephemeralKeys.init(args.defaultEphemeralKeys, rng)))
  {
    std::cerr << "Failed to load ephemeral key store" << std::endl;
    goto fail;
  }

  //initialize message receiver
  if((error = recv.init(&senderCerts, &ephemeralKeys)))
  {
    std::cerr << "Filed to initialize message receiver" << std::endl;
    goto fail;
  }

  //initialize the channel, but don't connect it yet
  if((error = chan.init(&authKeys, args.serverAddress, args.port, std::bind(
      &MessageReceiver::receiveMessage, &recv, std::placeholders::_1))))
  {
    std::cerr << "Failed to initialize channel" << std::endl;
    goto fail;
  }

  //establish the message channel: connect to the Server
  if((error = chan.connect(rng)))
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
