/**
 * @file
 * @brief start the Server system.
 */

#include "connections.h"
#include "authKeys.h"
#include "persistentStore.h"

#include <iostream>

/**
 * Directory path to default resources.
 */
#ifndef RESOURCE_PATH
#define RESOURCE_PATH "./"
#endif //RESOURCE_PATH

using namespace Bless;

std::string defaultServerSenderKey = RESOURCE_PATH"Sender";
std::string defaultServerSenderCert = RESOURCE_PATH"Sender.pub";
std::string defaultServerReceiverKey = RESOURCE_PATH"Receiver";
std::string defaultServerReceiverCert = RESOURCE_PATH"Receiver.pub";
std::string defaultSenderCert = RESOURCE_PATH;

/**
 * @brief run the bless Server.
 *
 * Currently, no arguments are parsed and only basic setup is done for the
 * Server.
 *
 * In the future, authentication keys should be loaded from alternative
 * resources if available via \p argv.
 *
 * @param argc length of \p argv.
 * @param argv argument vector to run the server with non-default behaviour.
 * @return non-zero on failure.
 */
int main(int argc, char **argv)
{
  int error = 0;
  InMemoryMessageQueue messages;
  ReceiverMain recv;
  SenderMain sender;
  ServerKey keyToSender;
  ServerKey keyToReceiver;
  FileSystemStore store;

  //load Server keys
  if((error =
      (keyToSender.init(defaultServerSenderKey, defaultServerSenderCert))))
  {
    std::cerr << "Failed to load Server public or private key to Sender." <<
      std::endl;
    goto fail;
  }

  if((error =
      (keyToReceiver.init(
        defaultServerReceiverKey, defaultServerReceiverCert))))
  {
    std::cerr << "Failed to load Server public or private key to Receiver." <<
      std::endl;
    goto fail;
  }

  //load Sender certificate store
  if((error = store.init(defaultSenderCert)))
  {
    std::cerr << "Couldn't load Sender certificate stores." << std::endl;
    goto fail;
  }

  //initialize main connection threads
  if((error = recv.init(&messages, &keyToReceiver)))
  {
    std::cerr << "Failed to initialize Receiver main." << std::endl;
    goto fail;
  }

  //initialize thread for handling connections to Sender
  if((error = sender.init(&messages, &keyToSender, &store)))
  {
    std::cerr << "Failed to initialize Sender main." << std::endl;
    goto fail;
  }

  //start the sender main thread
  if((error = sender.start()))
  {
    std::cerr << "Failed to start Sender thread." << std::endl;
    goto fail;
  }

  //start and block on the receiver
  if((error = recv.start()))
  {
    std::cerr << "Failed to start Receiver." << std::endl;
    goto fail;
  }

fail:
  return error;
}
