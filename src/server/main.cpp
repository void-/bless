/**
 * @file
 * @brief start the Server system.
 */

#include "connections.h"
#include "authKeys.h"
#include "persistentStore.h"

#include <iostream>

using namespace Bless;

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

  //...load ServerKeys

  //initialize main connection threads
  if((error = recv.init(&messages, &keyToReceiver)))
  {
    std::cerr << "Failed to initialize Receiver main." << std::endl;
    goto fail;
  }

  //initialize thread for handling connections to Sender
  if((error = sender.init(&messages, &keyToSender)))
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
