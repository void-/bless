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
  ReceiverMain recv(messages);
  SenderMain sender(messages);

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
