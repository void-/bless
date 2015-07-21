/**
 * @file
 * @brief definitions for authentication between Receiver and Server.
 */

#ifndef AUTH_H
#define AUTH_H

#include <botan/pk_keys.h>

#include <istream>

namespace Bless
{
  /**
   * @brief Long-standing authentication keys for the message channel.
   *
   * This should be staged into memory from disk.
   *
   * Public key of the Server.
   * Private key of the Receiver.
   */
  class AuthKeys
  {
    public:
      AuthKeys();
      int init(std::istream &serverKeyFile, std::istream &receiverKeyFile);
      ~AuthKeys();
    private:
      Botan::Public_Key const *serverKey;
      Botan::Private_Key const *receiverKey;
  };
}

#endif //AUTH_H
