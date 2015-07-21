#ifndef AUTH_H
#define AUTH_H

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
  };
}

#endif //AUTH_H
