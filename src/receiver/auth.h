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
   * @class AuthKeys
   * @brief Long-standing authentication keys for the message channel.
   *
   * This should be staged into memory from disk.
   *
   * The keys are preshared, by some external PKI, and used for authenticated
   * Diffie-Hellman.
   *
   * @var Botan::PublicKey const *AuthKeys::serverKey
   * @brief public signing key of the Server.
   *
   * @var Botan::Private_Key const *AuthKeys::receiverKey;
   * @brief private signing key of the Receiver.
   */
  class AuthKeys
  {
    public:
      AuthKeys();
      ~AuthKeys();
      int init(std::istream &server, std::istream &receiver,
        Botan::RandomNumberGenerator &);
    private:
      Botan::Public_Key const *serverKey;
      Botan::Private_Key const *receiverKey;
  };
}

#endif //AUTH_H
