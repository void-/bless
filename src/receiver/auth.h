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
   * @var Botan::X509_Certificate const *AuthKeys::serverCert
   * @brief self-signed certificate containing public key of the Server.
   *
   * @var Botan::X509_Certificate const *AuthKeys::receiverCert
   * @brief self-signed certificate for the Receiver.
   *
   * @var Botan::X509_Certificate const *AuthKeys::receiverPrivKey
   * @brief private half of receiverCert.
   */
  class AuthKeys
  {
    public:
      AuthKeys();
      ~AuthKeys();
      int init(std::string const &server, std::string const &recvCert,
        std::string const &recvKey, Botan::RandomNumberGenerator &rng);
    private:
      Botan::X509_Certificate const *serverCert;
      Botan::X509_Certificate const *receiverCert;
      Botan::Private_Key const *receiverPrivKey;
  };
}

#endif //AUTH_H
