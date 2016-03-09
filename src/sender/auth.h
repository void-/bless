/**
 * @file
 * @brief defines authentication keys between Sender, Server and Receiver.
 */

#ifndef AUTH_H
#define AUTH_H

#include <botan/pk_keys.h>
#include <botan/x509cert.h>

#include <istream>

namespace Bless
{
  /**
   * @class AuthKeys
   * @brief Long-standing authentication keys for the Sender.
   *
   * @todo this is copied from Bless::Receiver
   *
   * This should be staged into memory from disk.
   *
   * The keys are preshared, by some external PKI, and used for authenticated
   * Diffie-Hellman.
   *
   * @var Botan::X509_Certificate const *AuthKeys::senderReceiverCert
   * @brief certificate to identify the Sender to the Receiver.
   *
   * @var Botan::X509_Certificate const *AuthKeys::senderServerCert
   * @brief self-signed certificate containing public key of the Sender for a
   *   TLS connection to the Server.
   *
   * @var Botan::X509_Certificate const *AuthKeys::serverCert
   * @brief self-signed certificate containing public key of the Server.
   *
   * @var Botan::X509_Certificate const *AuthKeys::receiverCert
   * @brief self-signed certificate for the Receiver.
   *
   * @var Botan::X509_Certificate const *AuthKeys::senderReceiverKey
   * @brief private half of senderReceiverKey, used for signing.
   *
   * @var Botan::X509_Certificate const *AuthKeys::senderServerKey
   * @brief private half of senderServerKey, used for the TLS connection.
   */
  class AuthKeys
  {
    public:
      AuthKeys();
      ~AuthKeys();

      int init(std::string const &senderReceiverCert_,
        std::string const &senderServerCert_, std::string const &serverCert_,
        std::string const &receiverCert_,
        std::string const &senderReceiverKey_,
        std::string const &senderServerKey_,
        Botan::RandomNumberGenerator &rng);

      Botan::X509_Certificate const *getSenderCert() const;
      Botan::X509_Certificate const *getSenderReceiverCert() const;
      Botan::X509_Certificate const *getReceiverCert() const;
      Botan::X509_Certificate const *getServerCert() const;
      Botan::Private_Key *getSenderReceiverKey() const;
      Botan::Private_Key *getSenderPrivKey() const;

    private:
      Botan::X509_Certificate const *senderReceiverCert;
      Botan::X509_Certificate const *senderServerCert;
      Botan::X509_Certificate const *serverCert;
      Botan::X509_Certificate const *receiverCert;
      Botan::Private_Key *senderReceiverKey;
      Botan::Private_Key *senderServerKey;
  };
}

#endif //AUTH_H
