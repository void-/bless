/**
 * @file
 * @brief manage the authentication keys of the Receiver and Sender for the
 *   Server.
 */

#ifndef AUTHKEYS_H
#define AUTHKEYS_H

#include <botan/x509cert.h>
#include <botan/pk_keys.h>

#include "persistentStore.h"

namespace Bless
{
  /**
   * @class ConnectionKey
   * @brief abstract class for TLS authentication key stored in persistent
   *   memory.
   *
   * Key types
   * - Sender's cert to connect to the Server(many)
   * - Server's cert+key to connect to the Sender(one)
   * - Server's cert+key to connect to the Receiver(one)
   * - Receiver's cert to connect to the Server(one)
   *
   * @var Botan::X509_Certificate *ConnectionKey::cert
   * @brief certificate for the party this ConnectionKey represents
   */
  class ConnectionKey
  {
    public:
      virtual ~ConnectionKey();
      virtual int init(KeyStore &store) = 0;

      Botan::X509_Certificate const *getCert();
    protected:
      Botan::X509_Certificate const *cert;
  };

  /**
   * @class CounterpartyKey
   * @brief holds the certificate of either the Sender or Receiver.
   */
  class CounterpartyKey : public ConnectionKey
  {
    public:
      ~CounterpartyKey() override;
      int init(KeyStore &store) override;
  };

  /**
   * @class ServerKey
   * @brief stores both the certificate and corresponding private key of the
   *   Server.
   *
   * This is used for connections from both the Server to Sender and Server to
   * Receiver.
   *
   * @var Botan::Private_Key *receiverPrivKey
   * @brief private key for the Server.
   */
  class ServerKey : public ConnectionKey
  {
    public:
      ~ServerKey() override;
      int init(KeyStore &store) override;

      Botan::Private_Key const *getPrivKey();

    private:
      Botan::Private_Key *privKey;
  };
}

#endif //AUTHKEYS_H
