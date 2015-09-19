#include "authKeys.h"

namespace Bless
{
  /**
   * @brief return the public certificate associated with this ConnectionKey.
   *
   * Ownership is still held by ConnectionKey.
   *
   * @return ConnectionKey::cert.
   */
  Botan::X509_Certificate const *ConnectionKey::getCert()
  {
    return cert;
  }

  int CounterpartyKey::init(KeyStore &store)
  {
  }

  int ServerKey::init(KeyStore &store)
  {
  }

  /**
   * @brief return the private key for the ServerKey.
   *
   * Ownerhsip is still held by ServerKey.
   *
   * @return ServerKey::privKey.
   */
  Botan::Private_Key const *ServerKey::getPrivKey()
  {
    return privKey;
  }
}
