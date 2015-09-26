#include "authKeys.h"

namespace Bless
{
  /**
   * @brief destruct a ConnectionKey and all its owned resources.
   */
  ConnectionKey::~ConnectionKey()
  {
  }

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

  /**
   * @brief destruct a ServerKey and all its owned resources.
   *
   * Do nothing for now, lifecycle of privKey is unclear.
   */
  ServerKey::~ServerKey()
  {
  }

  /**
   * @brief initialize a ServerKey given the path to a serialized certificate.
   *
   * @param privPath the path to the serialized private key.
   * @param pubPath the path to the serialized certificate.
   * @return non-zero on failure.
   */
  int ServerKey::init(std::string const &privPath, std::string const &pubPath)
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
