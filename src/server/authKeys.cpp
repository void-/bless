#include "authKeys.h"

using namespace Botan;

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
   * @brief given a path to a serialized public cert, stage it into memory.
   *
   * TODO: this is repeated code from Bless::Receiver::auth
   *
   * @param path the filesystem path to load into ConnectionKey::cert.
   * @return non-zero on failure.
   */
  int ConnectionKey::init(std::string const &path)
  {
    try
    {
      cert = new X509_Certificate(path);

      //verify cert is self-signed and valid
      if(!(cert->is_self_signed() &&
          cert->check_signature(*cert->subject_public_key())))
      {
        return -1;
      }
    }
    catch(Decoding_Error &e)
    {
      return -2;
    }
    catch(Stream_IO_Error &e)
    {
      return -3;
    }
    catch(std::bad_alloc &e)
    {
      return -4;
    }

    return 0;
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
