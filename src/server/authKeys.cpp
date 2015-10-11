#include "authKeys.h"

#include <botan/pkcs8.h>

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
   * TODO: Reused code from Bless::Receiver::auth for loading priv key
   *
   * @param privPath the path to the serialized private key.
   * @param pubPath the path to the serialized certificate.
   * @param rng random number generator for loading private key.
   * @return non-zero on failure.
   */
  int ServerKey::init(std::string const &privPath, std::string const &pubPath,
      Botan::RandomNumberGenerator &rng)
  {
    //load the public key
    if(ConnectionKey::init(pubPath))
    {
      return -1;
    }

    //load the private key
    try
    {
      privKey = PKCS8::load_key(privPath, rng);
    }
    catch(Stream_IO_Error &e)
    {
      return -2;
    }
    catch(PKCS8_Exception &e)
    {
      return -3;
    }
    catch(Decoding_Error &e)
    {
      //unknown algorithm
      return -4;
    }

    //no error
    return 0;
  }

  /**
   * @brief return the private key for the ServerKey.
   *
   * Ownerhsip is still held by ServerKey.
   *
   * @return ServerKey::privKey.
   */
  Botan::Private_Key *ServerKey::getPrivKey()
  {
    return privKey;
  }
}
