#include "auth.h"

#include <botan/data_src.h>
#include <botan/x509_key.h>
#include <botan/x509cert.h>
#include <botan/pkcs8.h>

using namespace Botan;

namespace Bless
{
  /**
   * @brief Construct an empty AuthKeys.
   *
   * @warning call init() to make this valid.
   */
  AuthKeys::AuthKeys() : serverCert(nullptr), receiverCert(nullptr),
      receiverPrivKey(nullptr)
  {
  }

  /**
   * @brief destruct AuthKeys along with its internal keys.
   *
   * Only deallocate a key if its not null.
   */
  AuthKeys::~AuthKeys()
  {
    if(serverCert)
    {
      delete serverCert;
    }

    if(receiverCert)
    {
      delete receiverCert;
    }

    if(receiverPrivKey)
    {
      delete receiverPrivKey;
    }
  }

  /**
   * @brief initialize an AuthKeys from serialized keys.
   *
   * If this function fails to deserialize the inputs, the object still is not
   * valid.
   *
   * The keys must be signing keys.
   *
   * @param server filename for Server's X509 certificate.
   * @param recvCert filename to deserialize the Receiver's certificate from.
   * @param recvKey filename to deserialize the Receiver's private key from.
   * @param rng random number generator for loading the private key.
   * @return 0 on success, non-zero on failure.
   */
  int AuthKeys::init(std::string const &server, std::string const &recvCert,
      std::string const &recvKey, Botan::RandomNumberGenerator &rng)
  {
    //deserialize the Server's cert
    try
    {
      serverCert = new X509_Certificate(server);
    }
    catch(Decoding_Error &e)
    {
      return -1;
    }
    catch(Stream_IO_Error &e)
    {
      return -2;
    }
    catch(std::bad_alloc &e)
    {
      return -8;
    }

    //deserialize Receiver's cert
    try
    {
      receiverCert = new X509_Certificate(recvCert);
    }
    catch(Decoding_Error &e)
    {
      return -3;
    }
    catch(Stream_IO_Error &e)
    {
      return -4;
    }
    catch(std::bad_alloc &e)
    {
      return -9;
    }

    //deserialize Receiver's private key
    try
    {
      receiverPrivKey = PKCS8::load_key(recvKey, rng);
    }
    catch(Stream_IO_Error &e)
    {
      return -5;
    }
    catch(PKCS8_Exception &e)
    {
      return -6;
    }
    catch(Decoding_Error &e)
    {
      //unknown algorithm
      return -7;
    }

    //no error otherwise
    return 0;
  }

  /**
   * @brief return a pointer to the Server's certificate.
   *
   * @return serverCert.
   */
  Botan::X509_Certificate const *AuthKeys::getServerCert() const
  {
    return serverCert;
  }

  /**
   * @brief return a pointer to the Receiver's certificate.
   *
   * @return receiverCert.
   */
  Botan::X509_Certificate const *AuthKeys::getReceiverCert() const
  {
    return receiverCert;
  }

  /**
   * @brief return a pointer to the Receiver's private key.
   *
   * @return receiverPrivKey.
   */
  Botan::Private_Key *AuthKeys::getReceiverPrivKey() const
  {
    return receiverPrivKey;
  }
}
