#include "auth.h"

#include <botan/data_src.h>
#include <botan/x509_key.h>
#include <botan/x509path.h>
#include <botan/pkcs8.h>

using namespace Botan;

namespace Bless
{
  /**
   * @brief Construct an empty AuthKeys.
   *
   * @warning call init() to make this valid.
   */
  AuthKeys::AuthKeys()
  {
  }

  /**
   * @brief destruct AuthKeys along with its internal keys.
   */
  AuthKeys::~AuthKeys()
  {
  }

  /**
   * @brief initialize an AuthKeys from serialized keys.
   *
   * If this function fails to deserialize the inputs, the object still is not
   * valid.
   *
   * The given certificates are checked for validity and must be self-signed.
   * If init() succeeds; the certificates can be trusted.
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
      serverCert =
        std::unique_ptr<X509_Certificate const>(new X509_Certificate(server));

      //verify cert is self-signed and valid
      if(!(serverCert->is_self_signed() &&
          serverCert->check_signature(*serverCert->subject_public_key())))
      {
        return -10;
      }
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
      receiverCert =
        std::unique_ptr<X509_Certificate const>(
            new X509_Certificate(recvCert));

      //verify cert is self-signed and valid
      if(!(receiverCert->is_self_signed() &&
          receiverCert->check_signature(*receiverCert->subject_public_key())))
      {
        return -11;
      }
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
      receiverPrivKey =
        std::unique_ptr<Private_Key>(PKCS8::load_key(recvKey, rng));
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
   * @return serverCert without transfering ownership.
   */
  Botan::X509_Certificate const *AuthKeys::getServerCert() const
  {
    return serverCert.get();
  }

  /**
   * @brief return a pointer to the Receiver's certificate.
   *
   * @return receiverCert without transfering ownership.
   */
  Botan::X509_Certificate const *AuthKeys::getReceiverCert() const
  {
    return receiverCert.get();
  }

  /**
   * @brief return a pointer to the Receiver's private key.
   *
   * @return receiverPrivKey without transfering ownership.
   */
  Botan::Private_Key *AuthKeys::getReceiverPrivKey() const
  {
    return receiverPrivKey.get();
  }
}
