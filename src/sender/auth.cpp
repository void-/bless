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
  AuthKeys::AuthKeys() : senderReceiverCert(nullptr),
      senderServerCert(nullptr), serverCert(nullptr), receiverCert(nullptr),
      senderReceiverKey(nullptr), senderServerKey(nullptr)
  {
  }

  /**
   * @brief destruct AuthKeys along with its internal keys.
   *
   * Only deallocate a key if its not null.
   */
  AuthKeys::~AuthKeys()
  {
    if(senderReceiverCert)
    {
      delete senderReceiverCert;
    }

    if(senderServerCert)
    {
      delete senderServerCert;
    }

    if(serverCert)
    {
      delete serverCert;
    }

    if(receiverCert)
    {
      delete receiverCert;
    }

    if(senderReceiverkey)
    {
      delete senderReceiverkey;
    }

    if(senderServerKey)
    {
      delete senderServerKey;
    }
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
   * @param sender filename for Sender's X509 certificate to the Receiver.
   * @param server filename for Server's X509 certificate.
   * @param recvCert filename to deserialize the Receiver's certificate from.
   * @param recvKey filename to deserialize the Receiver's private key from.
   *
   * @param rng random number generator for loading the private key.
   * @return 0 on success, non-zero on failure.
   */
  int AuthKeys::init(std::string const &senderReceiverCert_,
      std::string const &senderServerCert_, std::string const &serverCert_,
      std::string const &receiverCert_, std::string const &senderReceiverKey_,
      std::string const &senderServerKey_, Botan::RandomNumberGenerator &rng)
  {
    //deserialize certificates
    try
    {
      senderReceiverCert = new X509_Certificate(senderReceiverCert_);

      //verify cert is self-signed and valid
      if(!(senderReceiverCert->is_self_signed() &&
          senderReceiverCert->check_signature(
            *senderReceiverCert->subject_public_key())))
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

    try
    {
      senderServerCert = new X509_Certificate(senderServerCert_);

      //verify cert is self-signed and valid
      if(!(senderServerCert->is_self_signed() &&
          senderServerCert->check_signature(
            *senderServerCert->subject_public_key())))
      {
        return -5;
      }
    }
    catch(Decoding_Error &e)
    {
      return -6;
    }
    catch(Stream_IO_Error &e)
    {
      return -7;
    }
    catch(std::bad_alloc &e)
    {
      return -8;
    }

    try
    {
      serverCert = new X509_Certificate(serverCert_);

      //verify cert is self-signed and valid
      if(!(serverCert->is_self_signed() && serverCert->check_signature(
          *serverCert->subject_public_key())))
      {
        return -9;
      }
    }
    catch(Decoding_Error &e)
    {
      return -10;
    }
    catch(Stream_IO_Error &e)
    {
      return -11;
    }
    catch(std::bad_alloc &e)
    {
      return -12;
    }

    try
    {
      receiverCert = new X509_Certificate(receiverCert_);

      //verify cert is self-signed and valid
      if(!(receiverCert->is_self_signed() && receiverCert->check_signature(
          *receiverCert->subject_public_key())))
      {
        return -13;
      }
    }
    catch(Decoding_Error &e)
    {
      return -13;
    }
    catch(Stream_IO_Error &e)
    {
      return -14;
    }
    catch(std::bad_alloc &e)
    {
      return -15;
    }

    //deserialize Sender's private key
    try
    {
      senderReceiver = PKCS8::load_key(senderReceiver_, rng);
    }
    catch(Stream_IO_Error &e)
    {
      return -16;
    }
    catch(PKCS8_Exception &e)
    {
      return -17;
    }
    catch(Decoding_Error &e)
    {
      //unknown algorithm
      return -18;
    }

    try
    {
      senderServerKey = PKCS8::load_key(senderServerKey_, rng);
    }
    catch(Stream_IO_Error &e)
    {
      return -19;
    }
    catch(PKCS8_Exception &e)
    {
      return -20;
    }
    catch(Decoding_Error &e)
    {
      //unknown algorithm
      return -21;
    }

    //no error otherwise
    return 0;
  }

  /**
   * @brief return a pointer to the Sender's certificate for TLS.
   *
   * @return senderServerCert.
   */
  Botan::X509_Certificate const *AuthKeys::getSenderCert() const
  {
    return senderServerCert;
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
   * @brief return a pointer to the Server's private key for TLS.
   *
   * @return senderServerKey, the private half of getServerCert().
   */
  Botan::Private_Key *AuthKeys::getSenderPrivKey() const
  {
    return senderServerKey;
  }
}
