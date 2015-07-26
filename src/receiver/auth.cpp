#include "auth.h"

#include <botan/data_src.h>
#include <botan/x509_key.h>
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
   *
   * Only deallocate a key if its not null.
   */
  AuthKeys::~AuthKeys()
  {
    if(serverKey)
    {
      delete serverKey;
    }

    if(receiverKey)
    {
      delete receiverKey;
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
   * @param server filename for Server's X509 encoded Public_Key.
   * @param receiver filename to deserialize the Receiver's PKCS8 key from.
   * @param rng random number generator for loading the private key.
   * @return 0 on success, non-zero on failure.
   */
  int AuthKeys::init(std::string const &server, std::string const &receiver,
      RandomNumberGenerator& rng)
  {

    //deserialize the public key
    try
    {
      serverKey = X509::load_key(server);
    }
    catch(Decoding_Error &e)
    {
      return -1;
    }

    //deserialize the private key
    try
    {
      receiverKey = PKCS8::load_key(receiver, rng);
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

    //no error otherwise
    return 0;
  }
}
