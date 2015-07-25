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
   * This function takes std::istreams and constructs DataSources from them.
   * This allows error handling for creating the std::istream be determined by
   * the caller rather than this function.
   *
   * The keys must be signing keys.
   *
   * @param server stream to deserialize the Server's X509 encoded Public_Key.
   * @param receiver stream to deserialize the Receiver's Private_Key from.
   * @param rng random number generator for loading the private key.
   * @return 0 on success, non-zero on failure.
   */
  int AuthKeys::init(std::istream &server, std::istream &receiver,
      RandomNumberGenerator& rng)
  {
    DataSource_Stream pubSource(server);
    DataSource_Stream privSource(receiver);

    //deserialize the public key
    try
    {
      serverKey = X509::load_key(pubSource);
    }
    catch(Decoding_Error &e)
    {
      return -1;
    }

    //deserialize the private key
    try
    {
      receiverKey = PKCS8::load_key(privSource, rng);
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
