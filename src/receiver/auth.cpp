#include "auth.h"

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
   * If this function fails to serialize the inputs, the object still is not
   * valid.
   *
   * @param server stream to serialize the Server's Public_Key from.
   * @param receiver stream to serialize the Receiver's Private_Key from.
   * @return 0 on success, non-zero on failure.
   */
  int AuthKeys::init(std::istream &server, std::istream &receiver)
  {

  }
}
