#include <bless/message.h>

namespace Bless
{
  Message::Message() : filled(0)
  {
  }

  /**
   * @brief deserialize a Message with a fragment of data in \p data.
   *
   * @warning This is not thread safe.
   *
   * @param data next piece of data to deserialize.
   * @param len length, in bytes, of \p data.
   *
   * @return 0 when fully deserialized, -1 on error, posotive when
   *   incomplete.
   */
  int Message::deserialize(unsigned char const *const data, std::size_t len)
  {
    return 0;
  }
}
