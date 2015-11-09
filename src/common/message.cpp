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
    //copy given payload into message
    for(std::size_t i = 0; (i < len) && ((filled) < this->data.size()); ++i)
    {
      this->data[filled] = data[i];
      ++filled;
    }

    return filled < this->data.size();
  }
}
