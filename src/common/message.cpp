#include <bless/message.h>

namespace Bless
{
  /**
   * @brief construct a default message.
   */
  Message::Message() : filled(0)
  {
    data[0] = 'H';
    data[1] = 'i';
    data[2] = '!';
    for(std::size_t i = 3; i < data.size(); ++i)
    {
      data[i] = '\0';
    }
  }

  /**
   * @brief construct an example message given a string
   */
  Message::Message(std::string const &data) : filled(0)
  {
    for(std::size_t i = 0; i < std::min(data.size(), this->data.size()); ++i)
    {
      this->data[i] = data[i];
    }

    //pad out the end
    for(std::size_t i = std::min(data.size(), this->data.size());
        i < this->data.size(); ++i)
    {
      this->data[i] = '\0';
    }
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
