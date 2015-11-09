#ifndef MESSAGE_H
#define MESSAGE_H

#include <cstdint> //for size_t
#include <array>

namespace Bless
{
  /**
   * @class Message
   * @brief represents an encrypted message between the Sender and Receiver.
   *
   * @var size_t Message::filled
   * @brief number of bytes filled in when deserializing.
   */
  class Message
  {
    public:
      Message();

      int deserialize(unsigned char const *const data, std::size_t len);

      std::array<unsigned char, 16> data;

    protected:
      std::size_t filled;
  };
}

#endif //MESSAGE_H
