#ifndef MESSAGE_H
#define MESSAGE_H

#include <cstdint> //for size_t
#include <array>
#include <istream>

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
      ~Message();
      Message(std::string const &data);
      Message(std::istream &in);

      int serialize(unsigned char *const out, std::size_t len) const;
      int deserialize(unsigned char const *const data, std::size_t len);

      static const std::size_t size = 512;
      std::array<unsigned char, size> data;

    protected:
      std::size_t filled;
  };
}

#endif //MESSAGE_H
