#ifndef MESSAGE_H
#define MESSAGE_H

#include <botan/pk_keys.h>
#include <botan/x509cert.h>
#include <botan/curve25519.h>

#include <cstdint> //for size_t
#include <array>
#include <istream>

namespace Bless
{
  /**
   * @class OpaqueEphemeralKey
   * @brief EphemeralKey in serialized form
   */
  class OpaqueEphemeralKey
  {
    public:
      OpaqueEphemeralKey() = default;
      int deserialize(std::string const &file);
      int deserialize(unsigned char const *const data, std::size_t len);

      unsigned char *getKey() const;
      unsigned char *getSig() const;

      static const std::size_t keySize = 32;
      static const std::size_t sigSize = 32;
      std::array<unsigned char, keySize+sigSize> data;
  };

  /**
   * @class EphemeralKey
   * @brief signed public diffie hellman key.
   */
  class EphemeralKey
  {
    public:
      EphemeralKey() = default;
      int init(OpaqueEphemeralKey const &serialized,
        Botan::Public_Key const &verify);

      static const std::string emsa;

      std::unique_ptr<Botan::Curve25519_PublicKey> key;
      std::array<unsigned char, 32> sig;
  };
  const std::string EphemeralKey::emsa = "EMSA3(SHA-256)";

  /**
   * @class OpaqueMessage
   * @brief encrypted Message that travels over the wire.
   *
   * To turn a sequence of bytes into a full OpaqueMessage, use deserialize().
   * This will indiciate when the message is fully deserialized and no more
   * bytes are needed off the wire.
   *
   * Example
   * @code
   * OpaqueMessage m;
   * unsigned char buffer[64];
   * size_t len;
   * int socket;
   * ...
   * do
   * {
   *   len = read(socket, buffer, sizeof(buffer));
   * } while(m.deserialize(buffer, len));
   * ... //m is complete
   * send(socket, m.data.data(), m.data.size(), 0);
   * @endcode
   */
  struct OpaqueMessage
  {
    int deserialize(unsigned char const *const data_, std::size_t len);

    static const std::size_t size = 512;
    std::array<unsigned char, size> data;
    std::size_t filled = 0;
  };

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
