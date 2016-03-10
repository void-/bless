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
      OpaqueEphemeralKey();
      int deserialize(std::string const &file);
      int deserialize(unsigned char const *const data_, std::size_t len);

      unsigned char *getKey() const;
      unsigned char *getSig() const;

      static const std::size_t keySize = 32;
      static const std::size_t sigSize = 64;
      static const constexpr std::size_t len = keySize + sigSize;
      std::array<unsigned char, len> data;

    private:
      std::size_t filled;
  };

  /**
   * @class EphemeralKey
   * @brief signed public diffie hellman key.
   */
  class EphemeralKey
  {
    public:
      EphemeralKey() = default;
      ~EphemeralKey();
      int init(OpaqueEphemeralKey const &serialized,
        Botan::Public_Key const &verify);
      int init(OpaqueEphemeralKey const &serializedPrivate);
      int init(Botan::Private_Key &sigKey, Botan::RandomNumberGenerator &rng);

      int serialize(OpaqueEphemeralKey &out) const;

      size_t serialize(unsigned char *out) const;

      static const std::string emsa;

      /**
       * An Ephemeral key is either just a public key or a public+private key
       * pair.
       *
       * Private key is already a subclass of public, so there's no use in
       * having both public and private fields coexist; just polymorph.
       *
       * Only if an EphemeralKey was generated in the application should priv
       * ever be used. If the key was deserialized, then only pub should be
       * used.
       */
      std::unique_ptr<Botan::Curve25519_PublicKey> key;

      std::array<unsigned char, 64> sig;
  };

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

    static const std::size_t len = 512;
    std::array<unsigned char, len> data;
    std::size_t filled = 0;
  };

  /**
   * @class Message
   * @brief represents an encrypted message between the Sender and Receiver.
   *
   * Format:
   *   senderId == hash of sender's certificate
   *   keyId == hash of Receiver ephemeral key used
   *   Sender's ephemeral key (signed)
   *   data encrypted under secret derived from Sender, Receiver keys
   *
   * @var size_t Message::filled
   * @brief number of bytes filled in when deserializing.
   */
  class Message
  {
    public:
      Message() = default;
      ~Message();

      int init(std::istream &in, Botan::Private_Key &sigKey,
        Botan::X509_Certificate const &senderCert,
        Botan::RandomNumberGenerator &rng);

      int serialize(OpaqueMessage &out) const;
      int deserialize(OpaqueMessage const &in);

      int encrypt(EphemeralKey &receiverKey);

      std::array<unsigned char, 32> senderId;
      std::array<unsigned char, 32> keyId;
      EphemeralKey senderKey;
      std::array<unsigned char, 12> nonce;
      static const size_t dataSize = 324;
      static const size_t tagSize = 16;
      Botan::secure_vector<Botan::byte> data;

      static_assert(
        (sizeof(senderId) +
         sizeof(keyId) +
         OpaqueEphemeralKey::len +
         sizeof(nonce) +
         dataSize +
         tagSize) == OpaqueMessage::len,
        "Not enough space to serialize Message into OpaqueMessage.");

      static const unsigned char salt[];
  };
}

#endif //MESSAGE_H
