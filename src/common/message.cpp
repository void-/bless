#include <bless/message.h>

#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/hex.h>
#include <botan/sha2_32.h>
#include <botan/kdf2.h>
#include <botan/chacha20poly1305.h>

#include <fstream>

using namespace Botan;

namespace Bless
{
  const std::string EphemeralKey::emsa = "EMSA1(SHA-256)";
  const unsigned char Message::salt[] = {
    0x62, 0x6c, 0x65, 0x73, 0x73, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
    0x65};

  OpaqueEphemeralKey::OpaqueEphemeralKey() : filled(0)
  {
  }

  /**
   * @brief load a serialized EphemeralKey from a file
   *
   * @param file the file to open and load the key from
   * @return non-zero on failure
   */
  int OpaqueEphemeralKey::deserialize(std::string const &file)
  {
    std::ifstream f(file);

    //failed to open file
    if(!f)
    {
      return -1;
    }

    //load in the serialized key
    f.read((char *)(getKey()), keySize);

    //check if all the bytes were read
    if(static_cast<std::size_t>(f.gcount()) != keySize)
    {
      return -2;
    }

    //load in the serialized signature
    f.read((char *)(getSig()), sigSize);

    //check if all the bytes were read
    if(static_cast<std::size_t>(f.gcount()) != sigSize)
    {
      return -3;
    }

    //return 0 if all bytes were read
    return f.eof();
  }

  /**
   * @brief deserialize an ephemeral key with a fragment of data in \p data.
   *
   * @warning This is not thread safe.
   *
   * If \p len is longer than the remaining number of bytes needed to
   * deserialize the message, this is not an error.
   *
   * @param data next piece of data to deserialize.
   * @param len length, in bytes, of \p data.
   * @return 0 when fully deserialized, non-zero when incomplete.
   */
  int OpaqueEphemeralKey::deserialize(unsigned char const *const data_,
      std::size_t len)
  {
    //copy given payload into message
    for(std::size_t i = 0; (i < len) && ((filled) < data.size()); ++i)
    {
      data[filled] = data_[i];
      ++filled;
    }

    return filled < data.size();
  }

  /**
   * @brief get pointer to key in data blob.
   *
   * @return pointer to blob of size keySize.
   */
  unsigned char *OpaqueEphemeralKey::getKey() const
  {
    return const_cast<unsigned char *>(data.data());
  }

  /**
   * @brief get pointer to signature in data blob.
   *
   * @return pointer to blob of size sigSize.
   */
  unsigned char *OpaqueEphemeralKey::getSig() const
  {
    return const_cast<unsigned char *>(keySize + data.data());
  }

  /**
   * @brief destruct EphemeralKey, zeroing the signature
   */
  EphemeralKey::~EphemeralKey()
  {
    sig.fill(0);
  }

  /**
   * @brief deserialize an OpaqueEphemeralKey and verify its signature.
   *
   * @param serialized the key to deserialize into this.
   * @param verify public signing key presumably used to sign this key.
   * @return non-zero on failure
   */
  int EphemeralKey::init(OpaqueEphemeralKey const &serialized,
      Public_Key const &verify)
  {
    //construct a signature verifier from given public key
    PK_Verifier v(verify, emsa);

    //check the signature in the key
    if(!v.verify_message(serialized.getKey(), OpaqueEphemeralKey::keySize,
          serialized.getSig(), OpaqueEphemeralKey::sigSize))
    {
      return -1;
    }

    //convert std::array into secure_vector to construct key
    secure_vector<byte> keyBytes(OpaqueEphemeralKey::keySize);
    if(buffer_insert(keyBytes, 0, serialized.getKey(),
        OpaqueEphemeralKey::keySize) == 0)
    {
      return -2;
    }

    //buffer_insert failed
    if(keyBytes.size() != OpaqueEphemeralKey::keySize)
    {
      return -3;
    }

    key = std::unique_ptr<Curve25519_PublicKey>(
      new Curve25519_PublicKey(keyBytes));

    //copy in signature
    ::memcpy(sig.data(), serialized.getSig(), sig.size());

    return 0;
  }

  /**
   * @brief deserialize a private EphemeralKey from a file
   *
   * @param file filepath to load from
   * @param rng needed for verifying file
   * @return non-zero on failure
   */
  int EphemeralKey::deserialize(std::string const &file,
      RandomNumberGenerator &rng)
  {
    try
    {
      key.reset(dynamic_cast<Curve25519_PrivateKey *>(
        PKCS8::load_key(file, rng)));
    }
    catch(Stream_IO_Error &e)
    {
      return -2;
    }
    catch(PKCS8_Exception &e)
    {
      return -3;
    }
    catch(Decoding_Error &e)
    {
      return -5;
    }

    return 0;
  }

  /**
   * @brief generate and sign a new Ephemeral key pair
   *
   * @param sigKey key to sign with
   * @param rng random number generator for generation and signature
   * @return non-zero on failure
   */
  int EphemeralKey::init(Private_Key &sigKey, RandomNumberGenerator &rng)
  {
    //generate key pair
    key.reset(new Curve25519_PrivateKey(rng));

    //sign public half
    PK_Signer sign(sigKey, emsa);
    std::vector<byte> rawSig = sign.sign_message(key->public_value(), rng);

    if(rawSig.size() != sig.size())
    {
      //signature was unexpected length
      return -1;
    }

    //write rawSig out to sig member variable
    copy_mem(sig.data(), rawSig.data(), sig.size());

    return 0;
  }

  /**
   * @brief serialize an EphemeralKey directly to a buffer of length
   *   OpaqueEphemeralKey::len
   *
   * @param out buffer to write out, OpaqueEphemeralKey::len bytes long
   * @return number of bytes written
   */
  size_t EphemeralKey::serialize(unsigned char *out) const
  {
    std::vector<byte> keyBytes = key->public_value();

    copy_mem(out, keyBytes.data(), OpaqueEphemeralKey::keySize);
    copy_mem(&out[OpaqueEphemeralKey::keySize], sig.data(),
      OpaqueEphemeralKey::sigSize);

    return OpaqueEphemeralKey::len;
  }

  OpaqueMessage::OpaqueMessage()
  {
    data.fill(0);
  }

  /**
   * @brief deserialize a message with a fragment of data in \p data.
   *
   * @warning This is not thread safe.
   *
   * If \p len is longer than the remaining number of bytes needed to
   * deserialize the message, this is not an error.
   *
   * @param data next piece of data to deserialize.
   * @param len length, in bytes, of \p data.
   * @return 0 when fully deserialized, non-zero when incomplete.
   */
  int OpaqueMessage::deserialize(unsigned char const *const data_,
      std::size_t len)
  {
    //copy given payload into message
    for(std::size_t i = 0; (i < len) && ((filled) < data.size()); ++i)
    {
      data[filled] = data_[i];
      ++filled;
    }

    return filled < data.size();
  }

  /**
   * @brief destruct a Message, zeroing the data.
   */
  Message::~Message()
  {
    senderId.fill(0);
    keyId.fill(0);
    nonce.fill(0);
  }

  /**
   * @brief init and encrypt a message given a stream to read from.
   *
   * Procedure:
   * - hash sender's certificate
   * - generate and sign Sender ephemeral key pair
   * - generate encryption nonce
   * - read message data from \p in
   *
   * @param in stream to read data to encrypt from
   * @param sigKey private half to \p senderCert, use to sign an EphemeralKey
   * @param senderCert cert to hash and identify who signed \p receiverKey
   * @param rng random number generator needed for encryption
   * @return non-zero on failure
   */
  int Message::init(std::istream &in, Private_Key &sigKey,
      X509_Certificate const &senderCert, RandomNumberGenerator &rng)
  {
    //senderId = sha256 of Sender's certificate
    std::string certId = senderCert.fingerprint("SHA-256");

    //iterate through string and replace `:' with ` ' to satisfy hex_decode
    for(auto &c : certId)
    {
      if(c == ':')
      {
        c = ' ';
      }
    }

    if(hex_decode(senderId.data(), certId, true) != senderId.size())
    {
      //wrote out an unexpected number of bytes
      return -5;
    }

    //generate ephemeral key for the Sender
    if(int error = senderKey.init(sigKey, rng))
    {
      return error;
    }

    //fill nonce
    rng.randomize(nonce.data(), nonce.size());

    //allocate enough space for user data; tag space will be auto allocated
    data.resize(dataSize);
    //read bytes from the user
    in.read((char *)(data.data()), dataSize);
    return in.good();
  }

  /**
   * @brief serialize a Message into an OpaqueMessage.
   *
   * @param out reference parameter to output
   * @return non-zero on failure.
   */
  int Message::serialize(OpaqueMessage &out) const
  {
    //encrypt always grows data by tagSize bytes
    if(data.size() != (dataSize+tagSize))
    {
      //data grew too large
      return -1;
    }

    out.data.fill(0);
    //copy fields packed into output
    unsigned char *const o = out.data.data();

    ::memcpy(&o[out.filled], senderId.data(), senderId.size());
    out.filled += senderId.size();

    ::memcpy(&o[out.filled], keyId.data(), keyId.size());
    out.filled += keyId.size();

    if((out.data.size() - out.filled) < OpaqueEphemeralKey::len)
    {
      //ran out of space for ephemeral key somehow
      return -2;
    }
    //serialize EphemeralKey directly to char *
    out.filled += senderKey.serialize(&o[out.filled]);

    ::memcpy(&o[out.filled], nonce.data(), nonce.size());
    out.filled += nonce.size();

    //write message data and tag (both stored in `data')
    ::memcpy(&o[out.filled], data.data(), dataSize+tagSize);
    out.filled += data.size();

    return out.filled != out.data.size();
  }

  /**
   * @brief given the Receiver's ephemeral key, encrypt this Message in place
   *
   * @warning the signature on \p receiverKey is not verified in encrypt()
   *
   * @param receiverKey verified public Ephemeral key to encrypt under.
   * @return non-zero on failure.
   */
  int Message::encrypt(EphemeralKey &receiverKey)
  {
    //copy out keyId = Receiver's ephemeral public key
    std::vector<byte> receiverRawKey = receiverKey.key->public_value();

    if(receiverRawKey.size() != keyId.size())
    {
      //public key is wrong size
      return -1;
    }
    ::memcpy(keyId.data(), receiverRawKey.data(), keyId.size());

    //derive a shared secret
    secure_vector<byte> ss =
      dynamic_cast<Curve25519_PrivateKey *>(senderKey.key.get())->agree(
        receiverRawKey.data(),
        receiverRawKey.size());

    //run kdf, [ieee1363a-2004 kdf2(sha256)] on shared secret
    secure_vector<byte> rawKey(32);

    //NOTE: KDF2() puts a hash * into a unique_ptr (why?!?)
    KDF2 kdf(new SHA_256());

    if(kdf.kdf(rawKey.data(), rawKey.size(), ss.data(), ss.size(), salt,
        sizeof(salt)) != 32u)
    {
      //not enough bytes were generated
      return -2;
    }

    //use rawKey as a symmetric key and encrypt plaintext
    ChaCha20Poly1305_Encryption enc;
    enc.set_key(rawKey);
    enc.set_associated_data(keyId.data(), keyId.size()); //authenticate keyId
    enc.start(nonce.data(), nonce.size());

    //encrypt all at once
    enc.finish(data, 0);

    return 0;
  }

  /**
   * @brief deserialize an OpaqueMessage into a useable Message
   *
   * @param in serialized OpaqueMessage to deserialize
   * @return non-zero on failure
   */
  int Message::deserialize(OpaqueMessage const &in)
  {
    //unpack the fields
    ::memcpy(senderId.data(), in.data.data(), senderId.size());
    ::memcpy(data.data(), senderId.size() + in.data.data(), data.size());

    return 0;
  }
}
