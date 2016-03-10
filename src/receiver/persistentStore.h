/**
 * @file
 * @brief interface between the Receiver and persistent storage.
 *
 * Load ephemeral keys and verify Sender certificates.
 */

#ifndef PERSISTENT_STORE_H
#define PERSISTENT_STORE_H

#include <bless/message.h>

#include <botan/x509cert.h>

#include <memory>
#include <condition_variable>
#include <list>
#include <queue>
#include <unordered_map>
#include <fstream>

namespace std
{
  template <>
  struct hash<decltype(Message::keyId)>
  {
    /**
     * @brief hash by the first 8 bytes of key id
     */
    size_t operator()(decltype(Message::keyId) const& key) const
    {
      return *(reinterpret_cast<size_t *>(key.data()));
    }
  }

  template <>
  struct hash<EphemeralKey *>
  {
    /**
     * @brief use raw pointer as hash
     */
    size_t operator()(EphemeralKey * key) const
    {
      return reinterpret_cast<size_t>(key);
    }
  }
}

namespace Bless
{
  /**
   * @class KeyStore
   * @brief abstract interface to disk for Sender certificates.
   *
   * The PKI for Bless is designed primarily as in-person exchange. When making
   * a tls connection, for any valid cert that the Sender sends us, the Server
   * should have it.
   *
   * This means that we only need to verify a cert was indeed exchanged
   * in-person. Hence, the only interface for KeyStore is testing whether a
   * given cert is both valid and in the KeyStore.
   *
   * We don't have to worry about providing an interface to use loaded certs.
   */
  class KeyStore
  {
    public:
      virtual ~KeyStore();
      virtual int isValid(Botan::X509_Certificate const &cert) = 0;
  };

  /**
   * @class FileSystemStore
   * @brief implementation of KeyStore that uses the filesystem as a storage
   *   backend.
   *
   * Thise is a more primitive, yet persistent, storage mechanism for Reciever
   * Certs.
   *
   * The premise is that this is initialized with a directory path. Each file
   * is a serialized X509_Certificate. The filenames are not meaningful, but
   * could be used for quick lookup.
   *
   * @var std::string FileSystemStore::path
   * @brief the path to the directory containing serialized keys.
   *
   * @var std::list<Botan::X509_Certificate> FileSystemStore::stagedIn
   * @brief all the keys staged into memory from file in FileSystemStore::path.
   */
  class FileSystemStore : public KeyStore
  {
    public:
      FileSystemStore() = default;
      ~FileSystemStore();

      int init(std::string &path_);
      int isValid(Botan::X509_Certificate const &cert) override;

    private:
      std::string path;
      std::list<Botan::X509_Certificate> stagedIn;
  };

  /**
   * @class EphemeralKeyStore
   * @brief interface to loading private ephemeral keys.
   *
   * Not thread safe
   */
  class EphemeralKeyStore
  {
    public:
      virtual ~EphemeralKeyStore() = default;

      /**
       * @brief get the private ephemeral key half for the given public half
       *
       * @param public ephemeral key id Sender encrypted under
       * @return private ephemeral key.
       */
      virtual EphemeralKey *getKey(
        decltype(Message::keyId) const &id) = 0;

      /**
       * @brief permenantly delete a private key because it was successfully
       *   used for decryption.
       *
       * @param key the private key, returned from getKey(), to delete.
       * @return non-zero on failure.
       */
      virtual int free(EphemeralKey *key) = 0;

      /**
       * @brief reuse a key yielded from getKey() because decryption was
       *   unsuccessful.
       *
       * The Sender could have incorectly encrypted or the Server could be
       * malicious. Its safer to delete \p key (the Server must have handed it
       * out), but in case further investigation is needed, call release().
       *
       * @param key the private key, returned from getKey(), to reuse.
       * @return non-zero on failure.
       */
      virtual int release(EphemeralKey *key) = 0;
  };

  /**
   * @class FileSystemEphemeralKeyStore
   * @brief implementation of EphemeralKeyStore that uses the filesystem as a
   *   storage backend.
   */
  class FileSystemEphemeralStore : public EphemeralKeyStore
  {
    public:
      FileSystemEphemeralStore() = default;
      ~FileSystemEphemeralStore() override;

      int init(std::string const &path);

      std::unique_ptr<EphemeralKey> getKey(
        decltype(Message::keyId) const &id) override;

      int free(EphemeralKey *key) override;
      int release(EphemeralKey *key) override;

    private:
      std::unordered_map<decltype(Message::keyId), EphemeralKey *> idToPriv;
      std::unordered_map<EphemeralKey *, std::string> keyToFile;

      std::size_t outstandingKeys = 0;
  };
}

#endif //PERSISTENT_STORE_H
