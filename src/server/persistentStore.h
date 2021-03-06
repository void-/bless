/**
 * @file
 * @brief interface between the Server and persistent storage.
 *
 * This is for Sender public key retrieval and durably storing messages.
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
  struct hash<Bless::OpaqueEphemeralKey const *const>
  {
    size_t operator()(Bless::OpaqueEphemeralKey const *const p) const
    {
      return reinterpret_cast<size_t>(p);
    }
  };
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
   * @brief interface to storing ephemeral keys to give to the Sender.
   *
   * Threadsafe interface to get persistently stored ephemeral keys for
   * Senders.
   */
  class EphemeralKeyStore
  {
    public:
      virtual ~EphemeralKeyStore() = default;

      /**
       * @brief atomically get the next ephemeral key to give to a Sender.
       *
       * @return the next key.
       */
      virtual OpaqueEphemeralKey *next() = 0;

      /**
       * @brief permenantly delete a key because a Sender used it for
       *   encryption.
       *
       * @param key the key, returned from next(), to delete.
       * @return non-zero on failure.
       */
      virtual int free(OpaqueEphemeralKey *key) = 0;

      /**
       * @brief reuse a key yielded from next() because a Sender did not
       *   successfully use it for encryption.
       *
       * @param key the key to reclaim to give out to another Sender.
       * @return non-zero on failure.
       */
      virtual int release(OpaqueEphemeralKey *key) = 0;
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

      OpaqueEphemeralKey *next() override;
      int free(OpaqueEphemeralKey *key) override;
      int release(OpaqueEphemeralKey *key) override;

    private:
      std::mutex keysLock;
      std::queue<OpaqueEphemeralKey *> keys;
      std::unordered_map<OpaqueEphemeralKey const *const, std::string> fileMap;
      std::size_t outstandingKeys;
  };

  /**
   * @class MessageStore
   * @brief interface to disk for durably stored Messages.
   *
   * Derive from this class to interface to an actual storage device, i.e.
   * disk, main memory, nvram, etc.
   *
   * This interface can be used by a MessageQueue to facilitate storing
   * persistent messages.
   */
  class MessageStore
  {
    public:
      virtual ~MessageStore();

      /**
       * @brief add a new OpaqueMessage to the persistent store.
       *
       * @param msg OpaqueMessage to add. Ownership is still held by the
       *   caller.
       * @return non-zero on failure.
       */
      virtual int append(OpaqueMessage &msg) = 0;

      /**
       * @brief yield the next OpaqueMessage from persistent store.
       *
       * The backend persistent store contains stored Messages. next() returns
       * Messages until all from the persistent store have been returned. The
       * intention is to resend Messages from before a crash.
       *
       * This transfers ownership to the caller.
       * Use end() to determine if next() still has Messages left to yeild.
       *
       * @warning only one thread should be calling this at any time.
       * @return the next OpaqueMessage, unspecified behaviour on failure.
       */
      virtual std::unique_ptr<OpaqueMessage> next() = 0;

      /**
       * @brief determine if any messages remain in the persistent store.
       *
       * @return true if calling next() won't return a valid OpaqueMessage.
       */
      virtual bool end() = 0;
  };

  /**
   * @class FileMessageStore
   * @brief implementation of MessageStore backed by a single file.
   *
   * @var std::fstream FileMessageStore::backend
   * @brief underlying file to read and write to
   *
   * @var std::mutex FileMessageStore::backendLock
   * @brief lock to synchronize using backend from append() and next()
   *
   * @var std::size_t FileMessageStore::offset
   * @brief current seek position in backend used by next()
   */
  class FileMessageStore : public MessageStore
  {
    public:
      ~FileMessageStore();

      int init(std::string const &file);
      int init();

      int append(OpaqueMessage &msg) override;
      std::unique_ptr<OpaqueMessage> next() override;
      bool end() override;

    protected:
      static const std::string defaultFilePath;

      std::fstream backend;
      std::mutex backendLock;
      std::size_t offset;
  };

  /**
   * @class MessageQueue
   * @brief interface to store Messages in memory and persistently.
   *
   * Store messages with addMessage() which can commit them to persistent
   * storage, depending on the implementation.
   *
   * next() will yields messages from addMessage(). If none are available, a
   * dummy message is returned.
   *
   * Implementors should be thread safe.
   *
   * @var std::mutex MessageQueue::realTimeLock
   * @brief lock to messageReady.
   *
   * @var std::condition_variable MessageQueue::messageReady
   * @brief condition variable corresponding to realTimeLock. This is used to
   *   signal when a new realtime message is available via next().
   */
  class MessageQueue
  {
    public:
      virtual ~MessageQueue();

      /**
       * @brief synchronously write a message to the queue and take ownership.
       *
       * When addMessage() returns, \p msg should be commited and available
       * via next().
       *
       * @param msg the message to write; addMessage() takes ownership.
       * @return non-zero on failure.
       */
      virtual int addMessage(std::unique_ptr<OpaqueMessage> &&msg) = 0;

      /**
       * @brief return the size of the underlying queue.
       *
       * This can be used to know how many times next() must be called to
       * exhaust all realtime messages.
       *
       * @return the message queue size.
       */
      size_t realTimeSize() const noexcept;

      /**
       * @brief return the next message from the message queue.
       *
       * This synchronously gets the next OpaqueMessage off the realtime queue.
       * If no OpaqueMessage is available, next() will block until either
       * condition is met:\n
       * - addMessage() returns on another thread
       * - \p timeout elapses, in which case, a dummy OpaqueMessage is returned
       *
       * This gives ownership of the message to the caller via unique_ptr.
       *
       * @param timeout maximum number of milliseconds to block during next().
       * @return the next message in the queue, giving ownership to the caller.
       */
      virtual std::unique_ptr<OpaqueMessage> next(unsigned timeout) = 0;

    protected:
      std::mutex realTimeLock;
      std::condition_variable messageReady;

      std::queue<OpaqueMessage *> realTimeMessages;
  };

  /**
   * @class InMemoryMessageQueue
   * @brief implementation of MessageQueue that only stores message in memory
   */
  class InMemoryMessageQueue : public MessageQueue
  {
    public:
      ~InMemoryMessageQueue() override;

      int init();

      int addMessage(std::unique_ptr<OpaqueMessage> &&msg) override;
      std::unique_ptr<OpaqueMessage> next(unsigned timeout) override;
  };

  /**
   * @class FileMessageQueue
   * @brief implementation of MessageQueue that stores messages to a file.
   */
  class FileMessageQueue : public MessageQueue
  {
    public:
      ~FileMessageQueue() override;

      int init(std::string const &file);
      int init();

      int addMessage(std::unique_ptr<OpaqueMessage> &&msg) override;
      std::unique_ptr<OpaqueMessage> next(unsigned timeout) override;

    private:
      FileMessageStore store;
  };
}

#endif //PERSISTENT_STORE_H
