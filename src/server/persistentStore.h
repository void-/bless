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
#include <fstream>

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

      /**
       * @brief add a new Message to the persistent store.
       *
       * @param msg Message to add. Ownership is still held by the caller.
       * @return non-zero on failure.
       */
      virtual int append(Message &msg) = 0;

      /**
       * @brief yield the next Message from persistent store.
       *
       * The backend persistent store contains stored Messages. next() returns
       * Messages until all from the persistent store have been returned. The
       * intention is to resend Messages from before a crash.
       *
       * This transfers ownership to the caller.
       * Use end() to determine if next() still has Messages left to yeild.
       *
       * @warning only one thread should be calling this at any time.
       * @return the next Message, unspecified behaviour on failure.
       */
      virtual std::unique_ptr<Message> next() = 0;

      /**
       * @brief determine if any messages remain in the persistent store.
       *
       * @return true if calling next() won't return a valid Message.
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
      int init(std::string const &file);
      int init();

      int append(Message &msg) override;
      std::unique_ptr<Message> next() override;
      bool end() override;

    protected:
      static const std::string defaultFilePath;

      std::fstream backend;
      std::mutex backendLock;
      std::size_t offset;
  };

  /**
   * @class MessageQueue
   * @brief stores realtime and persistent Messages.
   *
   * MessageQueue will iterate over messages using next(). Messages are of two
   * types:<p>
   * - realtime (added with addMessage())
   * - old (staged in from disk)
   * </p>
   *
   * next() will yield all real time messages until it runs out. It then yields
   * all messages from disk and when those run out, finally a dummy message.
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
       * @brief write a message to disk and take ownership.
       *
       * When addMessage() returns, \p msg has been written to disk and \p msg
       * will be available via next().
       *
       * realTimeLock will be acquired and messageReady will be signaled.
       *
       * @param msg the message to write; addMessage() takes ownership.
       * @return non-zero on failure.
       */
      virtual int addMessage(std::unique_ptr<Message> &&msg) = 0;

      /**
       * @brief return the number of realtime messages available via next().
       *
       * This can be used to know how many times next() must be called to
       * exhaust all realtime messages.
       *
       * This is the condition for messageReady.
       *
       * @return the size of the structure holding realtime messages.
       */
      virtual size_t realTimeSize() const noexcept = 0;

      /**
       * @brief return the next message from the message queue.
       *
       * All realtime messages added via addMessage() will be returned before
       * any old messages from disk. When all messages of both types are
       * returned, a dummy message will be returned instead.
       *
       * This gives ownership of the message to the caller.
       *
       * @return the next message in the queue, giving ownership to the caller.
       */
      virtual std::unique_ptr<Message> next() = 0;

      std::mutex realTimeLock;
      std::condition_variable messageReady;
  };

  /**
   * @class InMemoryMessageQueue
   * @brief implementation of MessageQueue that only stores message in memory
   */
  class InMemoryMessageQueue : public MessageQueue
  {
    public:
      ~InMemoryMessageQueue() override;

      int addMessage(std::unique_ptr<Message> &&msg) override;
      size_t realTimeSize() const noexcept override;
      std::unique_ptr<Message> next() override;

    private:
      std::queue<Message *> realTimeMessages;
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

      int addMessage(std::unique_ptr<Message> &&msg) override;
      size_t realTimeSize() const noexcept override;
      std::unique_ptr<Message> next() override;

    private:
      std::queue<Message *> realTimeMessages;
      FileMessageStore store;
  };
}

#endif //PERSISTENT_STORE_H
