/**
 * @file
 * @brief interface between the Server and persistent storage.
 *
 * This is for Sender public key retrieval and durably storing messages.
 */

#ifndef PERSISTENT_STORE_H
#define PERSISTENT_STORE_H

#include <condition_variable>
#include <queue>

namespace Bless
{
  /**
   * @class KeyStore
   * @brief interface to disk for Sender certificates.
   */
  class KeyStore
  {
  };

  /**
   * @class MessageStore
   * @brief interface to disk for durably stored Messages.
   *
   * Derive from this class to interface to an actual storage device.
   *
   * @tparam M the type of messages stored
   */
  template <class M>
  class MessageStore
  {
    public:
      virtual int append(M msg) = 0;

      virtual M &next() = 0;
      virtual bool end() = 0;
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
   * @tparam M the type of messages stored, used for parameter to addMessage()
   *
   * @var std::mutex MessageQueue::realTimeLock
   * @brief lock to messageReady.
   *
   * @var std::condition_variable MessageQueue::messageReady
   * @brief condition variable corresponding to realTimeLock. This is used to
   *   signal when a new realtime message is available via next().
   */
  template <class M>
  class MessageQueue
  {
    public:
      virtual ~MessageQueue() = 0;

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
      virtual int addMessage(M msg) = 0;

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
      virtual M next() = 0;

      std::mutex realTimeLock;
      std::condition_variable messageReady;
  };

  /**
   * @class InMemoryMessageQueue
   * @brief implementation of MessageQueue that only stores message in memory
   *
   * @tparam M the type of Message to store.
   */
  template <class M>
  class InMemoryMessageQueue : public MessageQueue<M>
  {
    public:
      ~InMemoryMessageQueue() override;

      int addMessage(M msg) override;
      size_t realTimeSize() const noexcept override;
      M next() override;

    private:
      std::queue<M> realTimeMessages;
  };
}

#endif //PERSISTENT_STORE_H
