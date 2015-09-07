/**
 * @file
 * @brief interface between the Server and persistent storage.
 *
 * This is for Sender public key retrieval and durably storing messages.
 */

#ifndef PERSISTENT_STORE_H
#define PERSISTENT_STORE_H

#include <condition_variable>
#include <list>

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
   * @brief stores Messages in memory and persistently.
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

      int init();
      int addMessage(M msg);
      size_t realTimeSize() const noexcept;
      M &next();

      std::mutex realTimeLock;
      std::condition_variable messageReady;
  };
}

#endif //PERSISTENT_STORE_H
