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
   * @tparam M the type of messages stored
   *
   * @var std::list<M> MessageStore::stagedIn
   * @brief stored messages, in memory, staged in from disk
   */
  template <class M>
  class MessageStore
  {
    public:
      int init();
      int append(M msg);

      typename std::list<M>::iterator begin();
      typename std::list<M>::iterator end();

    private:
      std::list<M> stagedIn;
  };

  /**
   * @class MessageQueue
   * @brief stores Messages in memory and persistently.
   *
   * This has two key datastructures: a realtime message structure and old
   * message structure. Realtime messages are those sent recently from Senders,
   * old messages are loaded from disk and, presumably, weren't delivered since
   * the last crash.
   *
   * @tparam M the type of messages stored, used for parameters to addMessage()
   * @tparam Q realtime message structure type, e.g. std::vector
   *
   * @var Q MessageQueue::realTime
   * @brief realtime message structure that holds messages receiver from a
   *   Sender in the current session.
   *
   * @var std::mutex MessageQueue::realTimeLock
   * @brief lock to realTime structure for adding/removing messages.
   *
   * @var std::condition_variable MessageQueue::messageReady
   * @brief condition variable corresponding to realTimeLock. Use this to
   *   signal when a new realtime message is available.
   */
  template <class M, class Q>
  class MessageQueue
  {
    public:
      MessageQueue();
      ~MessageQueue();

      int init();
      int addMessage(M msg);
      size_t realTimeSize() const noexcept;
      M &next();

      std::mutex realTimeLock;
      std::condition_variable messageReady;

    private:
      Q realTime;
      MessageStore<M> backendStore;
  };
}

#endif //PERSISTENT_STORE_H
