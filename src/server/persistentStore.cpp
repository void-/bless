#include "persistentStore.h"

namespace Bless
{
  /**
   * @brief destruct the MessageQueue.
   *
   * Nothing to do because nothing is dynamically allocated.
   */
  template <class M>
  InMemoryMessageQueue<M>::~InMemoryMessageQueue()
  {
  }

  /**
   * @brief add \p msg to the realtime queue, taking ownership.
   *
   * This signals messageReady.
   *
   * @param msg the message to enqueue and take ownership of.
   * @return non-zero on failure.
   */
  template <class M>
  int InMemoryMessageQueue<M>::addMessage(M msg)
  {
    realTimeMessages.emplace_back(msg);
    MessageQueue<M>::messageReady.notify_one();

    return 0;
  }

  /**
   * @brief return the number of realtime messages left.
   *
   * @return the number of messages in realTimeMessages.
   */
  template <class M>
  size_t InMemoryMessageQueue<M>::realTimeSize() const noexcept
  {
    return realTimeMessages.size();
  }

  /**
   * @brief return the next realtime message.
   *
   * If the underlying queue of messages is empty, a new, dummy message is
   * returned by calling the M constructor.
   *
   * @return the next message or a dummy message, giving ownership to the
   *   caller.
   */
  template <class M>
  M InMemoryMessageQueue<M>::next()
  {
    //no realtime messages left, return a dummy
    if(!realTimeSize())
    {
      return M();
    }
    M ret = realTimeMessages.front();
    realTimeMessages.pop();
    return std::move(ret);
  }
}
