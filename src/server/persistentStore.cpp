#include "persistentStore.h"

namespace Bless
{
  /**
   * @brief destruct a MessageQueue and all its owned resources.
   */
  MessageQueue::~MessageQueue()
  {
  }

  /**
   * @brief destruct the MessageQueue.
   *
   * Nothing to do because nothing is dynamically allocated.
   */
  InMemoryMessageQueue::~InMemoryMessageQueue()
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
  int InMemoryMessageQueue::addMessage(Message msg)
  {
    realTimeMessages.emplace(msg);
    MessageQueue::messageReady.notify_one();

    return 0;
  }

  /**
   * @brief return the number of realtime messages left.
   *
   * @return the number of messages in realTimeMessages.
   */
  size_t InMemoryMessageQueue::realTimeSize() const noexcept
  {
    return realTimeMessages.size();
  }

  /**
   * @brief return the next realtime message.
   *
   * If the underlying queue of messages is empty, a new, dummy message is
   * returned by calling the Message constructor.
   *
   * @return the next message or a dummy message, giving ownership to the
   *   caller.
   */
  Message InMemoryMessageQueue::next()
  {
    //no realtime messages left, return a dummy
    if(!realTimeSize())
    {
      return Message();
    }
    Message ret = realTimeMessages.front();
    realTimeMessages.pop();
    return std::move(ret);
  }
}
