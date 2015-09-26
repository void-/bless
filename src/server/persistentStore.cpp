#include "persistentStore.h"

namespace Bless
{
  /**
   * @brief destruct a FileSystemStore and all its owned resources.
   */
  FileSystemStore::~FileSystemStore()
  {
  }

  /**
   * @brief initialize a FileSystemStore given the path to a directory.
   *
   * The directory as \p path needs to be opened and the certificates loaded
   * into the stagedIn list.
   *
   * @param path the directory path to load certificates from.
   * @return non-zero on failure.
   */
  int FileSystemStore::init(std::string &path)
  {
  }

  /**
   * @brief given a candidate cert from the Sender, determine if its valid.
   *
   * To determine validity, there are two key things to check:
   * - Whether the certificate is in the KeyStore backend
   * - The certificate is valid
   * - - The self-signature is valid
   * - - The time stamp hasn't passed
   * - - etc.
   *
   * @param cert the certificate from the Sender to verify.
   * @return 0 if \p cert is valid, an error code otherwise.
   */
  int FileSystemStore::isValid(Botan::X509_Certificate const &cert)
  {
  }

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
