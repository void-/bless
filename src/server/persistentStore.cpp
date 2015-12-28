#include "persistentStore.h"

#include <sys/types.h> //for opendir
#include <dirent.h>

using namespace Botan;

namespace Bless
{
  /**
   * @brief destruct a KeyStore.
   */
  KeyStore::~KeyStore()
  {
  }

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
   * Load in every certificate from \p path_ into stagedIn.
   *
   * This implementation only works on Unix-like platforms to open \p path_.
   *
   * Failure occurs if:
   * - \p path_ cannot be opened
   * - a certificate loaded is invalid
   * - memory cannot be allocated for the certificate
   *
   * @param path_ the directory path to load certificates from.
   * @return non-zero on failure.
   */
  int FileSystemStore::init(std::string &path_)
  {
    int error = 0;
    ::dirent *entry;
    ::DIR *dir = ::opendir(path_.c_str());

    //set member variable
    path = path_;

    if(dir == nullptr)
    {
      //couldn't open directory
      error = -1;
      goto fail;
    }

    //try to load every directory as a certificate
    while((entry = readdir(dir)) != nullptr)
    {
      try
      {
        stagedIn.emplace_back(std::string(entry->d_name));
        auto cert = stagedIn.back();

        //verify cert is self-signed and valid
        if(!(cert.is_self_signed() &&
            cert.check_signature(*cert.subject_public_key())))
        {
          error = -2;
          goto fail;
        }
      }
      catch(Decoding_Error &e)
      {
        //do nothing - probably not a cert
      }
      catch(Stream_IO_Error &e)
      {
        //do nothing - probably not a cert
      }
      catch(std::bad_alloc &e)
      {
        error = -3;
        goto fail;
      }
    }

fail:
    //close the directory ignoring errors
    closedir(dir);
    return error;
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
    bool valid = false;

    //check if any staged in certificate is valid
    for(auto &c : stagedIn)
    {
      valid |= (cert == c);
    }

    //if the cert is valid, return 0
    return valid ? 0 : -1;
  }

  /**
   * @brief destruct a MessageStore.
   */
  MessageStore::~MessageStore()
  {
  }

  const std::string FileMessageStore::defaultFilePath = "./messages";

  /**
   * @brief destruct a FileMessageStore and close the underlying file
   */
  FileMessageStore::~FileMessageStore()
  {
    backend.close(); //ignore any error
  }

  /**
   * @brief initialize a message store given a path to a backing file.
   *
   * @param file path to a file to use
   * @return non-zero on failure
   */
  int FileMessageStore::init(std::string const &file)
  {
    backend.open(file, std::ios_base::in | std::ios_base::app);

    offset = 0;

    return !backend;
  }

  /**
   * @brief initialize a message store using the default storage file.
   *
   * @return non-zero on failure.
   */
  int FileMessageStore::init()
  {
    return init(defaultFilePath);
  }

  /**
   * @brief add and commit a message to the file.
   * <p>
   * - Course-grain lock the entire function
   * - Serialize \p msg into a buffer
   * - seek to the end of the underlying file
   * - write out the buffer
   * - flush to commit the data
   * </p>
   *
   * @param msg borrowed message to write out to the file.
   * @return non-zero on failure.
   */
  int FileMessageStore::append(Message &msg)
  {
    std::lock_guard<decltype(backendLock)> lock(backendLock);
    unsigned char buf[Message::size];

    if(msg.serialize(buf, sizeof(buf)))
    {
      return -1;
    }

    //seek, write, flush; saving the returned stream
    backend.seekp(0, std::ios_base::end)
      .write(reinterpret_cast<char *>(buf), Message::size)
      .flush();

    //return 1 if the stream errored
    return !backend;
  }

  /**
   * @brief yield the next Message from the file.
   *
   * @return a Message, transfering ownership to the caller.
   */
  std::unique_ptr<Message> FileMessageStore::next()
  {

  }

  /**
   * @brief determine if any Messages are left in the file for next().
   *
   * Example use:\n
   * @code
   * FileMessageStore store;
   * ...
   *
   * while(!store.end())
   * {
   *   auto m = store.next();
   *   //do something with Message m
   * }
   * @endcode
   *
   * @return true if no more Messages remain.
   */
  bool FileMessageStore::end()
  {

  }

  /**
   * @brief destruct a MessageQueue and all its owned resources.
   *
   * All Messages in the underlying queue are owned, so delete them.
   */
  MessageQueue::~MessageQueue()
  {
    while(realTimeMessages.size())
    {
      auto i = realTimeMessages.front();
      realTimeMessages.pop();
      delete i;
    }
  }

  /**
   * @brief destruct the MessageQueue.
   */
  InMemoryMessageQueue::~InMemoryMessageQueue()
  {
    while(realTimeMessages.size())
    {
      auto i = realTimeMessages.front();
      realTimeMessages.pop();
      delete i;
    }
  }

  /**
   * @brief initialize the memory queue.
   *
   * This actually does nothing, but makes the interface consistent with other
   * MessageQueue implementations.
   */
  int InMemoryMessageQueue::init()
  {
    return 0;
  }

  /**
   * @brief add \p msg to the realtime queue, taking ownership.
   *
   * This signals messageReady.
   *
   * @bug this has a race condition; the lock is not acquired.
   *
   * @param msg the message to enqueue and take ownership of.
   * @return non-zero on failure.
   */
  int InMemoryMessageQueue::addMessage(std::unique_ptr<Message> &&msg)
  {
    realTimeMessages.emplace(msg.release());
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
  std::unique_ptr<Message> InMemoryMessageQueue::next()
  {
    //no realtime messages left, return a dummy
    if(!realTimeSize())
    {
      return std::unique_ptr<Message>(new Message());
    }
    auto ret = realTimeMessages.front();
    realTimeMessages.pop();
    return std::unique_ptr<Message>(ret);
  }

  /**
   * @brief destruct the MessageQueue and all owned messages.
   */
  FileMessageQueue::~FileMessageQueue()
  {
    while(realTimeMessages.size())
    {
      auto i = realTimeMessages.front();
      realTimeMessages.pop();
      delete i;
    }
  }

  /**
   * @brief initialize a message queue given a path to a backing file.
   *
   * This just calls FileMessageStore::init().
   *
   * @param file path to a file to use
   * @return non-zero on failure
   */
  int FileMessageQueue::init(std::string const &file)
  {
    return store.init(file);
  }

  /**
   * @brief initialize a message queue using the default file.
   *
   * @return non-zero on failure.
   */
  int  FileMessageQueue::init()
  {
    return store.init();
  }


  /**
   * @brief add \p msg to the realtime queue, taking ownership.
   *
   * Procedure:
   * <p>
   * - take ownership of \p msg
   * - put it on the realtime queue
   * - add the new message to the message store
   * - signal messageReady
   * </p>
   *
   * @param msg the message to enqueue and take ownership of.
   * @return non-zero on failure.
   */
  int FileMessageQueue::addMessage(std::unique_ptr<Message> &&msg)
  {
    std::lock_guard<decltype(realTimeLock)> lock(realTimeLock);
    realTimeMessages.emplace(msg.release());
    Message &m = *realTimeMessages.back(); //get a reference to the new message

    //store the message and signal
    store.append(m);
    MessageQueue::messageReady.notify_one();

    return 0;
  }

  /**
   * @brief return the number of realtime messages left.
   *
   * @return the number of messages in realTimeMessages.
   */
  size_t FileMessageQueue::realTimeSize() const noexcept
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
  std::unique_ptr<Message> FileMessageQueue::next()
  {
    //return a realtime message if available
    if(realTimeSize())
    {
      auto ret = realTimeMessages.front();
      realTimeMessages.pop();
      return std::unique_ptr<Message>(ret);
    }

    //read an old message from the store if any are left
    if(!store.end())
    {
      return store.next();
    }

    //no messages left at all; return a dummy
    return std::unique_ptr<Message>(new Message());
  }
}
