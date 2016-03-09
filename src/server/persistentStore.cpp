#include "persistentStore.h"

#include <bless/log.h>

#include <sys/types.h> //for opendir
#include <cstdio> //for remove
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
   * @brief delete the ephemeral key store.
   */
  FileSystemEphemeralStore::~FileSystemEphemeralStore()
  {
    std::lock_guard<std::mutex> lock(keysLock);
    Log &log = Log::getLog();

    //check if all keys have been returned
    if(outstandingKeys != 0)
    {
      log.log("FileSystemEphemeralStore outstanding keys != 0: ",
        outstandingKeys);
    }
  }

  /**
   * @brief load ephemeral keys as individual files from the filesystem given a
   *   directory path.
   *
   * @param path the directory path to load from.
   * @return non-zero on failure
   */
  int FileSystemEphemeralStore::init(std::string const &path)
  {
    int error = 0;
    ::dirent *entry;
    Log &log = Log::getLog();
    ::DIR *dir = ::opendir(path.c_str());
    outstandingKeys = 0;

    if(dir == nullptr)
    {
      //couldn't open directory
      error = -1;
      goto fail;
    }

    //load every file as an ephemeral key
    while((entry = readdir(dir)) != nullptr)
    {
      //unique_ptr ensures k is never leaked; release when passing to queue/map
      std::unique_ptr<OpaqueEphemeralKey> k(new OpaqueEphemeralKey());
      std::string name(entry->d_name);
      OpaqueEphemeralKey *rawK;

      //deserialization failed, try the next file
      if(k->deserialize(name))
      {
        log.log("Failed to load ephemeral key file ", name);
        continue;
      }

      //add key and filename to store
      rawK = k.release();
      keys.push(rawK);
      fileMap.insert(std::pair<OpaqueEphemeralKey const *const, std::string>(
        rawK, name));
    }

    //no keys were loaded
    if(!keys.size())
    {
      error = -2;
      goto fail;
    }

fail:
    //close the directory ignoring errors
    ::closedir(dir);
    return error;
  }

  /**
   * @brief return the next ephemeral key from the backend.
   *
   * If the key was used by a Sender, call free() on the returned pointer.
   * If there was an error with the connection to the Sender, i.e. the key was
   * not used, call release() on the returned pointer so it may be reused.
   *
   * @invariant cursor is always pointing to the next key to return.
   *
   * @return an ephemeral key, ownership is not transfered, nullptr if no keys
   *   are left.
   */
  OpaqueEphemeralKey *FileSystemEphemeralStore::next()
  {
    std::lock_guard<std::mutex> lock(keysLock);

    //if no more keys are left, return null
    if(keys.size() == 0)
    {
      return nullptr;
    }

    //get the front key off the queue
    auto k = keys.front();
    keys.pop();
    outstandingKeys++;

    return k;
  }

  /**
   * @brief delete an ephemeral key returned by next().
   *
   * This removes it from both the keys list and deletes the file.
   *
   * Don't lock because the keys list is not accessed.
   *
   * @param key the key to delete forever.
   * @return non-zero on failure.
   */
  int FileSystemEphemeralStore::free(OpaqueEphemeralKey *key)
  {
    if(outstandingKeys == 0)
    {
      //free() called before next()
      return -2;
    }

    //lookup the key in the map
    auto it = fileMap.find(key);
    if(it == fileMap.end())
    {
      //key not found
      return -1;
    }

    //delete the underlying file
    int ret = std::remove(it->second.c_str());
    if(ret)
    {
      //failed to delete file
      return -3;
    }

    //clear the map and deallocate the key itself
    fileMap.erase(it);
    delete key;
    outstandingKeys--;

    return 0;
  }

  /**
   * @brief mark a key returned by next() as unused.
   *
   * Lock because the list is modified.
   *
   * Simply reinsert the given key into the queue, first performing safety
   * checks.
   *
   * @param key the key to reuse
   * @return non-zero on failure.
   */
  int FileSystemEphemeralStore::release(OpaqueEphemeralKey *key)
  {
    std::lock_guard<std::mutex> lock(keysLock);
    if(outstandingKeys == 0)
    {
      //release() called before next()
      return -2;
    }

    //lookup the key in the map
    auto it = fileMap.find(key);
    if(it == fileMap.end())
    {
      //key not found
      return -1;
    }

    keys.push(key);
    outstandingKeys--;

    return 0;
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
  int FileMessageStore::append(OpaqueMessage &msg)
  {
    std::lock_guard<decltype(backendLock)> lock(backendLock);

    //seek, write, flush; saving the returned stream
    backend.seekp(0, std::ios_base::end)
      .write(reinterpret_cast<char *>(msg.data.data()), OpaqueMessage::len)
      .flush();

    //return 1 if the stream errored
    return !backend;
  }

  /**
   * @brief yield the next OpaqueMessage from the file.
   *
   * @return a OpaqueMessage, transfering ownership to the caller.
   */
  std::unique_ptr<OpaqueMessage> FileMessageStore::next()
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
   *   //do something with OpaqueMessage m
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
   * @brief default interface implementation to get a message off the queue.
   *
   * Synchronously removes the front item from the queue, blocking for at most
   * \p timeout milliseconds.
   *
   * @param timeout maximum number of milliseconds to block during next().
   * @return the next message in the queue, giving ownership to the caller.
   */
  std::unique_ptr<OpaqueMessage> MessageQueue::next(unsigned timeout)
  {
    std::unique_lock<decltype(realTimeLock)> lock(realTimeLock);
    std::chrono::milliseconds t(timeout);

    //if queue is empty, wait
    if(!realTimeSize())
    {
      messageReady.wait_for(lock, t);
    }

    //no messages before the timeout: return a dummy
    if(!realTimeSize())
    {
      return std::unique_ptr<OpaqueMessage>(new OpaqueMessage());
    }

    //a message is available, remove it from the queue
    auto ret = realTimeMessages.front();
    realTimeMessages.pop();
    return std::unique_ptr<OpaqueMessage>(ret);
  }

  /**
   * @brief destruct the MessageQueue.
   */
  InMemoryMessageQueue::~InMemoryMessageQueue()
  {
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
  int InMemoryMessageQueue::addMessage(std::unique_ptr<OpaqueMessage> &&msg)
  {
    std::lock_guard<decltype(realTimeLock)> lock(realTimeLock);
    realTimeMessages.emplace(msg.release());
    MessageQueue::messageReady.notify_one();

    return 0;
  }

  /**
   * @brief return the number of realtime messages left.
   *
   * @return the number of messages in realTimeMessages.
   */
  size_t MessageQueue::realTimeSize() const noexcept
  {
    return realTimeMessages.size();
  }

  /**
   * @brief return the next realtime message.
   *
   * This just calls the default MessageQueue implementation.
   *
   * @param timeout maximum number of milliseconds to wait for a realtime
   *   message.
   * @return the next message or a dummy message, giving ownership to the
   *   caller.
   */
  std::unique_ptr<OpaqueMessage> InMemoryMessageQueue::next(unsigned timeout)
  {
    return MessageQueue::next(timeout);
  }

  /**
   * @brief destruct the MessageQueue and all owned messages.
   */
  FileMessageQueue::~FileMessageQueue()
  {
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
  int FileMessageQueue::addMessage(std::unique_ptr<OpaqueMessage> &&msg)
  {
    std::lock_guard<decltype(realTimeLock)> lock(realTimeLock);
    realTimeMessages.emplace(msg.release());
    OpaqueMessage &m = *realTimeMessages.back(); //get a ref to the new message

    //store the message and signal
    store.append(m);
    MessageQueue::messageReady.notify_one();

    return 0;
  }

  /**
   * @brief return the next realtime message.
   *
   * This just calls the default MessageQueue implementation.
   *
   * @param timeout maximum number of milliseconds to wait for a realtime
   *   message.
   * @return the next message or a dummy message, giving ownership to the
   *   caller.
   */
  std::unique_ptr<OpaqueMessage> FileMessageQueue::next(unsigned timeout)
  {
      return MessageQueue::next(timeout);
  }
}
