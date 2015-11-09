#include "persistentStore.h"

#include <sys/types.h> //for opendir
#include <dirent.h>

using namespace Botan;

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
