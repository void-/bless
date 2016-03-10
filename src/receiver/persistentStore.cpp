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
        stagedIn.emplace_back(std::string(path_ + "/" + entry->d_name));
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
    //check if all keys have been returned
    if(outstandingKeys != 0)
    {
      //log.log("FileSystemEphemeralStore outstanding keys != 0: ",
      //  outstandingKeys);
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
    OpaqueEphemeralKey opaqueKey;

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
      std::unique_ptr<EphemeralKey> k(new EphemeralKey());
      std::string name(path + "/" + entry->d_name);
      EphemeralKey *rawK;

      //file -> opaque key
      if(opaqueKey.deserialize(name))
      {
        //deserialization failed, try the next file
        //log.log("Failed to load ephemeral key file ", name);
        continue;
      }

      //opaque key -> private ephemeral key
      if(k->init(opaqueKey))
      {
        //failed to initialize, ignore this key
        continue;
      }

      //get the `keyId' for k
      auto keyIdRaw = k->public_value();
      decltype(Message::keyId) keyId;
      if(keyIdRaw.size() != keyId.size())
      {
        //size mismatch; bad key?
        continue;
      }
      ::memcpy(keyId.data(), keyIdRaw.data(), keyId.size());

      //add key and id
      rawK = k.release();
      idToPriv.insert(std::pair<decltype(Message::keyId), EphemeralKey *>(
        keyId, rawK));

      //add key and underlying file
      keyToFile.insert(std::pair<EphemeralKey *, std::string>(rawK, name));
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
  EphemeralKey *FileSystemEphemeralStore::getKey(decltype(Message::keyId)
      const &id)
  {
    //if no more keys are left, return null
    if(idToPriv.size() == 0)
    {
      return nullptr;
    }

    //lookup corresponding private key by id
    auto it = idToPriv.find(id);
    if(it == idToPriv.end())
    {
      //key not found: already used?
      return -1;
    }

    //check key can be found in keyToFile
    auto itFile = keyToFile.find(it->second);
    if(itFile == keyToFile.end())
    {
      //key was deleted, but not removed from idToPriv
      return -2;
    }

    outstandingKeys++;

    return it->second;
  }

  /**
   * @brief delete an ephemeral key returned by next().
   *
   * This removes it from both the keys list and deletes the file.
   *
   * @param key the key to delete forever.
   * @return non-zero on failure.
   */
  int FileSystemEphemeralStore::free(EphemeralKey *key)
  {
    if(outstandingKeys == 0)
    {
      //free() called before next()
      return -2;
    }

    //lookup the key in the map
    auto it = keyToFile.find(key);
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
    keyToFile.erase(it);
    //XXX: this key isn't removed from idToPriv because we can't look it up
    delete key;
    outstandingKeys--;

    return 0;
  }

  /**
   * @brief mark a key returned by next() as unused.
   *
   * @param key the key to reuse
   * @return non-zero on failure.
   */
  int FileSystemEphemeralStore::release(OpaqueEphemeralKey *key)
  {
    if(outstandingKeys == 0)
    {
      //release() called before next()
      return -2;
    }

    //lookup the key in the map
    auto it = keyToFile.find(key);
    if(it == fileMap.end())
    {
      //key not found
      return -1;
    }

    outstandingKeys--;
    return 0;
  }
}
