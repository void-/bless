/**
 * @file
 * @brief start the Server system.
 */

#include <bless/log.h>

#include "connections.h"
#include "authKeys.h"
#include "persistentStore.h"

#include <botan/auto_rng.h>

#include <iostream>
#include <csignal>
#include <condition_variable>

/**
 * Directory path to default resources.
 */
#ifndef RESOURCE_PATH
#define RESOURCE_PATH "./"
#endif //RESOURCE_PATH

using namespace Bless;

std::string defaultServerSenderKey = RESOURCE_PATH"server.pem";
std::string defaultServerSenderCert = RESOURCE_PATH"serverCert.pem";
std::string defaultServerReceiverKey = RESOURCE_PATH"server.pem";
std::string defaultServerReceiverCert = RESOURCE_PATH"serverCert.pem";
std::string defaultReceiverCert = RESOURCE_PATH"receiverCert.pem";
std::string defaultSenderCert = RESOURCE_PATH;

std::string logFile = RESOURCE_PATH"log";

std::mutex exitLock;
bool blessDone = false;
std::condition_variable mainExit;

/**
 * @brief run the bless Server.
 *
 * Currently, no arguments are parsed and only basic setup is done for the
 * Server.
 *
 * In the future, authentication keys should be loaded from alternative
 * resources if available via \p argv.
 *
 * main() will run until mainExit condition variable is signaled. This gives
 * the Sender and Receiver threads a chance to run.
 *
 * @param argc length of \p argv.
 * @param argv argument vector to run the server with non-default behaviour.
 * @return non-zero on failure.
 */
int main(int argc, char **argv)
{
  int error = 0;
  Botan::AutoSeeded_RNG rng;
  FileMessageQueue messages;
  ReceiverMain recv;
  SenderMain sender;
  ServerKey keyToSender;
  ServerKey keyToReceiver;
  ConnectionKey receiverKey;
  FileSystemStore store;
  std::unique_lock<std::mutex> waitLock;

  //initialize the log
  if((error = Log::init(logFile)))
  {
    std::cerr << "Failed to initialize log file: " << logFile << std::endl;
    goto fail;
  }

  //initialize shared message queue
  if((error = messages.init()))
  {
    std::cerr << "Failed to open message storage or init queue." << std::endl;
    goto fail;
  }

  //load Server keys
  if((error =
      (keyToSender.init(defaultServerSenderKey, defaultServerSenderCert,
        rng))))
  {
    std::cerr << "Failed to load Server public or private key to Sender." <<
      std::endl;
    goto fail;
  }

  if((error =
      (keyToReceiver.init(
        defaultServerReceiverKey, defaultServerReceiverCert, rng))))
  {
    std::cerr << "Failed to load Server public or private key to Receiver." <<
      std::endl;
    goto fail;
  }

  //load receiver certificate
  if((error = receiverKey.init(defaultReceiverCert)))
  {
    std::cerr << "Couldn't load Receiver certificate." << std::endl;
    goto fail;
  }

  //load Sender certificate store
  if((error = store.init(defaultSenderCert)))
  {
    std::cerr << "Couldn't load Sender certificate stores." << std::endl;
    goto fail;
  }

  //initialize main connection threads
  if((error = recv.init(&messages, &keyToReceiver, &receiverKey, &rng)))
  {
    std::cerr << "Failed to initialize Receiver main." << std::endl;
    goto fail;
  }

  //initialize thread for handling connections to Sender
  if((error = sender.init(&messages, &keyToSender, &store, &rng)))
  {
    std::cerr << "Failed to initialize Sender main." << std::endl;
    goto fail;
  }

  //start the sender main thread
  if((error = sender.start()))
  {
    std::cerr << "Failed to start Sender thread." << std::endl;
    goto fail;
  }

  //start and block on the receiver
  if((error = recv.start()))
  {
    std::cerr << "Failed to start Receiver." << std::endl;
    goto fail;
  }

  //register a signal handler to wakeup main to cleanly exit
  std::signal(SIGINT, [] (int) {
    std::lock_guard<std::mutex> lock(exitLock);
    blessDone = true;
    mainExit.notify_one();
  });

  //wait until its time to exit
  waitLock = std::unique_lock<std::mutex>(exitLock);
  while(!blessDone)
  {
    mainExit.wait(waitLock);
  }

  //workaround to terminate() blocking
  _exit(-1);

  sender.terminate();
  recv.terminate();

fail:
  return error;
}
