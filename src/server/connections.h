/**
 * @file
 * @brief track the connections between the Server and Sender and Receiver and
 *   Server.
 */

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "persistentStore.h"
#include "authKeys.h"

#include <sys/types.h>
#include <sys/unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <array>

#include <botan/tls_server.h>
#include <botan/tls_session_manager.h>
#include <botan/credentials_manager.h>

namespace Bless
{
  /**
   * @class Runnable
   * @brief interface for a concurrent context.
   *
   * Subclass and override run() to do something on a separate thread. Call
   * start() to begin execution.
   *
   * This allows for dividing initialization and execution.
   */
  class Runnable
  {
    public:
      Runnable(const Runnable &) = delete;
      virtual ~Runnable();

      int start();
      void join();

    protected:
      Runnable() = default;
      virtual void run() = 0;

      std::thread t;
  };

  /**
   * @class Channel
   * @brief abstract, secure channel between two parties in the protocol.
   *
   * The Server always acts as a server; it never needs to store client
   * information aside from the client's expected certificate.
   *
   * @var int Channel::connection
   * @brief socket descriptor for the connection.
   *
   * @var Botan::TLS::Server Channel::server
   * @brief TLS connection to another party.
   *
   * @var Botan::TLS::Session_Manager Channel::sessionManager
   * @brief Used by server for managing sessions (which aren't used).
   *
   * @var Botan::Credentials_Manager Channel::credentialsManager
   * @brief Used by server as an interface to serverKey and the expected
   * certificate of the client.
   *
   * @var Botan::TLS::Policy Channel::policy
   * @brief Used by server for connection parameters.
   *
   * @var Botan::RandomNumberGenerator Channel::rng
   * @brief Random number generator used to make a connection.
   *
   * @var MessageQueue Channel::messageQueue
   * @brief message queue to communicate messages from Sender to Receiver.
   */
  class Channel
  {
    public:
      Channel(const Channel &) = delete;
      virtual ~Channel();
      int init(int socket, ServerKey *serverKey_, MessageQueue *messageQueue_,
        Botan::RandomNumberGenerator *rng_);

    protected:
      Channel();

      Botan::TLS::Server *server;
      Botan::TLS::Session_Manager *sessionManager;
      Botan::Credentials_Manager *credentialsManager;
      Botan::TLS::Policy *policy;
      Botan::RandomNumberGenerator *rng;

      int connection;
      ServerKey *serverKey;
      MessageQueue *messageQueue;
  };

  /**
   * @class MainConnection
   * @brief abstract class for handling all connections to either Sender or
   *   Receiver.
   *
   * This exists to avoid repeated code for ReceiverMain and SenderMain.
   *
   * @var int MainConnection::listen
   * @brief socket to listen for connections on.
   *
   * @var MessageQueue *MainConnection::queue
   * @brief shared message queue used to communicate Sender-sent Messages to
   *   the Receiver.
   *
   * @var ServerKey *MainConnection::serverKey
   * @brief certificate and private key used by the Server to connect to the
   *   client(either Sender or Receiver).
   */
  class MainConnection
  {
    public:
      virtual ~MainConnection();
      int init(MessageQueue *queue_, ServerKey *serverKey_,
        Botan::RandomNumberGenerator *rng_);

    protected:
      MainConnection() = default;

      int listen;
      MessageQueue *queue;
      ServerKey *serverKey;
      Botan::RandomNumberGenerator *rng;
  };

  /**
   * @class ReceiverChannel
   * @brief store state for the message channel between the Server and Receiver
   *
   * This represents a connection to the Receiver regardless of whether the
   * message channel is stale or not. When a new address of the Receiver is
   * known, this can be updated, by init(), with the new information.
   *
   * There should only be one instance of ReceiverChannel. It should be
   * allocated on a controlling thread.
   *
   * @var ConnectionKey *ReceiverChannel::receiverKey
   * @brief ConnectionKey containing the expected certificate for the Receiver.
   *
   * @var std::mutex ReceiverChannel::serverLock
   * @brief lock to update Channel::server during connect().
   *
   * @var size_t ReceiverChannel::bufferSize
   * @brief size, in bytes, of the buffer to use for the DTLS connection.
   *
   * @var unsigned RecieverChannel::timeout
   * @brief length, in milliseconds, to wait between sending a message.
   */
  class ReceiverChannel : public Channel, public Runnable
  {
    public:
      ReceiverChannel();
      ~ReceiverChannel();
      int init(int &socket, ConnectionKey *receiverKey_, ServerKey *serverKey_,
        MessageQueue *messageQueue_, Botan::RandomNumberGenerator *rng);
      int connect(sockaddr_in addr);

    protected:
      void send(sockaddr_in dest, const Botan::byte *const payload,
        size_t len);

      void alert(Botan::TLS::Alert alert, const Botan::byte *const payload,
        size_t len);
      void recvData(const Botan::byte *const payload, size_t len);
      bool handshake(const Botan::TLS::Session &session);
      std::string nextProtocol(std::vector<std::string> protocols);

      void sendMessage(Message &m);

      void run() override;
      ConnectionKey *receiverKey;
      std::mutex serverLock;

      static const size_t bufferSize = 4096;
      static const unsigned timeout = 30*1000;
  };

  /**
   * @class ReceiverMain
   * @brief main class for handling a changing connection to the Receiver.
   *
   * @var unsigned short ReceiverMain::port
   * @brief udp port to listen for connections from the Receiver.
   *
   * @var ConnectionKey *ReceiverMain::receiverKey;
   * @brief contains the public key of the Receiver.
   *
   * @var bool ReceiverMain::channelRunning;
   * @brief indicates whether chan is running.
   *
   * @var ReceiverChannel ReceiverMain::chan;
   * @brief the message channel to the Receiver as its own thread.
   *
   * @var Botan::RandomNumberGenerator *ReceiverMain::rng;
   * @brief random number generator needed by chan.
   */
  class ReceiverMain : public MainConnection, public Runnable
  {
    public:
      ReceiverMain() = default;
      ~ReceiverMain();

      int init(MessageQueue *queue_, ServerKey *serverKey_,
        ConnectionKey *receiverKey_, Botan::RandomNumberGenerator *rng_);
      void run() override;

      static const unsigned short port = 9549;

    private:
      ConnectionKey *receiverKey;
      bool channelRunning;
      ReceiverChannel chan;
  };

  /**
   * @struct ChannelWork
   * @brief a single work item for a SenderChannel thread to process.
   *
   * @var int ChannelWork::conn
   * @brief socket connected to a Sender
   *
   * @var sockaddr_in ChannelWork::sender
   * @brief the address of the Sender
   */
  struct ChannelWork
  {
    ChannelWork(int &conn_, sockaddr_in &sender_) :
        conn(conn_), sender(sender_)
    {
    }

    int conn;
    sockaddr_in sender;
  };

  /**
   * @class SenderChannel
   * @brief store state for the connection to a Sender; this should run on its
   *   own thread.
   *
   * This keeps the state per instance of a connection to the Sender. The
   * lifecycle of this object should be the same as the connection itself.
   *
   * The use idea is:
   * - A new connection is available
   * - Allocate a SenderChannel
   * - init() the SenderChannel with a socket
   * - call start() to handle the connection on a separate thread
   * - The SenderChannel will complete the connection and deallocate itself
   *
   * @var size_t SenderChannel::bufferSize
   * @brief size, in bytes, of the buffer to use for the TLS connection.
   */
  class SenderChannel : public Channel, public Runnable
  {
    public:
      SenderChannel() = default;
      ~SenderChannel();

      int init(ServerKey *serverKey_, MessageQueue *messageQueue_,
        KeyStore *store_, std::mutex *workLock_,
        std::condition_variable *workReady_, std::queue<ChannelWork> *work_,
        Botan::RandomNumberGenerator *rng_);

    protected:
      void run() override;

      void send(const Botan::byte *const payload, size_t len);

      void alert(Botan::TLS::Alert alert, const Botan::byte *const payload,
        size_t len);
      void recvData(const Botan::byte *const payload, size_t len);
      bool handshake(const Botan::TLS::Session &session);
      std::string nextProtocol(std::vector<std::string> protocols);

      static const size_t bufferSize = 4096;
      static const size_t timeout = 4000;

    private:
      KeyStore *store;
      std::mutex *workLock;
      std::condition_variable *workReady;
      std::queue<ChannelWork> *work;
      Message partialMessage;
  };

  /**
   * @class SenderMain
   * @brief main class for handling connections to the Sender.
   *
   * This should run on its own thread and will create many threads to handle
   * individual connections.
   *
   * @var unsigned short SenderMain::port
   * @brief tcp port used to listen for connections from Senders.
   *
   * @var int SenderMain::backlog
   * @brief number of waiting connections when listening for Senders.
   *
   * @var unsigned int SenderMain::maxThreads
   * @brief the maximum number of threads to have allocated at once.
   *
   * @var std::array<SenderChannel, maxThreads> SenderMain::channels
   * @brief fixed array of SenderChannels to handle connections.
   */
  class SenderMain : public Runnable, public MainConnection
  {
    public:
      SenderMain() = default;
      ~SenderMain();
      int init(MessageQueue *queue_, ServerKey *serverKey_,
        KeyStore *store_, Botan::RandomNumberGenerator *rng_);

      static const unsigned short port = 9548;

    protected:
      void run() override;
      static const int backlog = 32;
      static const unsigned int maxThreads = 2;

    private:
      KeyStore *store;

      std::array<SenderChannel, maxThreads> channels;
      std::mutex workLock;
      std::condition_variable workReady;
      std::queue<ChannelWork> connections;
  };
}

#endif //CONNECTIONS_H
