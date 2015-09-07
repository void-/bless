/**
 * @file
 * @brief track the connections between the Server and Sender and Receiver and
 *   Server.
 */

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "persistentStore.h"

#include <sys/types.h>
#include <sys/unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <botan/tls_server.h>

namespace Bless
{
  /**
   * @class Channel
   * @brief abstract, secure channel between two parties in the protocol.
   *
   * The Server always acts as a server; it never needs to store client
   * information.
   *
   * @var int Channel::connection
   * @brief socket descriptor for the connection.
   *
   * @var Botan::TLS::Server Channel::server
   * @brief TLS connection to another party.
   */
  class Channel
  {
    public:
      Channel() = delete;
      virtual ~Channel();
      int init(int socket, sockaddr_in sender);

    protected:
      int connection;
      Botan::TLS::Server *server;
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
   * allocated on a controlling thread, but run() should be called on a
   * separate thread; hence run() is not static.
   */
  class ReceiverChannel : Channel
  {
    public:
      ReceiverChannel();
      ~ReceiverChannel();
      int init(int socket, sockaddr_in receiver);

      void run();
  };

  /**
   * @class SenderChannel
   * @brief store state for the connection to a Sender; this should run on its
   *   own thread.
   *
   * This keeps the state per instance of a connection to the Sender. The
   * lifecycle of this object should be the same as the connection itself.
   *
   * @var sockaddr_in SenderChannel::senderAddress
   * @brief address of the Sender in this connection
   */
  class SenderChannel : Channel
  {
    public:
      SenderChannel();
      ~SenderChannel();

      int init(int socket, sockaddr_in sender);

      static void run(int socket, sockaddr_in receiver);
  };

  template <class M>
  void senderMain(MessageQueue<M> &queue);
}

#endif //CONNECTIONS_H
