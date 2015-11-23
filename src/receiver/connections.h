/**
 * @file
 * @brief manage network connections between the Receiver and the Server.
 */

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "auth.h"
#include <bless/message.h>

#include <functional>
#include <botan/tls_client.h>
#include <botan/tls_session_manager.h>
#include <botan/credentials_manager.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace Bless
{
  /**
   * @class Channel
   * @brief holds connection information about the message channel.
   *
   * This is the secure message channel from the Server to the Receiver
   * implemented as a DTLS connection.
   *
   * Packets will arrive when a message is sent from the Sender; these are
   * unacked. The Receiver never needs to send application data, so there is
   * no interface for that.
   *
   * When the Receiver shuts down, the DTLS connection will uncleanly be
   * shutdown, i.e. no finalizing packets will be sent by the Receiver.
   *
   * Call init(), connect(), then listen().
   *
   * Example:<p>
   * @code
   * Channel chan;
   * AuthKeys keys;
   * Botan::RandomNumberGenerator rng;
   * Channel::recvCallback cb = [](unsigned char const *const data, size_t n) {
   *   //do something with n bytes of data from Sender
   * }
   * //...initialize keys and rng
   *
   * chan.init(&keys, "127.0.0.1", 8675); //initialized message channel
   * chan.connect(rng, cb); //establish a connection to 127.0.0.1:8675 udp
   * chan.listen(); //block and listen for messages from the Server/Sender
   * @endcode
   *
   * @var Botan::TLS::Client *Channel::client
   * @brief TLS client that holds state about the connection to the Server
   *
   * @var Botan::TLS::Policy *Channel::policy
   * @brief the policy used when negotiating the DTLS connection
   *
   * @var Botan::TLS::Session_Manager *Channel::sessionManager
   * @brief nop session manager used to manage saved DTLS sessions; does
   *   nothing
   *
   * @var Botan::TLS::Credentials_Manager *Channel::credentialsManager
   * @brief store credentials for DTLS connection; interfaces AuthKeys for DTLS
   *
   * @var Botan::TLS::Server_Information *Channel::serverInformation
   * @brief information about the Server, of which there is none
   *
   * @var size_t Channel::bufferSize
   * @brief the size, in bytes, used for stack-allocated buffers. Ensure this
   * is larger than Message::data.size() by at least 24 bytes.
   *
   * @var int Channel::handshakeTimeout
   * @brief the number of milliseconds to timeout at when handshaking the DTLS
   *   connection
   *
   * @var int Channel::channelTimeout
   * @brief the maximum length of time, in milliseconds, to wait between
   *   channel messages before the message channel is considered stale
   *
   * @var Channel::recvCallback
   * @brief callback when an authenticated message comes in.
   *
   * @var AuthKeys *Channel::authKeys
   * @brief keys used to authenticate the DTLS message channel.
   *
   * @var int Channel::connection
   * @brief socket descriptor for the connection to the Server.
   *
   * @var sockaddr_in Channel::connectionInfo
   * @brief socket structure information about Channel::connection
   */
  class Channel
  {
    public:
      typedef std::function<int (unsigned char const *const, std::size_t)>
        recvCallback;

      Channel();
      ~Channel();

      int init(AuthKeys *keys, const std::string &server,
        unsigned short port);
      int connect(Botan::RandomNumberGenerator &rng, recvCallback cb);
      int listen();

    protected:
      Botan::TLS::Client *client;
      Botan::TLS::Policy *policy;
      Botan::TLS::Session_Manager *sessionManager;
      Botan::Credentials_Manager *credentialsManager;
      Botan::TLS::Server_Information *serverInformation;
      void send(const Botan::byte *const payload, size_t len);
      void alert(Botan::TLS::Alert alert, const Botan::byte *const payload,
        size_t len);
      bool handshake(const Botan::TLS::Session &session);

      static const size_t bufferSize = 16416;
      static_assert(bufferSize > (Message::size + 24u),
        "Buffer too small for Message size.");
      static const int handshakeTimeout = 1 * 1000;
      static const int channelTimeout = 120 * 1000;

    private:
      AuthKeys *authKeys;
      int connection;
      sockaddr_in connectionInfo;
  };
}
#endif //CONNECTIONS_H
