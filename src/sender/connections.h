/**
 * @file
 * @brief manage network connections between the Sender and the Server.
 */

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "auth.h"

#include <botan/pubkey.h>
#include <botan/tls_client.h>
#include <botan/tls_session_manager.h>
#include <botan/credentials_manager.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bless/message.h>

namespace Bless
{
  /**
   * @class Channel
   * @brief connection to the Server.
   *
   * This is the secure channel from the Sender to the Server.
   *
   * Call init(), connect(), then sendMessage().
   *
   * @var Botan::TLS::Client *Channel::client
   * @brief TLS client that holds state about the connection to the Server
   *
   * @var Botan::TLS::Policy *Channel::policy
   * @brief the policy used when negotiating the TLS connection
   *
   * @var Botan::TLS::Session_Manager *Channel::sessionManager
   * @brief nop session manager used to manage saved TLS sessions; does
   *   nothing
   *
   * @var Botan::TLS::Credentials_Manager *Channel::credentialsManager
   * @brief store credentials for TLS connection; interfaces AuthKeys for TLS
   *
   * @var Botan::TLS::Server_Information *Channel::serverInformation
   * @brief information about the Server, of which there is none
   *
   * @var size_t Channel::bufferSize
   * @brief the size, in bytes, used for stack-allocated buffers
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
   * @brief keys used to authenticate the TLS channel.
   *
   * @var int Channel::connection
   * @brief socket descriptor for the connection to the Server.
   *
   * @var sockaddr_in Channel::connectionInfo
   * @brief socket structure information about Channel::connection
   *
   * @var Botan::RandomNumberGenerator Channel::rng
   * @brief random number generator used to connect and send messages.
   */
  class Channel
  {
    public:
      Channel();
      ~Channel();

      int init(AuthKeys *keys, const std::string &server,
        unsigned short port, Botan::RandomNumberGenerator *rng_);
      int connect();
      int recvKey(EphemeralKey &out, Botan::Public_Key const &verify);
      int sendMessage(Message const &message);

    protected:
      Botan::TLS::Client *client;
      Botan::TLS::Policy *policy;
      Botan::TLS::Session_Manager *sessionManager;
      Botan::Credentials_Manager *credentialsManager;
      Botan::TLS::Server_Information *serverInformation;
      void send(const Botan::byte *const payload, size_t len);
      void recvData(const Botan::byte *const payload, size_t len);
      void alert(Botan::TLS::Alert alert, const Botan::byte *const payload,
        size_t len);
      bool handshake(const Botan::TLS::Session &session);

      static const size_t bufferSize = 4096;
      static const int handshakeTimeout = 1 * 1000;
      static const int channelTimeout = 120 * 1000;

      OpaqueEphemeralKey tempKey;

    private:
      AuthKeys *authKeys;
      int connection;
      sockaddr_in connectionInfo;
      Botan::RandomNumberGenerator *rng;
  };
}
#endif //CONNECTIONS_H
