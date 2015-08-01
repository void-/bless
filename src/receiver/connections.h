/**
 * @file
 * @brief manage network connections between the Receiver and the Server.
 */

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "auth.h"

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
   * @var Channel::recvCallback
   * @brief callback when an authenticated message comes in.
   *
   * @var AuthKeys *Channel::authKeys
   * @brief keys used to authenticate the DTLS message channel.
   *
   * @var int Channel::connection
   * @brief socket descriptor for the connection to the Server.
   */
  class Channel
  {
    public:
      typedef std::function<int (unsigned char const * const, std::size_t)>
        recvCallback;

      Channel();
      ~Channel();

      int init(AuthKeys *keys, const std::string &server,
        unsigned short port);
      int connect(Botan::RandomNumberGenerator &rng, recvCallback cb);

    protected:
      Botan::TLS::Client *client;
      Botan::TLS::Policy *policy;
      Botan::TLS::Session_Manager *sessionManager;
      Botan::Credentials_Manager *credentialsManager;
      Botan::TLS::Server_Information *serverInformation;
      void send(const Botan::byte *const payload, size_t len);
      void recv(const Botan::byte *const payload, size_t len);
      void alert(Botan::TLS::Alert alert, const Botan::byte *const payload,
        size_t len);
      bool handshake(const Botan::TLS::Session &session);

      static const size_t bufferSize = 4096;
    private:
      AuthKeys *authKeys;
      int connection;
      sockaddr_in connectionInfo;
  };
}
#endif //CONNECTIONS_H
