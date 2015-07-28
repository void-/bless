/**
 * @file
 * @brief manage network connections between the Receiver and the Server.
 */

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "auth.h"

#include <functional>
#include <botan/tls_client.h>

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
   */
  class Channel
  {
    public:
      typedef std::function<int (unsigned char *, std::size_t)> recvCallback;

      Channel();
      ~Channel();

      int init(AuthKeys *keys, std::string server);
      int connect(Botan::RandomNumberGenerator &rng, recvCallback cb);

    protected:
      Botan::TLS::Client *client;
      //put callbacks here
    private:
      AuthKeys *authKeys;
      std::string serverAddress;
  };
}
#endif //CONNECTIONS_H
