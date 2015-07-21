#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "auth.h"

int tcpBootstrap(char const *host, unsigned short port,
  struct serverAuthKeys const *, struct sessionKeys *);

int udpBootstrap(char const *host, unsigned short port,
  struct sessionKeys const *, int *socket);

int listenLoop(int socket, struct sessionKeys const *, struct messageKeys *);

namespace Bless
{

  /**
   * @brief holds connection information about the message channel.
   *
   * This is the secure message channel from the Server to the Receiver
   * implemented as a DTLS connection.
   *
   * Packets will arrive when a message is sent from the Sender; these are
   * unacked.
   *
   * When the Receiver shuts down, the DTLS connection will uncleanly be
   * shutdown, i.e. no finalizing packets will be sent by the Receiver.
   */
  class Channel
  {
    public:
      Channel();

    protected:
  };

}
#endif //CONNECTIONS_H
