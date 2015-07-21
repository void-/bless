/**
 * @file
 * @brief manage network connections between the Receiver and the Server.
 */

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "auth.h"

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
   * unacked.
   *
   * When the Receiver shuts down, the DTLS connection will uncleanly be
   * shutdown, i.e. no finalizing packets will be sent by the Receiver.
   *
   * @var AuthKeys Channel::authKeys
   * @brief keys used to authenticate the DTLS message channel.
   */
  class Channel
  {
    public:
      Channel();

    protected:
    private:
      AuthKeys authKeys;
  };

}
#endif //CONNECTIONS_H
