#include "connections.h"

namespace Bless
{
  /**
   * @brief initialize a ReceiverChannel to the Receiver.
   *
   * init() can be called multiple times as new connections are initiated by
   * the Receiver.
   *
   * @param sock udp socket the Receiver has connected to.
   * @param receiver socket information about \p sock.
   * @return non-zero on failure.
   */
  int ReceiverChannel::init(int socket, sockaddr_in receiver)
  {
    return 0;
  }

  /**
   * @brief initialize a SenderChannel with an opened socket.
   *
   * \p sender is a useful parameter because it could be used to detect
   * attempted DoS attacks.
   *
   * @param sock opened socket for a tcp connection to a Sender.
   * @param sender socket information about \p sock.
   * @return non-zero on failure.
   */
  int SenderChannel::init(int sock, sockaddr_in sender)
  {
    return 0;
  }

  /**
   * @brief main function for handling connections to the Sender.
   *
   * This should run on its own thread and will create many threads to handle
   * individual connections.
   *
   * @tparam M the type of message \p queue should store.
   * @param queue message queue to write Sender-sent messages to.
   */
  template <class M>
  void senderMain(MessageQueue<M> &queue)
  {
  }
}
