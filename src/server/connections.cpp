#include "connections.h"

namespace Bless
{
  /**
   * @brief start the underlying thread of the Runnable.
   *
   * @return non-zero if the thread fails to start.
   */
  int Runnable::start()
  {
    t = std::thread(&Runnable::run, this);
    return 0;
  }

  /**
   * @brief destruct a Channel and all its owned resources.
   */
  Channel::~Channel()
  {
  }

  /**
   * @brief base implementation for initializing a Channel.
   *
   * Use this in subclasses of channel to avoid repeated lines.
   *
   * @param socket the socket descriptor for the connection.
   * @param addr the address of the counterparty.
   * @param server ServerKey containing the Server's certificate and private
   *   key.
   * @return non-zero on failure.
   */
  int Channel::init(int socket, sockaddr_in addr, ServerKey *server)
  {
  }

  /**
   * @brief construct a ReceiverChannel.
   *
   * @warning this is invalid until init() is called.
   */
  ReceiverChannel::ReceiverChannel()
  {
  }

  /**
   * @brief deallocate a ReceiverChannel and all its owned resources.
   */
  ReceiverChannel::~ReceiverChannel()
  {
  }

  /**
   * @brief initialize a ReceiverChannel to the Receiver.
   *
   * init() can be called multiple times as new connections are initiated by
   * the Receiver.
   *
   * @param sock udp socket the Receiver has connected to.
   * @param receiver socket information about \p sock.
   * @param client ConectionKey containing the Receiver's certificate.
   * @return non-zero on failure.
   */
  int ReceiverChannel::init(int socket, sockaddr_in addr,
      ConnectionKey *receiver, ServerKey *server)
  {
    return 0;
  }

  /**
   * @brief preform the main logic of maintaining a connection to the Receiver.
   *
   * The socket used to connect to the Reciever may be updated via init() when
   * the Receiver moves.
   */
  void ReceiverChannel::run()
  {
  }

  /**
   * @brief construct a new Receiver Main Thread given a shared MessageQueue.
   *
   * The reason this construct take \p queue_ as a parameter is to emphasize
   * that this does not own the queue. It shares it and the queue's lifecycle
   * encompasses this.
   *
   * This will create its own thread via ReceiverMain::chan.
   *
   * @param queue_ the message queue to receive messages on from the Sender.
   */
  ReceiverMain::ReceiverMain(MessageQueue &queue_) : queue(queue_)
  {
  }

  /**
   * @brief destruct a Receiver Main Thread.
   *
   * This will close the connection to the Receiver.
   */
  ReceiverMain::~ReceiverMain()
  {
  }

  /**
   * @brief initialize a ReceiverMain.
   *
   * @return non-zero on failure.
   */
  int ReceiverMain::init()
  {
  }

  /**
   * @brief start listening for connections from the Receiver and block.
   *
   * Unlike SenderChannel::start() this function blocks so it can be run by the
   * main thread. Subclass Runnable and rename this function to run() if this
   * is not the desired behaviour.
   *
   * @return non-zero on failure.
   */
  int ReceiverMain::start()
  {
  }

  /**
   * @brief construct a SenderChannel.
   *
   * @warning this isn't valid until init() is called.
   */
  SenderChannel::SenderChannel()
  {
  }

  /**
   * @brief deallocate the SenderChannel, closing the connection.
   */
  SenderChannel::~SenderChannel()
  {
  }

  /**
   * @brief initialize a SenderChannel with an opened socket.
   *
   * \p sender is a useful parameter because it could be used to detect
   * attempted DoS attacks.
   *
   * @param sock opened socket for a tcp connection to a Sender.
   * @param sender socket information about \p sock.
   * @param server contains certificate of the Server, SenderChannel does not
   *   own this.
   * @return non-zero on failure.
   */
  int SenderChannel::init(int sock, sockaddr_in sender, ServerKey *server)
  {
    return 0;
  }

  /**
   * @brief perform the main logic of connecting to a Sender.
   */
  void SenderChannel::run()
  {
  }

  /**
   * @brief main function for handling connections to the Sender.
   *
   * This should run on its own thread and will create many threads to handle
   * individual connections.
   *
   * @param queue message queue to write Sender-sent messages to.
   */
  SenderMain::SenderMain(MessageQueue &queue_) : queue(queue_)
  {
  }

  /**
   * @brief deallocate the Sender main thread and kill any threads its created.
   */
  SenderMain::~SenderMain()
  {
  }

  /**
   * @brief perform the main logic of receiving connections from Senders.
   */
  void SenderMain::run()
  {
  }
}
