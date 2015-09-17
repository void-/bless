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
   * @brief base implementation for initializing a Channel.
   *
   * Use this in subclasses of channel to avoid repeated lines.
   *
   * @param socket the socket descriptor for the connection.
   * @param addr the address of the counterparty.
   * @return non-zero on failure.
   */
  int Channel::init(int socket, sockaddr_in addr)
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
   * @return non-zero on failure.
   */
  int ReceiverChannel::init(int socket, sockaddr_in receiver)
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
   * @tparam M the type of message \p queue should store.
   * @param queue_ the message queue to receive messages on from the Sender.
   */
  template <class M>
  ReceiverMain<M>::ReceiverMain(MessageQueue<M> &queue_) : queue(queue_)
  {
  }

  /**
   * @brief destruct a Receiver Main Thread.
   *
   * This will close the connection to the Receiver.
   *
   * @tparam M the type of message \p queue should store.
   */
  template <class M>
  ReceiverMain<M>::~ReceiverMain()
  {
  }

  /**
   * @brief initialize a ReceiverMain.
   *
   * @tparam M the type of message \p queue should store.
   * @return non-zero on failure.
   */
  template <class M>
  int ReceiverMain<M>::init()
  {
  }

  /**
   * @brief start listening for connections from the Receiver and block.
   *
   * Unlike SenderChannel::start() this function blocks so it can be run by the
   * main thread. Subclass Runnable and rename this function to run() if this
   * is not the desired behaviour.
   *
   * @tparam M the type of message \p queue should store.
   * @return non-zero on failure.
   */
  template <class M>
  int ReceiverMain<M>::start()
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
   * @return non-zero on failure.
   */
  int SenderChannel::init(int sock, sockaddr_in sender)
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
   * @tparam M the type of message \p queue should store.
   * @param queue message queue to write Sender-sent messages to.
   */
  template <class M>
  SenderMain<M>::SenderMain(MessageQueue<M> &queue_) : queue(queue_)
  {
  }

  /**
   * @brief deallocate the Sender main thread and kill any threads its created.
   */
  template <class M>
  SenderMain<M>::~SenderMain()
  {
  }

  /**
   * @brief perform the main logic of receiving connections from Senders.
   *
   * @tparam M the type of message \p queue should store.
   */
  template <class M>
  void SenderMain<M>::run()
  {
  }
}
