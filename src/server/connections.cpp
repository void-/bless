#include "connections.h"

using namespace Botan;

namespace Bless
{
  /**
   * @brief destruct a runnable.
   */
  Runnable::~Runnable()
  {
  }

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
    return 0;
  }

  /**
   * @brief destruct a MainConnection and all its owned resources.
   *
   * @warning do not delete queue or serverKey, they are shared.
   */
  MainConnection::~MainConnection()
  {
  }

  /**
   * @brief initialize a main connection thread.
   *
   * No ownership of the parameters is taken.
   *
   * @param queue_ shared message queue to read or write Sender-sent messages
   *   to.
   * @param serverKey_ contains certificate and private key for connections to
   *   either Senders or the Receiver.
   * @return non-zero on failure.
   */
  int MainConnection::init(MessageQueue *queue_, ServerKey *serverKey_)
  {
    queue = queue_;
    serverKey = serverKey_;

    return 0;
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
   * pseudocode
   * @code
   *   create and init a dtls server
   *   init a connection using \p socket
   *   the first packet should be client hello
   *   allocate a socket to write to the receiver
   *   if the connection succeeds, replace channel socket
   *   replace keys
   * @endcode
   *
   * \p socket will we read off of, but no reads will occur after init()
   * returns. The lifetime of \p socket just needs to exceed init().
   *
   * @param socket borrowed udp socket that dtls connection initialization
   *   packets are read from, but not written to.
   * @param receiver socket information about \p socket.
   * @param client ConectionKey containing the Receiver's certificate.
   * @return non-zero on failure.
   */
  int ReceiverChannel::init(int &socket, sockaddr_in addr,
      ConnectionKey *receiver, ServerKey *serverKey,
      RandomNumberGenerator &rng)
  {
    Botan::TLS::Server *tmpServer;
    int tmpSocket = -1;
    std::unique_lock<std::mutex> handshakeWait;
    sockaddr_in tmpAddr = addr;

    //allocate a socket to write to
    if((tmpSocket = ::socket(PF_INET, SOCK_DGRAM, 0) == -1))
    {
      goto fail;
    }

    //connect the socket to the candidate receiver
    if(::connect(socket, reinterpret_cast<const sockaddr *>(&tmpAddr),
        sizeof(tmpAddr)))
    {
      goto fail;
    }

    //XXX: initialize credentials manager; this should be a single instance

    /**
     * have the callback member function signal a condition variable.
     * Wait on that condition variable after creating the server
     * Check the condition - indicating whether the connection suceeded;
     *   i.e the new connection was indeed a new Receiver
     *
     * Need to setup the callbacks so they use the temporary socket
     * This is ok because the socket will be replaced eventually
     *
     * This shouldn't lock the ReceiverChannel thread to avoid Dos
     * The core issue is that this->send is being used for two connections
     *
     * This doesn't go async. No condvar needed. When is_active is true, the
     * connection is active
     *
     * A different idea: make a tls server in main thread and pass off to
     * receiver thread
     */
    //create a new connection using socket
    tmpServer = new Botan::TLS::Server(
      //we capture the temporary socket
      [tmpSocket](const byte *const data, size_t len) {
        ReceiverChannel::send(tmpSocket, data, len);
      },
      [this](const byte *const data, size_t len) {
        this->recvData(data, len);
      },
      [this](TLS::Alert alert, const byte *const payload, size_t len) {
        this->alert(alert, payload, len);
      },
      [this](const TLS::Session &session) {
        return this->handshake(session);
      },
      *sessionManager,
      *credentialsManager,
      *policy,
      rng,
      [this](std::vector<std::string> proto) {
        return this->nextProtocol(proto);
      },
      true,
      bufferSize);

    //start up the connection to the candidate Receiver
    while(!tmpServer->is_active())
    {
    }

    //if the connection succeeds, shutdown and replace the current connection
    //if the connection fails; don't modify anything
    connection = tmpSocket;
    //XXX: close down the old server
    server = tmpServer;
    return 0;

fail:

    //try to close the temporary socket
    if(tmpSocket != -1)
    {
      if(close(tmpSocket))
      {
        return -1;
      }
    }
    return -1;
  }

  /**
   * @brief send
   *
   * @param payload
   * @param len)
   */
  void ReceiverChannel::send(int sock, const byte *const payload, size_t len)
  {
  }

  /**
   * @brief
   *
   * @param alert
   * @param payload
   * @param len
   */
  void ReceiverChannel::alert(TLS::Alert alert, const byte *const payload,
      size_t len)
  {
  }

  /**
   * @brief
   *
   * @param payload
   * @param len
   */
  void ReceiverChannel::recvData(const byte *const payload, size_t len)
  {
  }

  /**
   * @brief
   *
   * @param session
   *
   * @return
   */
  bool ReceiverChannel::handshake(const TLS::Session &session)
  {
    return false;
  }

  /**
   * @brief
   *
   * @param protocols
   *
   * @return
   */
  std::string ReceiverChannel::nextProtocol(std::vector<std::string> protocols)
  {
    return "";
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
   * @brief destruct a Receiver Main Thread.
   *
   * This will close the connection to the Receiver.
   */
  ReceiverMain::~ReceiverMain()
  {
  }

  /**
   * @brief initialize the main thread for listen to Receiver connections.
   *
   * @see MainConnection::init()
   *
   * @param queue_ parameter to MainConnection::init.
   * @param serverKey_ parameter to MainConnection::init.
   * @param receiverKey_ contains the certificate of the Receiver.
   * @return non-zero on failure.
   */
  int ReceiverMain::init(MessageQueue *queue_, ServerKey *serverKey_,
      ConnectionKey *receiverKey_, RandomNumberGenerator *rng_)
  {
    ::sockaddr_in addr;

    //initialize a main connection like normal
    if(MainConnection::init(queue_, serverKey_))
    {
      return -1;
    }

    receiverKey = receiverKey_;
    rng = rng_;

    //allocate a socket
    if((listen = socket(PF_INET, SOCK_DGRAM, 0) == -1))
    {
      return -2;
    }

    //initialize bind parameters
    ::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ::htons(port);

    //bind to udp listen port
    if(bind(listen, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr))
        == -1)
    {
      close(listen); //ignore error
      return -3;
    }

    return 0;
  }

  /**
   * @brief start listening for connections from the Receiver.
   *
   * pseudocode
   * @code
   *   listen for a new udp packet
   *   chan.init(receiver address); chan.run();
   *   while(...) {listen; chan.init(new socket)}
   * @endcode
   *
   * peek on the read udp socket; extract the address
   * any packets are probably new connections from a new Receiver
   * call and block on channel.init(the read socket)
   *   channel will reads from the read socket, checking for a 'Client Hello'
   *   internally channel allocates its own write socket
   *   it reads and writes until a new dtls connection is made
   *   on success, it then replaces its server* and socket
   * if init() fails, the received packet could have been garbage
   *   decide what to do on the different errors
   */
  void ReceiverMain::run()
  {
    sockaddr_in receiverAddress;
    ::socklen_t addrLen;

    while(true)
    {
      addrLen = sizeof(receiverAddress);
      ::memset(&receiverAddress, 0, sizeof(receiverAddress));

      //peek for a `ClientHello` message from a new Receiver
      if(::recvfrom(
          listen, nullptr, 0, ::MSG_PEEK,
          reinterpret_cast<sockaddr *>(&receiverAddress),
          &addrLen) == -1)
      {
        goto fail;
      }

      //a connection is ready for the channel
      if(chan.init(listen, receiverAddress, receiverKey, serverKey, *rng))
      {
        //XXX: do something more sophisticated- the packet could be ignored
        goto fail;
      }
    }

fail:
    //XXX: do something with the error
    return;
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
   * @brief deallocate the Sender main thread and kill any threads its created.
   */
  SenderMain::~SenderMain()
  {
  }

  /**
   * @brief initialize a Sender main thread.
   *
   * @param store KeyStore that stores Sender certificates.
   */
  int SenderMain::init(MessageQueue *queue_, ServerKey *serverKey_,
      KeyStore *store)
  {
    MainConnection::init(queue_, serverKey_);

    return 0;
  }

  /**
   * @brief perform the main logic of receiving connections from Senders.
   */
  void SenderMain::run()
  {
  }
}
