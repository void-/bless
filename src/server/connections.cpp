#include "connections.h"

#include <chrono> //for duration

#include <poll.h>

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
   * @brief block until the underlying threads completes.
   */
  void Runnable::join()
  {
    t.join();
  }

  /**
   * @class ReceiverChannelPolicy
   * @brief specifies the connection policy for the message channel.
   *
   * The ultimate goal is to use safe curves such as Curve25519 implemented in
   * Botan. However, there is no support for this with D/TLS.
   *
   * @todo this is a copy from Bless::Receiver
   */
  class ReceiverChannelPolicy : public TLS::Strict_Policy
  {
    public:
      /**
       * @brief turn DTLS heartbeats off.
       *
       * @bug heartbeats are only client to server, which defeats the purpose.
       * This is only useful if it could be from server to client, but is not.
       *
       * @return false.
       */
      bool negotiate_hearbeat_support() const
      {
        return false;
      }

      /**
       * @brief turn off server initiated renegotiation.
       *
       * The Server shouldn't be able to send any data that will require a
       * client response.
       *
       * @return false.
       */
      bool allow_server_initiated_renegotiation() const override
      {
        return false;
      }

      /**
       * @brief given a protocol version, return whether its ok.
       *
       * Only DTLS1.2 is acceptable.
       *
       * @param version the protocol version in question.
       * @return whether \p version is DTLS1.2.
       */
      bool acceptable_protocol_version(TLS::Protocol_Version version) const
      {
        return version == TLS::Protocol_Version::DTLS_V12;
      }
  };

  /**
   * @class ReceiverChannelCredentials
   * @brief Manage the credentials for the message channel.
   */
  class ReceiverChannelCredentials : public Credentials_Manager
  {
    public:
      /**
       * @brief construct a ChannelCredentials.
       *
       * @warning this isn't valid until init() is called.
       */
      ReceiverChannelCredentials()
      {
      }

      /**
       * @brief destruct the ChannelCredentials.
       *
       * Don't deallocate authKeys.
       */
      ~ReceiverChannelCredentials() override
      {
      }

      /**
       * @brief initialize credentials to the Receiver.
       *
       * @param serverKey_ the Server's certificate and private key.
       * @param receiverKey_ the Receiver's certificate.
       *
       * @return non-zero on failure.
       */
      int init(ServerKey *serverKey_, ConnectionKey *receiverKey_)
      {
        serverKey = serverKey_;
        receiverKey = receiverKey_;

        return 0;
      }

      /**
       * @brief return no trusted certificate authorities.
       *
       * Self-signed certificates are used between the Server and Receiver; no
       * certificate authorities are trusted.
       *
       * @return an empty vector
       */
      std::vector<Certificate_Store *> trusted_certificate_authorities(
          const std::string &, const std::string &) override
      {
        return std::vector<Certificate_Store *>();
      }

      /**
       * @brief verify the given certificate chain.
       *
       * \p certChain should contain the Receiver's public key.
       *
       * If the certificate matches, it must be valid because it was verified
       * These are verified in authKeys when loaded.
       *
       * @param type the type of operation occuring.
       * @param certChain the certificate chain to verify.
       * @throw std::invalid_argument if its wrong.
       * @throw std::runtime_error if \p type is not "tls_client"
       */
      void verify_certificate_chain(const std::string &type,
          const std::string &,
          const std::vector<X509_Certificate> &certChain) override
      {
        if(type != "tls-server")
        {
          throw std::runtime_error("Must use for tls-server.");
        }

        if(!(certChain.size() == 1 &&
            certChain[0] == *receiverKey->getCert()))
        {
          throw std::invalid_argument("Certificate did not match Receiver's.");
        }
      }

      /**
       * @brief return a certificate chain to identify the Server.
       *
       * This returns the Server's self-signed cert, regardless of the type
       * of key requested.
       *
       * This must be communicated, to the Receiver by means of some externel
       * PKI.
       *
       * @param type the type of operation occuring
       * @throw std::runtime_error if \p type is not "tls_client"
       * @return vector containing the self-signed certificate for the Server.
       */
      std::vector<X509_Certificate> cert_chain(const std::vector<std::string>
          &, const std::string &type, const std::string &)
          override
      {
        if(type != "tls-server")
        {
          throw std::runtime_error("Must use for tls-server.");
        }
        auto cert = serverKey->getCert();
        return std::vector<X509_Certificate>{*cert};
      }

      /**
       * @brief return the private key corresponding to the given \p cert.
       *
       * \p cert should have been returned by cert_chain().
       *
       * @param cert the certificate to yield the private key for.
       * @param type the type of operation occuring.
       * @throw std::runtime_error if \p type is not "tls_client"
       * @return the private half of \p cert.
       */
      Private_Key *private_key_for(const X509_Certificate &cert,
          const std::string &type, const std::string &) override
      {
        if(type != "tls-server")
        {
          throw std::runtime_error("Must use for tls-server.");
        }

        //if the cert is the Server's, return the private key
        if(cert == *serverKey->getCert())
        {
          return serverKey->getPrivKey();
        }

        return nullptr;
      }

      /**
       * @brief return whether an SRP connection should be attempted.
       *
       * Never try SRP, use long-standing public keys.
       *
       * @return false.
       */
      bool attempt_srp(const std::string &, const std::string &) override
      {
        return false;
      }

    private:
      ServerKey *serverKey;
      ConnectionKey *receiverKey;
  };

  /**
   * @class SenderChannelPolicy
   * @brief specifies the connection policy when Senders connect.
   *
   * The functions here should be overriden to restrict available cipher
   * suites.
   */
  class SenderChannelPolicy : public TLS::Strict_Policy
  {
  };

  /**
   * @class SenderChannelCredentials
   * @brief Manage the credentials for connections from Senders.
   */
  class SenderChannelCredentials : public Credentials_Manager
  {
    public:
      /**
       * @brief construct a ChannelCredentials.
       *
       * @warning this isn't valid until init() is called.
       */
      SenderChannelCredentials()
      {
      }

      /**
       * @brief destruct the ChannelCredentials.
       *
       * Don't deallocate authKeys.
       */
      ~SenderChannelCredentials() override
      {
      }

      /**
       * @brief initialize credentials to a Sender.
       *
       * @param serverKey_ the Server's certificate and private key.
       * @param store_ KeyStore to lookup Sender certificates.
       *
       * @return non-zero on failure.
       */
      int init(ServerKey *serverKey_, KeyStore *store_)
      {
        serverKey = serverKey_;
        store = store_;

        return 0;
      }

      /**
       * @brief return no trusted certificate authorities.
       *
       * Self-signed certificates are used between the Server and Sender; no
       * certificate authorities are trusted.
       *
       * @return an empty vector
       */
      std::vector<Certificate_Store *> trusted_certificate_authorities(
          const std::string &, const std::string &) override
      {
        return std::vector<Certificate_Store *>();
      }

      /**
       * @brief verify the given certificate chain.
       *
       * \p certChain should contain a Sender's public key; check this is valid
       * by searching for it in the KeyStore.
       *
       * If the certificate matches, it must be valid because it was verified.
       * These are verified in authKeys when loaded.
       *
       * @param type the type of operation occuring.
       * @param certChain the certificate chain to verify.
       * @throw std::invalid_argument if its wrong.
       * @throw std::runtime_error if \p type is not "tls_client"
       */
      void verify_certificate_chain(const std::string &type,
          const std::string &,
          const std::vector<X509_Certificate> &certChain) override
      {
        if(type != "tls-server")
        {
          throw std::runtime_error("Must use for tls-server.");
        }

        //the chain should be size 1 and valid in the key store
        if(!(certChain.size() == 1 && (store->isValid(certChain[0]) == 0)))
        {
          throw std::invalid_argument("Certificate did not match Receiver's.");
        }
      }

      /**
       * @brief return a certificate chain to identify the Server.
       *
       * This returns the Server's self-signed cert, regardless of the type
       * of key requested.
       *
       * This must be communicated, to the Receiver by means of some externel
       * PKI.
       *
       * @param type the type of operation occuring
       * @throw std::runtime_error if \p type is not "tls_client"
       * @return vector containing the self-signed certificate for the Server.
       */
      std::vector<X509_Certificate> cert_chain(const std::vector<std::string>
          &, const std::string &type, const std::string &) override
      {
        if(type != "tls-server")
        {
          throw std::runtime_error("Must use for tls-server.");
        }
        auto cert = serverKey->getCert();
        return std::vector<X509_Certificate>{*cert};
      }

      /**
       * @brief return the private key corresponding to the given \p cert.
       *
       * \p cert should have been returned by cert_chain().
       *
       * @param cert the certificate to yield the private key for.
       * @param type the type of operation occuring.
       * @throw std::runtime_error if \p type is not "tls_client"
       * @return the private half of \p cert.
       */
      Private_Key *private_key_for(const X509_Certificate &cert,
          const std::string &type, const std::string &) override
      {
        if(type != "tls-server")
        {
          throw std::runtime_error("Must use for tls-server.");
        }

        //if the cert is the Server's, return the private key
        if(cert == *serverKey->getCert())
        {
          return serverKey->getPrivKey();
        }

        return nullptr;
      }

      /**
       * @brief return whether an SRP connection should be attempted.
       *
       * Never try SRP, use long-standing public keys.
       *
       * @return false.
       */
      bool attempt_srp(const std::string &, const std::string &) override
      {
        return false;
      }

    private:
      ServerKey *serverKey;
      KeyStore *store;
  };

  /**
   * @brief construct a Channel, initializing some pointers to null.
   */
  Channel::Channel() : server(nullptr), sessionManager(nullptr),
      credentialsManager(nullptr), policy(nullptr)
  {
  }

  /**
   * @brief destruct a Channel and all its owned resources.
   *
   * Close connection socket, ignoring errors.
   * Destruct all allocated connection objects.
   */
  Channel::~Channel()
  {
    close(connection);

    if(server)
    {
      delete server;
    }

    if(sessionManager)
    {
      delete sessionManager;
    }

    if(credentialsManager)
    {
      delete credentialsManager;
    }

    if(policy)
    {
      delete policy;
    }
  }

  /**
   * @brief base implementation for initializing a Channel.
   *
   * Use this in subclasses of channel to avoid repeated lines.
   *
   * @param socket the socket descriptor for the connection.
   * @param serverKey_ contains the Server's certificate and private
   *   key to the counterparty.
   * @param messageQueue_ used to communicate messages from SenderChannel to be
   *   sent to the Receiver.
   * @return non-zero on failure.
   */
  int Channel::init(int socket, ServerKey *serverKey_,
      MessageQueue *messageQueue_, RandomNumberGenerator *rng_)
  {
    connection = socket;
    serverKey = serverKey_;
    messageQueue = messageQueue_;
    rng = rng_;

    return 0;
  }

  /**
   * @brief destruct a MainConnection and all its owned resources.
   *
   * @warning do not delete queue or serverKey, they are shared.
   * Close listen socket, ignoring errors.
   */
  MainConnection::~MainConnection()
  {
    close(listen);
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
   * @param rng_ random number generator needed for d/tls connections.
   * @return non-zero on failure.
   */
  int MainConnection::init(MessageQueue *queue_, ServerKey *serverKey_,
      RandomNumberGenerator *rng_)
  {
    queue = queue_;
    serverKey = serverKey_;
    rng = rng_;

    return 0;
  }

  /**
   * @brief construct a ReceiverChannel.
   *
   * @warning this is invalid until init() is called.
   */
  ReceiverChannel::ReceiverChannel() : Channel()
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
   * \p socket will we read off of, but no reads will occur after init()
   * returns. It will be further used to send packets, but won't be connected
   * to any destination.
   *
   * @param socket borrowed udp socket that is bound to the listening port, but
   *   not connected to any destination.
   * @param receiverKey_ ConectionKey containing the Receiver's certificate.
   * @param serverKey_ serverKey containing the Server's certificate to the
   *   Receiver.
   * @param messageQueue_ used to communicate messages from SenderChannel to be
   *   sent to the Receiver.
   * @param rng random number generator to use for the connection.
   *
   * @return non-zero on failure.
   */
  int ReceiverChannel::init(int &socket, ConnectionKey *receiverKey_,
      ServerKey *serverKey_, MessageQueue *messageQueue_,
      RandomNumberGenerator *rng_)
  {
    int error = 0;

    if((error = Channel::init(socket, serverKey_, messageQueue_, rng_)))
    {
      goto fail;
    }

    receiverKey = receiverKey_;

    //allocate tls server objects
    try
    {
      policy = new ReceiverChannelPolicy();
      sessionManager = new TLS::Session_Manager_Noop();
      auto creds = new ReceiverChannelCredentials();

      if(creds->init(serverKey_, receiverKey_))
      {
        error = -1;
        goto fail;
      }
      credentialsManager = creds;
    }
    catch(std::bad_alloc &e)
    {
      //couldn't dynamically allocate memory
      error = -2;
      goto fail;
    }

fail:
    return error;
  }

  /**
   * @brief connect the ReceiverChannel to a candidate Receiver at \p addr.
   *
   * connect() can be called multiple times as new connections are initiated by
   * the Receiver.
   *
   * If making a dtls connection to \p addr fails, ReceiverChannel is not
   * modified.
   *
   * Procedure:
   * <p>
   * - initialize a new dtls server
   * - read data from socket until the dtls connection is made
   * - if the connection succeeds, replace the old connection with the new one
   * </p>
   *
   * @param addr socket information about \p socket.
   * @return non-zero on failure.
   */
  int ReceiverChannel::connect(sockaddr_in addr)
  {
    int error = 0;
    Botan::TLS::Server *tmpServer = nullptr;
    ::pollfd pollSocket;
    sockaddr_in tmpAddr = addr;
    unsigned char readBuffer[bufferSize];
    std::unique_lock<std::mutex> lock;
    TLS::Server *oldServer;

    //create a new connection using socket
    try
    {
      tmpServer = new Botan::TLS::Server(
        //we capture the candidate address
        [this, tmpAddr](const byte *const data, size_t len) {
          this->send(tmpAddr, data, len);
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
        *rng,
        [this](std::vector<std::string> proto) {
          return this->nextProtocol(proto);
        },
        true,
        bufferSize);
    }
    catch(std::bad_alloc &e)
    {
      error = -5;
      goto fail;
    }

    //set up socket for polling
    pollSocket.fd = connection;
    pollSocket.events = POLLIN; //poll for reading

    //start up the connection to the candidate Receiver
    while(!tmpServer->is_active())
    {
      //wait at most 2 seconds-the Receiver could be fake
      if(::poll(&pollSocket, 1u, timeout) != 1)
      {
        error = -8;
        goto fail;
      }

      //error on socket
      if((pollSocket.revents & POLLERR) | (pollSocket.revents & POLLHUP) |
          (pollSocket.revents & POLLNVAL))
      {
        //could have received ICMP unreachable
        error = -pollSocket.revents;
        goto fail;
      }

      //read bytes from the candidate Receiver
      auto len = ::read(connection, readBuffer, sizeof(readBuffer));

      //XXX: make sure each packet received is from \p addr

      if(len <= 0)
      {
        //poll() lied!
        error = -6;
        goto fail;
      }

      //give the data to the server
      try
      {
        tmpServer->received_data(readBuffer, len);
      }
      catch(std::runtime_error &e)
      {
        //received data wasn't valid
        error = -7;
        goto fail;
      }
    }

    //if the connection succeeds, shutdown and replace the current connection
    oldServer = server;

    //lock to safely update server
    lock = std::unique_lock<std::mutex>(serverLock);
    server = tmpServer;
    lock.unlock();

    //don't lock to delete
    if(oldServer)
    {
      oldServer->close();
      delete oldServer;
    }
    return 0;

    //if the connection fails; don't modify anything
fail:

    if(tmpServer)
    {
      delete tmpServer;
    }

    return error;
  }

  /**
   * @brief send write \p len bytes of \p payload to udp socket \p sock.
   *
   * @param addr the Receiver address to send to.
   * @param payload data to write to \p sock.
   * @param len length, in bytes, of \p sock.
   */
  void ReceiverChannel::send(sockaddr_in addr, const byte *const payload,
      size_t len)
  {
    auto l = ::sendto(connection, payload, len, MSG_NOSIGNAL,
      reinterpret_cast<sockaddr *>(&addr), sizeof(addr));

    //error writing to socket
    if(l < static_cast<decltype(l)>(len))
    {
      throw std::runtime_error("send failed");
    }
  }

  /**
   * @brief called when a TLS alert is received
   *
   * @todo do something with the alert
   *
   * Beware that alert() might be called during init() for a different
   * connection.
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
   * @brief called when data is received from Receiver, which should never
   * happen.
   *
   * This function is a no op, because the Receiver should never send the
   * Server data after the initial connection is made.
   *
   * @param payload not used.
   * @param len not used.
   */
  void ReceiverChannel::recvData(const byte *const, size_t)
  {
  }

  /**
   * @brief called when a handshake is created from Receiver to Server.
   *
   * @param session not used.
   * @return false, don't cache the session
   */
  bool ReceiverChannel::handshake(const TLS::Session &)
  {
    return false;
  }

  /**
   * @brief called to pick a protocol between Receiver and Sender; this feature
   * is not used.
   *
   * @param protocols
   *
   * @return an empty string indicating no protocol.
   */
  std::string ReceiverChannel::nextProtocol(std::vector<std::string> protocols)
  {
    return "";
  }

  /**
   * @brief send a Message \p m to the Receiver over the message channel.
   *
   * This abstracts serializing the message and actually sending it, incase
   * this needs to be mocked out.
   *
   * Lock serverLock to access a safe copy of server.
   *
   * @param m the message to send.
   */
  void ReceiverChannel::sendMessage(Message &m)
  {
    std::unique_lock<std::mutex> lock(serverLock);
    //TEST
    server->send(m.data.data(), static_cast<size_t>(m.data.size()));
    lock.unlock();
  }

  /**
   * @brief preform the main logic of maintaining a connection to the Receiver.
   *
   * The socket used to connect to the Reciever may be updated via init() when
   * the Receiver moves.
   *
   * @warning init() should be called atleast once before run()
   * @invariant ReceiverChannel::server is not null
   *
   * Procedure:
   * <p>
   * - sleep on the MessageQueue waiting at most timeout milliseconds
   * - take a message off the queue and send it to the Receiver
   * </p>
   */
  void ReceiverChannel::run()
  {
    std::unique_lock<std::mutex> lock(messageQueue->realTimeLock);
    std::chrono::milliseconds timeout(ReceiverChannel::timeout);
    std::unique_ptr<Message> toSend;

    //enter the loop locked
    while(true)
    {
      //wait until a real time message is available or timeout
      if(messageQueue->realTimeSize() == 0)
      {
        messageQueue->messageReady.wait_for(lock, timeout);
      }

      //get the next message from the queue
      toSend = messageQueue->next();
      lock.unlock();
      sendMessage(*toSend);

      //lock down here because the loop is entered locked already
      lock.lock();
    }
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
   * @param rng_ parameter to MainConnection::init.
   * @return non-zero on failure.
   */
  int ReceiverMain::init(MessageQueue *queue_, ServerKey *serverKey_,
      ConnectionKey *receiverKey_, RandomNumberGenerator *rng_)
  {
    ::sockaddr_in addr;

    //initialize a main connection like normal
    if(MainConnection::init(queue_, serverKey_, rng_))
    {
      return -1;
    }

    channelRunning = false;
    receiverKey = receiverKey_;

    //allocate a socket
    if((listen = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
    {
      return -2;
    }

    //initialize bind parameters
    ::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = ::htons(port);

    //bind to udp listen port
    if(bind(listen, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr))
        == -1)
    {
      close(listen); //ignore error
      return -3;
    }

    //initialize the channel, but don't connect or run it
    if(chan.init(listen, receiverKey, serverKey, queue, rng))
    {
      return -4;
    }

    return 0;
  }

  /**
   * @brief start listening for connections from the Receiver.
   *
   * Procedure
   * <p>
   * - peek for a new udp packet
   * - initialize the channel with the new address
   * - run the channel if its not already
   * </p>
   *
   * If connect() fails, the received packet could have been garbage
   *   decide what to do on the different errors.
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

      //a connection is ready for the channel, try to connect to it
      if(chan.connect(receiverAddress))
      {
        //XXX: do something more sophisticated- the packet could be ignored
        //goto fail;
        continue;
      }

      //start the channel thread if its not already
      if(!channelRunning)
      {
        if(chan.start())
        {
          //couldn't start the channel thread
          goto fail;
        }
        channelRunning = true;
      }
    }

fail:
    //XXX: do something with the error
    return;
  }

  /**
   * @brief construct a SenderChannel.
   *
   * Call init() to make it valid.
   */
  SenderChannel::SenderChannel() : Channel(), partialMessage(nullptr)
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
   * Initialize tls session and credentials managers.
   *
   * @param serverKey_ contains certificate of the Server, SenderChannel does
   *   not own this.
   * @param messageQueue_ queue to write Receiver-bound messages to from
   *   Senders.
   * @param store_ KeyStore to validate Sender certificates.
   * @param workLock_ lock to \p work_.
   * @param workReady_ condition variable to \p work_.
   * @param work_ queue to process new Sender connections from.
   * @return non-zero on failure.
   */
  int SenderChannel::init(ServerKey *serverKey_, MessageQueue *messageQueue_,
      KeyStore *store_, std::mutex *workLock_,
      std::condition_variable *workReady_, std::queue<ChannelWork> *work_,
      RandomNumberGenerator *rng_)
  {
    int error = 0;

    //set member variables
    serverKey = serverKey_;
    messageQueue = messageQueue_;
    store = store_;
    workLock = workLock_;
    workReady = workReady_;
    work = work_;
    rng = rng_;

    //allocate tls server objects
    try
    {
      policy = new SenderChannelPolicy();
      sessionManager = new TLS::Session_Manager_Noop();
      auto creds = new SenderChannelCredentials();

      if(creds->init(serverKey_, store_))
      {
        error = -1;
        goto fail;
      }
      credentialsManager = creds;
    }
    catch(std::bad_alloc &e)
    {
      //couldn't dynamically allocate memory
      error = -2;
      goto fail;
    }

fail:
    return error;
  }

  /**
   * @brief perform the main logic of connecting to a Sender.
   *
   * Procedure:
   * <p>
   * - wait until a connection is available on the work queue
   * - allocate a new TLS server to handle the connection
   * - read for a message from the Sender
   * - write the message to the message queue
   * - shutdown the connection
   * </p>
   */
  void SenderChannel::run()
  {
    std::unique_lock<std::mutex> lock;
    ::pollfd pollSocket;
    int error = 0;
    unsigned char readBuffer[bufferSize];

    while(true)
    {
      lock = std::unique_lock<std::mutex>(*workLock);
      //wait until work is available
      while(work->size() == 0)
      {
        workReady->wait(lock);
      }

      //remove a work item = a connection to handle
      ChannelWork sender = work->front();
      work->pop();
      //assign member variable for server lambdas; inside lock for destructor
      connection = sender.conn;
      lock.unlock();

      //process the connection
      try
      {
        server = new Botan::TLS::Server(
          [this](const byte *const data, size_t len) {
            this->send(data, len);
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
          *rng,
          [this](std::vector<std::string> proto) {
            return this->nextProtocol(proto);
          },
          false,
          bufferSize);
      }
      catch(std::bad_alloc &e)
      {
        error = -1;
        goto shutdown;
      }

      //allocate a message to write to
      try
      {
        partialMessage = std::unique_ptr<Message>(new Message());
      }
      catch(std::bad_alloc &e)
      {
        error = -10;
        goto shutdown;
      }

      //set up socket for polling
      pollSocket.fd = connection;
      pollSocket.events = POLLIN; //poll for reading

      //start up the connection
      while(!server->is_active())
      {
        //wait at most 4 seconds-the Sender could be fake
        if(::poll(&pollSocket, 1u, timeout) != 1)
        {
          error = -2;
          goto shutdown;
        }

        //error on socket
        if((pollSocket.revents & POLLERR) | (pollSocket.revents & POLLHUP) |
            (pollSocket.revents & POLLNVAL))
        {
          //could have received ICMP unreachable
          error = -3;
          goto shutdown;
        }

        //read bytes from the candidate Receiver
        auto len = ::read(connection, readBuffer, sizeof(readBuffer));

        if(len <= 0)
        {
          //poll() lied!
          error = -4;
          goto shutdown;
        }

        //give the data to the server
        try
        {
          server->received_data(readBuffer, len);
        }
        catch(std::runtime_error &e)
        {
          error = -5;
          goto shutdown;
        }
      }

      //secure connection established; read data from the Sender
      while(server->is_active())
      {
        if(::poll(&pollSocket, 1u, timeout) != 1)
        {
          error = -6;
          goto shutdown;
        }

        //error on socket
        if((pollSocket.revents & POLLERR) | (pollSocket.revents & POLLHUP) |
            (pollSocket.revents & POLLNVAL))
        {
          //could have received ICMP unreachable
          error = -7;
          goto shutdown;
        }

        //read bytes from the candidate Receiver
        auto len = ::read(connection, readBuffer, sizeof(readBuffer));

        if(len <= 0)
        {
          //poll() lied!
          error = -8;
          goto shutdown;
        }

        //give the data to the server
        try
        {
          server->received_data(readBuffer, len);
        }
        catch(std::runtime_error &e)
        {
          error = -9;
          goto shutdown;
        }
      }

shutdown:
      //successfully received a message from Sender or failure
      if(server)
      {
        delete server;
      }

      //deallocate the message
      if(partialMessage)
      {
        partialMessage.reset();
      }

      close(connection);

      //do something with error
    }
  }

  /**
   * @brief send write \p len bytes of \p payload to tcp socket.
   *
   * @param payload data to write.
   * @param len length, in bytes, of \p payload.
   */
  void SenderChannel::send(const byte *const payload, size_t len)
  {
    size_t read = 0;
    //keep writing the entire payload
    while(read < len)
    {
      auto sent = ::send(connection, &payload[read], len, MSG_NOSIGNAL);

      if(sent == -1)
      {
        throw std::runtime_error("send failed");
      }

      read += sent;
    }
  }

  /**
   * @brief called when a TLS alert is received
   *
   * @todo do something with the alert
   *
   * Beware that alert() might be called during init() for a different
   * connection.
   *
   * @param alert
   * @param payload
   * @param len
   */
  void SenderChannel::alert(TLS::Alert alert, const byte *const payload,
      size_t len)
  {
  }

  /**
   * @brief called when data is received from Sender.
   *
   * This function is non-reentrant; it should be called synchronously.
   *
   * Deserialize \p payload into partialMessage until partialMessage is
   * complete. At this point, shutdown the TLS connection; no more bytes are
   * needed from the Sender.
   *
   * Ownership of partialMessage is transfered to the message queue when
   * completed.
   *
   * @invariant partialMessage always has a valid pointer.
   *
   * @param payload some bytes of a Message from Sender.
   * @param len length of \p payload in bytes.
   */
  void SenderChannel::recvData(const byte *const payload, size_t len)
  {
    //give payload bytes to message
    int status = partialMessage->deserialize(payload, len);

    //message was fully deserialized
    if(status == 0)
    {
      //give ownership to message queue
      messageQueue->addMessage(std::move(partialMessage));

      //signal to shutdown the TLS server
      server->close();
    }
    else if(status == -1)
    {
      //error in deserialization
      server->close();
    }
  }

  /**
   * @brief called when a handshake is created from Receiver to Server.
   *
   * @param session not used.
   * @return false, don't cache the session
   */
  bool SenderChannel::handshake(const TLS::Session &)
  {
    return false;
  }

  /**
   * @brief called to pick a protocol between Sender and Server; this feature
   * is not used.
   *
   * @param protocols
   *
   * @return an empty string indicating no protocol.
   */
  std::string SenderChannel::nextProtocol(std::vector<std::string> protocols)
  {
    return "";
  }

  /**
   * @brief deallocate the Sender main thread and kill any threads its created.
   */
  SenderMain::~SenderMain()
  {
    std::unique_lock<std::mutex> lock(workLock);

    //lock and close all outstanding connections
    while(connections.size())
    {
      auto w = connections.front();
      connections.pop();
      ::close(w.conn);
    }
    lock.unlock();
  }

  /**
   * @brief initialize a Sender main thread.
   *
   * @see MainConnection::init()
   *
   * @param queue_ parameter to MainConnection::init.
   * @param serverKey_ parameter to MainConnection::init.
   * @param store_ KeyStore that stores Sender certificates.
   * @param rng_ parameter to MainConnection::init.
   * @return non-zero on failure.
   */
  int SenderMain::init(MessageQueue *queue_, ServerKey *serverKey_,
      KeyStore *store_, RandomNumberGenerator *rng_)
  {
    ::sockaddr_in addr;
    int sockOption = 1;
    int error;

    //initialize a main connection
    if(MainConnection::init(queue_, serverKey_, rng_))
    {
      error = -1;
      goto fail;
    }

    store = store_;

    //initialize all channel threads
    for(auto &c : channels)
    {
      if(c.init(serverKey, queue, store, &workLock, &workReady, &connections,
          rng))
      {
        error = -6;
        goto fail;
      }
    }

    //allocate a tcp socket
    if((listen = ::socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
      error = -2;
      goto fail;
    }

    //set socket options
    if(::setsockopt(listen, SOL_SOCKET, SO_REUSEADDR, &sockOption,
        sizeof(sockOption)) == -1)
    {
      error = -3;
      goto fail;
    }

    //initialize bind parameters
    ::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = ::htons(port);

    //bind to tcp listen port
    if(::bind(listen, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr))
        == -1)
    {
      error = -4;
      goto fail;
    }

    //set the socket to listen, but don't accept yet
    if(::listen(listen, backlog) == -1)
    {
      error = -5;
      goto fail;
    }

    return 0;

fail:
    close(listen); //ignore error
    return error;
  }

  /**
   * @brief perform the main logic of receiving connections from Senders.
   *
   * Procedure:
   * <p>
   * - start all channel threads to handle connections
   * - accept for tcp connections
   * - load the new socket and Sender address to a work queue
   * </p>
   */
  void SenderMain::run()
  {
    int conn;
    sockaddr_in addr;
    socklen_t len;
    std::unique_lock<std::mutex> lock;

    //start all channel threads
    for(auto &c : channels)
    {
      c.start();
    }

    while(true)
    {
      //reset length of address; the length written by accept() is ignored
      len = sizeof(addr);

      //wait for a Sender connection
      if((conn =
          ::accept(listen, reinterpret_cast<sockaddr *>(&addr), &len))
          == -1)
      {
        //accept failed; try again?
        continue;
      }

      //add the new connection to the work queue
      lock = std::unique_lock<std::mutex>(workLock);
      connections.emplace(conn, addr);
      //signal a channel there's a new connection
      workReady.notify_one();
      lock.unlock();
    }
  }
}
