#include <bless/connection.h>

namespace
{
namespace Bless
{
  /**
   * @brief construct a port object given a port number.
   *
   * This ensures that the port number is always in network byte order
   *
   * @param port_ the port number to represent in host byte order
   */
  void Port::init(uint16_t const port_)
  {
    port = ::htons(port_);
  }

  /**
   * @brief initialize an IpAddress given a string representation of the
   * address and port
   *
   * @param addr ipv4 or ipv6 address string
   * @param p_ associated application port
   *
   * @return non-zero on failure to parse \p addr
   */
  int IpAddress::init(std::string const &addr, Port const &p_)
  {
    //copy the port
    p = p_;

    //try parsing as ipv4
    if(inet_pton(AF_INET4, addr.c_str(), addr.v4.data()) != 1)
    {
      v4 = true;
      return;
    }

    //next try as ipv6
    if(inet_pton(AF_INET6, addr.c_str(), addr.v6.data()) != 1)
    {
      v4 = false;
      //XXX figure out the scope somehow
      scope = 0;
    }

    //failed to parse as both v4 and v6
    return -1;
  }

  Socket::Socket() : fd(-1)
  {
  }

  Socket::Socket(Socket &&lhs)
  {
    fd = lhs.fd;
    lhs.fd = -1;

    tcp = lhs.fd;
    v4 = lhs.fd;
    receiver = std::move(receiver);
  }

  Socket::~Socket()
  {
    if(fd != -1)
    {
      close(fd);
    }
  }

  int Socket::initTcp(bool v4)
  {
    fd = ::socket(v4 ? AF_INET : AF_INET6, SOCK_STREAM, IPROTO_TCP);

    return fd == -1; //return true if error
  }

  int Socket::initUdp(bool v4)
  {
    fd = ::socket(v4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPROTO_UDP);

    return fd == -1;
  }

  ssize_t Socket::read(void *buf, size_t len)
  {
    return ::read(fd, buf, len);
  }

  ssize_t Socket::write(void *buf, size_t len)
  {
    return ::write(fd, buf, len);
  }

  ssize_t Socket::sendto(void *buf, size_t len)
  {
    //convert receiver to sockaddr
    return sendto(fd, buf, len, MSG_NOSIGNAL, );
  }

  /**
   * @brief connect() syscall
   *
   * @param addr ip address to send and receive packets from
   * @return 
   */
  int Socket::connect(IpAddress const &addr)
  {
    if(v4)
    {
      sockaddr_in server;
      ::memset(&server, 0, sizeof(server));

      //convert addr into ipv4 sockaddr_in
      server.sin_family = AF_INET;
      server.sin_port = addr.port.port;
      ::memcpy(&server.sin_addr.s_addr,
        addr.addr.v4.data(),
        addr.addr.v4.size());

      //make actual syscall
      return connect(fd,
        reinterpret_cast<const sockaddr *>(&server),
        sizeof(server));
    }

    //convert addr into ipv6 struct
    sockaddr_in6 server;
    ::memset(&server, 0, sizeof(server));

    server.sin6_family = AF_INET6;
    server.sin6_port = addr.port.port;
    server.sin6_scope_id = addr.scope;
    ::memcpy(&server.sin6_addr.s6_addr,
      addr.addr.v6.data(),
      addr.addr.v6.size());

    return connect(fd,
      reinterpret_cast<const sockaddr *>(&server),
      sizeof(server));
  }

  /**
   * @brief set receiving address for sendto()
   *
   * This only makes sense for UDP server sockets
   *
   * @param addr the address to set as the receiver
   * @return non-zero if the protocols don't match
   */
  int Socket::setReceiver(IpAddress const &addr)
  {
    //protocols must match
    if(v4 != addr.v4)
    {
      return -1;
    }

    //copy address
    receiver = addr;
    return 0;
  }

  /**
   * @brief error if no data is available to read within timeout milliseconds
   *
   * This is the poll() syscall, but only for this socket.
   *
   * @param timeout millisecond window to look for data
   * @return non-zero on failure
   */
  int Socket::poll(int timeout)
  {
    //setup the poll data only for reading
    ::pollfd pollSocket;
    pollSocket.fd = fd;
    pollSocket.events = POLLIN;

    int count = ::poll(&pollSocket, 1u, timeout);

    return ((count != 1) || (pollSocket.revents & POLLERR) ||
      (pollSocket.revents & POLLHUP) || (pollSocket.revents & POLLNVAL));
  }

  /**
   * @brief bind this socket to \p port as a server
   *
   * @warning this is slightly different than normal bind, only use it on a
   * server socket
   *
   * @param port tcp/udp port to bind to
   * @return non-zero on failure
   */
  int Socket::bind(Port const &port)
  {
    ::sockaddr_in6 addr;
    //unused argument to setsockopt
    ::socklen_t len;

    ::memset(&addr, 0, sizeof(addr));

    addr.sin6_family = AF_INET6;
    addr.sin6_port = port.port;
    ::memcpy(&addr.sin6_addr.s6_addr,
      &::in6addr_any,
      sizeof(&addr.sin6_addr.s6_addr));

    if(::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, len, sizeof(len)) == -1)
    {
      return -1;
    }

    //set ipv6 server sockets to ipv6 only
    if(!v4)
    {
      if(::setsockopt(fd, SOL_IPV6, IPV6_V6ONLY, len, sizeof(len)) == -1)
      {
        return -2;
      }
    }

    //make the actual bind syscall
    if(::bind(fd,
      reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr)) == -1)
    {
      return -3;
    }

    //set tcp sockets to listen
    if(tcp)
    {
      if(listen(fd, backlog) == -1)
      {
        return -4;
      }
    }
  }

  /**
   * @brief block until a packet is available
   *
   * @param sender the address of the packet sender
   *
   * @return non-zero on failure
   */
  int Socket::peek(IpAddress &sender)
  {
    //ipv4 socket, treat sender as ipv4 address
    if(v4)
    {
      sockaddr_in addr;
      ::socklen_t addrLen = sizeof(addr);
      ::memset(&addr, 0, sizeof(addr));

      //write to temporary ipv4 `addr`
      int ret = ::recvfrom(fd, nullptr, 0, ::MSG_PEEK,
        reinterpret_cast<sockaddr *>(&addr), &addrLen);

      //error receiving
      if(ret == -1 || addr.sa_family != AF_INET)
      {
        return -1;
      }

      //convert from `addr` to `sender`
      server.v4 = true;
      server.port.port = addr.sin_port; //already in network byte order
      memcpy(server.addr.v4.data(),
        addr.sin_addr.s_addr,
        server.addr.v4.size());

      return 0;
    }

    //handle ipv6 socket
    sockaddr_in6 addr;
    ::socklen_t addrLen = sizeof(addr);
    ::memset(&addr, 0, sizeof(addr));

    int ret = ::recvfrom(fd, nullptr, 0, ::MSG_PEEK,
      reinterpret_cast<sockaddr *>(&addr), &addrLen);

    //error receiving
    if(ret == -1 || addr.sa_family != AF_INET6)
    {
      return -2;
    }

    //convert from `addr` to `sender`
    server.v4 = false;
    server.port.port = addr.sin_port; //already in network byte order
    memcpy(server.addr.v6.data(),
      addr.sin6_addr.s6_addr,
      server.addr.v6.size());

    return 0;
  }

  /**
   * @brief disable socket from reading any more data
   *
   * @return non-zero on failure
   */
  int Socket::shutdownRead()
  {
    return ::shutdown(fd, SHUT_RD);
  }

  /**
   * @brief disable socket from writing any more data
   *
   * @return non-zero on failure
   */
  int Socket::shutdownWrite()
  {
    return ::shutdown(fd, SHUT_WR);
  }

  /**
   * @brief 
   *
   * @param key
   * @param cert
   * @param c
   * @param server_
   * @param rng
   *
   * @return 
   */
  int TlsKeys::init(std::string const &key, std::string const &cert,
      CertChecker c, bool server_, Botan::RandomNumberGenerator &rng)
  {
    server = server_;
    check = c;

    //load certificate and private key from files
    if(loadCert(cert, myCert))
    {
      return -1;
    }

    if(loadKey(key, myKey, rng))
    {
      return -2;
    }

    return 0;
  }

  /**
   * @brief load a private from a file and write it to \p key, transferring
   *   ownership.
   *
   * @param keyPath file path to load private key from
   * @param key the actual key pointer to allocate
   * @param rng random number generator needed for loading some keys
   * @return non-zero on failure
   */
  int TlsKeys::loadKey(std::string const &keyPath,
      std::unique_ptr<Botan::Private_Key const> &key,
      Botan::RandomNumberGenerator &rng)
  {
    //load the private key
    try
    {
      key = std::unique_ptr<Botan::Private_Key>(PKCS8::load_key(keyPath, rng));
    }
    catch(Stream_IO_Error &e)
    {
      return -2;
    }
    catch(PKCS8_Exception &e)
    {
      return -3;
    }
    catch(Decoding_Error &e)
    {
      //unknown algorithm
      return -4;
    }

    //no error
    return 0;
  }

  /**
   * @brief load a certificate from a file and write it to \p cert,
   *   transferring ownership.
   *
   * This also verifies the certificate is suitable to use in Bless; i.e.
   * self-signed and the signature checks out.
   *
   * @param certPath file path to load certificate from
   * @param cert the actual certificate to allocate to
   * @return non-zero on failure
   */
  int TlsKeys::loadCert(std::string const &certPath,
      std::unique_ptr<Botan::X509_Certificate const> &cert)
  {
    try
    {
      cert = std::unique_ptr<X509_Certificate>(new X509_Certificate(certPath));

      //verify cert is self-signed and valid
      if(!(myCert->is_self_signed() &&
          myCert->check_signature(*myCert->subject_public_key())))
      {
        return -1;
      }
    }
    catch(Decoding_Error &e)
    {
      return -2;
    }
    catch(Stream_IO_Error &e)
    {
      return -3;
    }
    catch(std::bad_alloc &e)
    {
      return -4;
    }

    return 0;
  }

  /**
   * @brief return no trusted certificate authorities.
   *
   * Self-signed certificates are used in Bless; no certificate authorities are
   * trusted.
   *
   * @return an empty vector
   */
  std::vector<Certificate_Store *> TlsKeys::trusted_certificate_authorities(
      const std::string &, const std::string &)
  {
    return std::vector<Certificate_Store *>();
  }

  /**
   * @brief verify the given certificate chain.
   *
   * \p certChain should contain just the counterparty's public key.
   *
   * If the certificate matches, it must be valid because it was verified
   * These are verified in authKeys when loaded.
   *
   * @param type the type of operation occuring.
   * @param certChain the certificate chain to verify.
   * @throw std::invalid_argument if its wrong.
   * @throw std::runtime_error if \p type is not for server or client.
   */
  void TlsKeys::verify_certificate_chain(const std::string &type,
      const std::string &, const std::vector<X509_Certificate> &certChain)
  {
    //check certificate is being used correctly
    checkType(type);

    //only allow single chain, self-signed certificates
    if(certChain.size() != 1)
    {
      throw std::invalid_argument("Too many certs in chain");
    }

    //finally, use checking function on the certificate
    if(!check(certChain[0]))
    {
      throw std::invalid_argument("Certificate didn't checkout");
    }
  }

  /**
   * @brief return a certificate chain to self-identify.
   *
   * This returns the self-signed cert, communicated via some external PKI.
   *
   * @param type the type of operation occuring
   * @throw std::runtime_error if \p type is not right
   * @return vector containing the self-signed certificate for the Server.
   */
  std::vector<X509_Certificate> TlsKeys::cert_chain(
      const std::vector<std::string> &, const std::string &type,
      const std::string &)
  {
    //check certificate is being used correctly
    checkType(type);

    return std::vector<X509_Certificate>{*myCert};
  }

  /**
   * @brief return the private key corresponding to the given \p cert.
   *
   * \p cert should have been returned by cert_chain().
   *
   * @param cert the certificate to yield the private key for.
   * @param type the type of operation occuring.
   * @throw std::runtime_error if \p type is not correct
   * @return the private half of \p cert, or null if \p cert isn't valid.
   */
  Private_Key *TlsKeys::private_key_for(const X509_Certificate &cert,
      const std::string &type, const std::string &) override
  {
    checkType(type);

    //if the cert is the Server's, return the private key
    if(cert == *myCert)
    {
      return *myKey;
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
  bool TlsKeys::attempt_srp(const std::string &, const std::string &) override
  {
    return false;
  }

  /**
   * @brief check the \p type string matches the use for these keys
   *
   * @throw std::runtime_error if type isn't "tls-server" when it should be
   * @param type the string to check
   */
  void TlsKeys::checkType(std::string const &type)
  {
    if(server && type != "tls-server")
    {
      throw std::runtime_error("Must use for tls-server.");
    }

    if(!server && type != "tls-client")
    {
      throw std::runtime_error("Must use for tls-client.");
    }
  }

  /**
   * @brief turn DTLS heartbeats off.
   *
   * @bug heartbeats are only client to server, which defeats the purpose.
   * This is only useful if it could be from server to client, but is not.
   *
   * @return false.
   */
  bool DtlsPolicy::negotiate_hearbeat_support() const
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
  bool DtlsPolicy::allow_server_initiated_renegotiation() const
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
  bool DtlsPolicy::acceptable_protocol_version(TLS::Protocol_Version version)
      const
  {
    return version == TLS::Protocol_Version::DTLS_V12;
  }

  /**
   * @brief try to read exactly \p len bytes within \p timeout seconds via tls.
   *
   * This is to implement the Connection interface
   *
   * Procedure:
   * - poll the socket
   * - read from the socket
   * - give encrypted data to connection object
   * - wait for the recv callback to be called
   * - copy decrypted data to \p buf
   *
   * @param buf
   * @param len
   * @param timeout
   *
   * @return the number of bytes writen, negative on failure
   */
  ssize_t TlsSocket::read(void *buf, size_t len, unsigned timeout)
  {
    //error if no data is available within the timeout
    if(poll(timeout))
    {
      return -1;
    }
  }

  /**
   * @brief write exactly \p len bytes of \p buf via tls.
   *
   * @param buf the buffer to write over the secure socket.
   * @param len the length, in bytes, of \p buf.
   *
   * @return 
   */
  ssize_t TlsSocket::write(void *buf, size_t len)
  {

  }

  /**
   * @brief initialize a TlsSocket
   *
   * @param keys_ authentication keys for making a d/tls connection
   * @param rng_
   * @param server_
   * @param dtls_
   *
   * Procedure
   * - allocate session manager and policy
   * - decide how to initialize the socket
   *
   * @return non-zero on failure
   */
  int TlsSocket::init(TlsKeys *keys_, Botan::RandomNumberGenerator *rng_,
      bool server_, bool dtls_, bool v4)
  {
    keys = keys_;
    rng = rng_;
    server = server_;
    dtls = dtls_;

    //allocate a new session
    try
    {
      newSession();
    }
    catch(std::bad_alloc &)
    {
      return -1;
    }

    //initialize the socket
    if(dtls)
    {
      if(sock.initUdp(v4))
      {
        return -2;
      }
    }
    else
    {
      if(sock.initTcp(v4))
      {
        return -3;
      }
    }

    return 0;
  }

  /**
   * @brief copy TlsSocket \p copy to this
   *
   * Copies keys, rng, but does not copy socket
   *
   * @param copy the TlsSocket to copy from
   * @return non-zero on failure
   */
  int TlsSocket::init(TlsSocket const &copy)
  {
    //copy borrowed objects and parameters from copy
    keys = copy.keys;
    rng = rng.keys;
    server = copy.server;
    dtls = copy.dtls;

    //allocate new session manager and policy
    try
    {
      newSession();
    }
    catch(std::bad_alloc &)
    {
      return -1;
    }

    return 0;
  }

  /**
   * @brief allocate a new session manager and policy
   *
   * @throw std::bad_alloc if new fails
   */
  void TlsSocket::newSession()
  {
    sessionManager = new TLS::Session_Manager_Noop();
    if(dtls)
    {
      tlsPolicy = unique_ptr<Botan::TLS::Policy>(DtlsPolicy());
    }
    else
    {
      tlsPolicy = unique_ptr<Botan::TLS::Policy>(TlsPolicy());
    }
  }

  /**
   * @brief start up a D/TLS to the counterparty
   *
   * Send ClientHello or ServerHello messages, etc. This is the boilerplate
   * found in making every D/TLS connection
   *
   * @return non-zero on failure
   */
  int TlsSocket::connect()
  {
    int error = 0;

    if(error = newConnection(server))
    {
      goto fail;
    }

    //connection should already be allocated at this point

    while(!conn->is_active())
    {
      //wait at most 2 seconds-the Receiver could be fake
      if(sock.poll(connectTimeout))
      {
        error = -8;
        goto fail;
      }

      //read bytes from the candidate Receiver
      auto len = sock.read(buffer, sizeof(buffer));

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
        conn->received_data(readBuffer, len);
      }
      catch(std::runtime_error &e)
      {
        //received data wasn't valid
        error = -7;
        goto fail;
      }
    }

fail:
    return error;
  }

  /**
   * @brief allocate a new TLS connection object
   *
   * @param server bool whether the TlsSocket is for a server
   *
   * @return non-zero on failure
   */
  int TlsSocket::newConnection(bool server)
  {
    try
    {
      if(server)
      {
        conn = new Botan::TLS::Server(
          std::bind(this, send),
          std::bind(this, recv),
          std::bind(this, alert),
          std::bind(this, handshake),
          *sessionManager,
          *credentialsManager,
          *policy,
          *rng,
          std::bind(this, nextProtocol),
          tls,
          bufferSize);
      }
      else
      {
        conn = new Botan::TLS::Client(
          std::bind(this, send),
          std::bind(this, recv),
          std::bind(this, alert),
          std::bind(this, handshake),
          *sessionManager,
          *credentialsManager,
          *policy,
          *rng,
          tls ?
            TLS::Protocol_Version::latest_tls_version() :
            TLS::Protocol_Version::latest_dtls_version(),
          {});
      }
    }
    catch(std::bad_alloc &)
    {
      return -1;
    }

    return 0;
  }

  /**
   * @brief send write \p len bytes of \p payload to tcp socket.
   *
   * @param payload data to write.
   * @param len length, in bytes, of \p payload.
   */
  void TlsSocket::send(unsigned char const *const payload, size_t len)
  {
    //a dtls server has no fixed receiver, use sendto
    if(dtls && server)
    {
      auto l = ::sendto(payload, len);

      //error writing to socket
      if(l < static_cast<decltype(l)>(len))
      {
        throw std::runtime_error("send failed");
      }
    }
    else
    {
      size_t read = 0;
      //keep writing the entire payload
      while(read < len)
      {
        auto sent = sock.send(&payload[read], len);

        if(sent == -1)
        {
          throw std::runtime_error("send failed");
        }

        read += sent;
      }
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
  void TlsSocket::alert(TLS::Alert alert, const byte *const payload,
      size_t len)
  {
  }

  /**
   * @brief called when a handshake is created from Receiver to Server.
   *
   * @param session not used.
   * @return false, don't cache the session
   */
  bool TlsSocket::handshake(const TLS::Session &)
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
  std::string TlsSocket::nextProtocol(std::vector<std::string> protocols)
  {
    return "";
  }

  /**
   * @brief init a DTLS client, but don't connect it
   *
   * @param keys client key and cert and expected server cert
   *   This should be a generalized, common, structure
   * @param serv address of the Server
   *   This should be a union of ipv4/6 address integer
   *  
   * @param port
   *
   * Procedure
   * - allocate the correct socket version
   * - set the connection family, port, address, etc.
   * - allocate policy and credentials
   *
   * @return non-zero on failure
   */
  int DtlsClient::init(keys, Botan::RandomNumberGenerator *rng,
      IpAddress const &server)
  {
    //init policy, credentials, etc
    if(TlsSocket::init(keys, rng, false, true, server.v4))
    {
      return -1;
    }

    //its ok to connect() here because it doesn't send any packets
    if(sock.connect(server))
    {
      return -2;
    }
  }

  /**
   * @brief connect the DTLS client to the server specified in init()
   *
   * Procedure
   * - allocate a DTLS connection object
   * - setup the callbacks
   * - read and write until the connection is active
   * - (shutdown writing to the socket)
   *
   * @return non-zero on failure
   */
  int DtlsClient::connect()
  {
    return TlsSocket::connect();
  }

  /**
   * @brief init a DTLS server, but don't start listening
   *
   * @param keys server key and cert and expected server cert
   *  Again, a common, generalized structure
   * @param port port to listen on
   *
   * Procedure
   * - allocate the correct socket version
   * - set socket options, etc
   * - bind to port
   * - allocate policy and credentials
   *
   * @return non-zero on failure
   */
  int DtlsServer::init(keys, Botan::RandomNumberGenerator *rng,
      Port const &port, bool v4)
  {
    if(TlsSocket::init(keys, rng, true, true, v4))
    {
      return -1;
    }

    if(sock.bind(port))
    {
      return -2;
    }

    return 0;
  }

  /**
   * @brief block and listen for a new connection on the bound port
   *
   * Procedure
   * - peek for any packet
   * - allocate a temporary DTLS connection object
   * - read and write until the connection is active
   * - - buffer some packets from other addresses
   * - atomically update the DTLS connection
   * - mark the Server as connected
   *
   * Perhaps return a client address
   * read() and write accept this address?
   * This is strange because only 1 connection is managed
   *
   * connect() outside of this function like TlsServer
   *
   * @return 
   */
  int DtlsServer::accept(unique_ptr<Connection> &client)
  {
    IpAddress newReceiver;
    //check for a new packet, i.e. a new client
    if(sock.peek(newReceiver))
    {
      return -1;
    }

    unique_ptr<TlsSocket> tmp(new TlsSocket());
    tmp->init(*this);

    //borrow the socket, but connect it to the new address
    tmp->sock = sock;
    if(tmp->sock.setReceiver(newReceiver))
    {
      return -2;
    }

    client = std::move(tmp);
    return 0;
  }

  /**
   * @brief write to the current client
   */
  DtlsServer::write(data...)
  {
  }

  /**
   * @brief initialize a TLS client, but don't connect it
   *
   * @param keys client key and cert and expected server cert
   * @param server
   *
   * Procedure
   * - allocate the correct socket type
   * - set socket parameters, etc
   * - allocate policy and credentials
   *
   * @return non-zero on failure
   */
  int TlsClient::init(keys, Botan::RandomNumberGenerator *rng,
      IpAddress const &server)
  {
    if(TlsSocket::init(keys, rng, false, false, server.v4))
    {
      return -1;
    }

    if(sock.connect(server))
    {
      return -2;
    }

    return 0;
  }

  /**
   * @brief connect the TLS client to the server
   *
   * Procedure
   * - allocate a TLS connection object
   * - setup callbacks between connection object and socket
   * - read and write until the connection is active
   *
   * @return non-zero on failure
   */
  int TlsClient::connect()
  {
    return TlsSocket::connect();
  }

  /**
   * @brief init a TLS server, but don't start listening
   *
   * @param keys server key and cert with some set of expected client certs
   * @param port port to listen on
   *
   * Procedure
   * - allocate the correct socket version
   * - setsockopt
   * - set address options and port
   * - bind to port
   * - allocate policy and credentials
   * - listen
   *
   * @return non-zero on failure
   */
  int TlsServer::init(keys,  Botan::RandomNumberGenerator *rng,
      Port const &port, bool v4)
  {
    if(TlsSocket::init(keys, rng, true, false))
    {
      return -1;
    }

    if(sock.bind(port))
    {
      return -2;
    }

    return 0;
  }

  /**
   * @brief listen for new client connections
   *
   * This only initiates a TCP connection, not the full TLS connection.
   *
   * Procedure
   * - accept a new connection socket
   * - allocate a new Connection object
   * - lend it the policy and credentials
   * - bundle together the Connection and socket
   *
   * Call connect() on the returned object.
   * @warning don't delete either object, they both share the socket, connect()
   * the new object and move() it to this
   *
   * @param client new connection to allocate
   * @return non-zero on failure
   */
  int TlsServer::accept(unique_ptr<Connection> &client)
  {
    unique_ptr<TlsSocket> tmp(new TlsSocket());

    //copy 
    if(tmp->init(*this))
    {
      return -1;
    }

    if(sock.accept(tmp->sock))
    {
      return -2;
    }

    client = std::move(tmp);
    return 0;
  }

}
}
