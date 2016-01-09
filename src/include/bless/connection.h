#ifndef CONNECTION_h
#define CONNECTION_h

namespace Bless
{
  /**
   * @class Connection
   * @brief abstract connection interface
   *
   * Supports reading and writing application data.
   */
  class Connection
  {
    public:
      Connection(Connection const &) = delete;
      virtual ~Connection() = 0;

      /**
       * @brief read application data within \p timeout milliseconds.
       *
       * The return value should equal \p len, if not something went wrong.
       *
       * @param buf buffer to read data into
       * @param len the number of bytes to read
       * @param timeout maximum number of milliseconds to wait for data
       * @return the number of bytes read or negative on failure.
       */
      virtual ssize_t read(void *buf, size_t len, int timeout = -1) = 0;

      /**
       * @brief write application data, blocking until its all written
       *
       * @param buf the buffer to write \p len bytes from
       * @param len the exact number of bytes of \p buf to send
       * @return the number of bytes written or negative on failure
       */
      virtual ssize_t write(void *buf, size_t len) = 0;

    protected:
      Connection() = default;
  };

  /**
   * @class Client
   * @brief extends interface of Connection to provide client functionality
   *
   * This is implemented to provide secure connections only although there's
   * nothing that suggests this in the class name `Client`.
   */
  class Client : virtual Connection
  {
    public:
      /**
       * @brief initialize a secure client connection, but don't connect it.
       *
       * @param keys authentication keys
       * @param rng random number generator needed to make a secure connection
       * @param server this indicates whether to use ipv4 or ipv6
       *
       * @return non-zero on failure
       */
      virtual int init(TlsKeys *keys, Botan::RandomNumberGenerator *rng,
        IpAddress const &server) = 0;

      /**
       * @brief connect the client to the address specified via init().
       *
       * This blocks until the connection is complete.
       *
       * @return non-zero on failure
       */
      virtual int connect() = 0;
  };

  /**
   * @class Server
   * @brief extends interface of Connection to provide server functionality
   */
  class Server : virtual Connection
  {
    public:
      virtual int init(TlsKeys *keys, Botan::RandomNumberGenerator *rng,
        Port const &port, bool v4=true) = 0;
      virtual unique_ptr<Connection> accept() = 0;
  };

  /**
   * @class Port
   * @brief ip tcp/udp application port always in network byte order
   */
  struct Port
  {
    void init(uint16_t const port_);

    uint16_t port;
  };

  /**
   * @class IpAddress
   * @brief generalize both ipv4 and ipv6 addresses into a single object
   */
  struct IpAddress
  {
    int init(std::string const &addr, Port const &p);

    union
    {
      std::array<unsigned char, 16> v6;
      std::array<unsigned char, 4> v4;
    } addr;

    bool v4;
    Port p;
    uint32_t scope;
  };

  /**
   * @class Socket
   * @brief BSD socket wrapper
   *
   * Initialized to either TCP or UDP socket.
   *
   * @var int Socket::fd
   * @brief underlying file descriptor representing a BSD socket.
   */
  class Socket
  {
    public:
      Socket();
      Socket(Socket &&lhs);
      ~Socket();

      int initTcp(bool v4);
      int initUdp(bool v4);

      ssize_t read(void *buf, size_t len);
      ssize_t write(void *buf, size_t len);

      ssize_t send(void *buf, size_t len);
      ssize_t sendto(void *buf, size_t len);

      int connect(IpAddress const &addr);
      int setReceiver(IpAddress const &addr);

      int poll(int timeout);

      int bind(Port const &port);

      int accept(Socket &out);

      int peek(IpAddress &sender);

      int shutdownRead();
      int shutdownWrite();

    protected:
      static const int backlog = 16;

    private:
      int fd;
      bool tcp;
      bool v4;
      IpAddress receiver;
  };

  /**
   * @class ReceiverChannelCredentials
   * @brief Manage the credentials for the message channel.
   */
  class TlsKeys : public Credentials_Manager
  {
    public:
      TlsKeys() = default;
      ~TlsKeys() override;

      typedef std::function<bool (Botan::X509_Certificate const &)>
        CertChecker;

      int init(std::string const &key, std::string const &cert,
        CertChecker c, bool server_, Botan::RandomNumberGenerator &rng);

      static int loadKey(std::string const &keyPath,
        std::unique_ptr<Botan::Private_Key const> &key,
        Botan::RandomNumberGenerator &rng);

      static int loadCert(std::string const &certPath,
        std::unique_ptr<Botan::X509_Certificate const> &cert);

      std::vector<Certificate_Store *> trusted_certificate_authorities(
        const std::string &, const std::string &) override;

      void verify_certificate_chain(const std::string &type,
        const std::string &,
        const std::vector<X509_Certificate> &certChain) override;

      std::vector<X509_Certificate> cert_chain(const std::vector<std::string>
        &, const std::string &type, const std::string &) override;

      Private_Key *private_key_for(const X509_Certificate &cert,
        const std::string &type, const std::string &) override;

      bool attempt_srp(const std::string &, const std::string &) override;

    private:
      void checkType(std::string const &type);

      std::unique_ptr<Botan::Private_Key const> myKey;
      std::unique_ptr<Botan::X509_Certificate const> myCert;
      CertChecker check;
      bool server;
  };

  /**
   * @class ReceiverChannelPolicy
   * @brief specifies the connection policy for the message channel.
   *
   * The ultimate goal is to use safe curves such as Curve25519 implemented in
   * Botan. However, there is no support for this with D/TLS.
   *
   * @todo this is a copy from Bless::Receiver
   */
  class DtlsPolicy : public TLS::Strict_Policy
  {
    public:
      bool negotiate_hearbeat_support() const;

      bool allow_server_initiated_renegotiation() const override;

      bool acceptable_protocol_version(TLS::Protocol_Version version) const;
  };

  /**
   * @class SenderChannelPolicy
   * @brief specifies the connection policy when Senders connect.
   *
   * The functions here should be overriden to restrict available cipher
   * suites.
   */
  class TlsPolicy : public TLS::Strict_Policy
  {
  };

  /**
   * @class TlsSocket
   * @brief base class to reduce repeated code in subclasses.
   *
   * Glue together socket and Botan tls.
   */
  class TlsSocket : public Connection
  {
    public:
      ssize_t read(void *buf, size_t len, int timeout = -1) override;
      ssize_t write(void *buf, size_t len) override;

    protected:
      /**
       * @brief generalized boilerplate to make a secure connection.
       *
       * Independant of client, server, tcp, or udp. Use the underlying socket
       * to do all io.
       *
       * @return non-zero on failure.
       */
      int init(TlsKeys *, Botan::RandomNumberGenerator *rng_, bool server,
        bool tls, bool v4);

      int init(TlsSocket const &copy);

      virtual recv(unsigned char *data, size_t len);
      int connect();

      void newSession();
      int newConnection(bool server);

      unique_ptr<Botan::TLS::Channel> conn;
      Socket sock;

      static const size_t bufferSize = 4096;

      unsigned char buffer[bufferSize];

    private:
      void send(unsigned char *data, size_t len);

      TlsKeys *keys;
      Botan::RandomNumberGenerator *rng;
      std::unique_ptr<Botan::TLS::Session_Manager> sessionManager;
      std::unique_ptr<Botan::TLS::Policy> tlsPolicy;

      bool server;
      bool dtls;
  };

  class DtlsConnection : protected SecureConnection, public Connection
  {
    public:
      int initClient();
      int initServer();

      int connect();

  };

  class TlsConnection : protected SecureConnection, public Connection
  {
    public:
      int initClient();
      int initServer();
  };

  class DtlsClient : protected TlsSocket, public Client
  {
    public:
      int init();
      int connect(std::string const &server, unsigned short port) override;
  };

  class DtlsServer : protected SecureConnection, public Server
  {
    public:
      int accept(unsigned short port) override;
      bool isConnected();
      write(data...);
      read = delete;
      unique_ptr<Connection> accept() override;
  };

  class TlsClient : protected SecureConnection, public Client
  {
    public:
      int connect(std::string const &server, unsigned short port) override;
  };

  class TlsServer : protected SecureConnection, public Server
  {
    public:
      int listen(unsigned short port) override;
      unique_ptr<Connection> accept() override;
  };

  class SecureClient : SecureConnection, Client
  {
  };

  class SecureServer : SecureConnection, Server
  {
  };
}
#endif //CONNECTION_h
