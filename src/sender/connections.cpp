#include "connections.h"

#include <unistd.h>
#include <poll.h>

using namespace Botan;

namespace Bless
{
  /**
   * @class ChannelPolicy
   * @brief specifies the connection policy for connecting to the Server.
   */
  class ChannelPolicy : public TLS::Strict_Policy
  {
  };

  /**
   * @class ChannelCredentials
   * @brief Manage the credentials for connecting to the Server.
   *
   * Essentially, interface from AuthKeys to Credentials_Manager interface.
   *
   * @var AuthKeys *ChannelCredentials::authKeys
   * @brief keys to authenticate the message channel; not owned by
   *   ChannelCredentials.
   */
  class ChannelCredentials : public Credentials_Manager
  {
    public:
      /**
       * @brief construct a ChannelCredentials.
       *
       * @warning this isn't valid until init() is called.
       */
      ChannelCredentials()
      {
      }

      /**
       * @brief destruct the ChannelCredentials.
       *
       * Don't deallocate authKeys.
       */
      ~ChannelCredentials() override
      {
      }

      /**
       * @brief initialize the ChannelCredentials given an AuthKeys.
       *
       * @param keys AuthKeys used for authentication; must be not null.
       * @return non-zero on failure.
       */
      int init(AuthKeys *keys)
      {
        authKeys = keys;
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
       * \p certChain should contain the Server's public key.
       *
       * If the certificate matches, it must be valid because it was verified
       * in AuthKeys::init().
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
        if(type != "tls-client")
        {
          throw std::runtime_error("Must use for tls-client.");
        }

        if(!(certChain.size() == 1 &&
            certChain[0] == *authKeys->getServerCert()))
        {
          throw std::invalid_argument("Certificate did not match Server's.");
        }
      }

      /**
       * @brief return a certificate chain to identify the Sender.
       *
       * This returns the Sender's self-signed cert, regardless of the type
       * of key requested.
       *
       * @param type the type of operation occuring
       * @throw std::runtime_error if \p type is not "tls_client"
       * @return vector containing the self-signed certificate for the
       *   Sender.
       */
      std::vector<X509_Certificate> cert_chain(const std::vector<std::string>
          &, const std::string &type, const std::string &)
          override
      {
        if(type != "tls-client")
        {
          throw std::runtime_error("Must use for tls-client.");
        }
        auto cert = authKeys->getSenderCert();
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
        if(type != "tls-client")
        {
          throw std::runtime_error("Must use for tls-client.");
        }

        //if the cert is the Receiver's, return the private key
        if(cert == *authKeys->getSenderCert())
        {
          return authKeys->getSenderPrivKey();
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
      AuthKeys *authKeys;
  };

  /**
   * @brief construct a new, unitialized, Channel.
   *
   * @warning invalid unless init() is called.
   */
  Channel::Channel() : client(nullptr), policy(nullptr)
  {
  }

  /**
   * @brief disconnect and destruct the Channel.
   *
   * If Channel::client is not null, then its safe to delete everything because
   * this is the last initialized. Likewise for Channel::policy; it is the
   * first initialized.
   *
   * Any resources allocated for the connection will be freed, but fields like
   * Channel::authKeys will not be.
   */
  Channel::~Channel()
  {
    if(client)
    {
      delete client;
    }

    if(policy)
    {
      delete policy;
      delete sessionManager;
      delete credentialsManager;
      delete serverInformation;
    }
    close(connection); //ignore any errors
  }

  /**
   * @brief initialize the Channel, but don't connect it.
   *
   * This is where all allocation occurs.
   *
   * Allocate and set sockets to use in connect().
   *
   * Channel::client is initialized in connect().
   *
   * @warning calling init() twice leaks resources.
   *
   * @param keys pointer to initialized AuthKeys to use for authentication.
   * @param server ip address of the Server in the protocol.
   * @param port UDP port to connect to the Server on.
   * @return non-zero on error.
   */
  int Channel::init(AuthKeys *keys, const std::string &server,
      unsigned short port, RandomNumberGenerator *rng_)
  {
    int error = 0;
    in_addr address;
    authKeys = keys;
    rng = rng_;

    //allocate socket
    if((connection = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
      error = -1;
      goto fail;
    }
    ::memset(&connectionInfo, 0, sizeof(connectionInfo));

    //convert ip address to number
    if(!inet_aton(server.c_str(), &address))
    {
      //couldn't convert address
      error = -2;
      goto fail;
    }
    connectionInfo.sin_family = AF_INET;
    connectionInfo.sin_addr = address;

    connectionInfo.sin_port = htons(port);

    //allocate parameters for the channel
    try
    {
      policy = new ChannelPolicy();
      sessionManager = new TLS::Session_Manager_Noop(); //don't keep a session

      //initialize the Channel Credentials
      auto creds = new ChannelCredentials();
      if((error = creds->init(keys)))
      {
        goto fail;
      }
      credentialsManager = creds;

      serverInformation = new TLS::Server_Information();
    }
    catch(std::bad_alloc &e)
    {
      //couldn't dynamically allocate memory
      error = -3;
      goto fail;
    }

fail:
    return error;
  }

  /**
   * @brief make a connection to the Server.
   *
   * This only establishes a connection, use sendMessage() to actually use the
   * connection.
   *
   * @return non-zero on error.
   */
  int Channel::connect()
  {
    ::pollfd pollSocket;
    unsigned char readBuffer[bufferSize];

    //connect the socket to the Server
    if(::connect(connection,
          reinterpret_cast<const sockaddr *>(&connectionInfo),
          sizeof(connectionInfo)) == -1)
    {
      return -1;
    }

    //initiate the TLS connection
    try
    {
      client = new TLS::Client(
        [this](const byte *const data, size_t len) {
          this->send(data, len);
        },
        [this](const byte *const data, size_t len) {
          this->recvData(data, len);
        },
        [this](TLS::Alert alert_, const byte *const data, size_t len) {
          this->alert(alert_, data, len);
        },
        [this](const TLS::Session &session) {
          return this->handshake(session);
        },
        *sessionManager,
        *credentialsManager,
        *policy,
        *rng,
        *serverInformation,
        TLS::Protocol_Version::latest_tls_version(),
        {});
    }
    catch(std::bad_alloc &e)
    {
      //couldn't allocate new client
      return -1;
    }

    //set up socket for polling
    pollSocket.fd = connection;
    pollSocket.events = POLLIN; //poll for reading

    //establish a TLS connection
    while(!client->is_active())
    {
      //not ready after 1 second
      if(::poll(&pollSocket, 1u, handshakeTimeout) != 1)
      {
        return -2;
      }

      //error on socket
      if((pollSocket.revents & POLLERR) | (pollSocket.revents & POLLHUP) |
          (pollSocket.revents & POLLNVAL))
      {
        //could have received ICMP unreachable
        return pollSocket.revents;
      }

      //must be ready to read
      ssize_t count = read(connection, readBuffer, sizeof(readBuffer));

      if(count <= 0)
      {
        //poll() lied!
        return -3;
      }

      //give read data to client
      client->received_data(readBuffer, count);
    }

    return 0;
  }

  /**
   * @brief send a message to the Server.
   *
   * @return non-zero on failure.
   */
  int Channel::sendMessage(Message const &message)
  {
    //connection established, write message
    client->send(message.data.data(), message.data.size());

    return 0;
  }

  /**
   * @brief callback used by the TLS connection to send data.
   *
   * The interface of this callback has no way to communicate errors in-band,
   * so a std::runtime_error is thrown on error. This can be caught above the
   * stack and handled back in-bands.
   *
   * @throws std::runtime_error when writing fails.
   * @param payload the bytes to write out to the wire.
   * @param len the length of \p payload.
   */
  void Channel::send(const byte *const payload, size_t len)
  {
    if(::send(connection, payload, len, MSG_NOSIGNAL) == -1)
    {
      throw std::runtime_error("send failed");
    }
  }

  /**
   * @brief callback when the Server sends data to the Sender.
   *
   * This is a no op, because currently, the Server never writes back to the
   * sender.
   *
   * @param payload not used.
   * @param len not used.
   */
  void Channel::recvData(const byte *const, size_t)
  {
  }


  /**
   * @brief callback when the TLS connection receives an encryption alert.
   *
   * This silently kills the connection by closing the socket.
   */
  void Channel::alert(Botan::TLS::Alert, const Botan::byte *const, size_t)
  {
    close(connection);
  }

  /**
   * @brief callback when the TLS handshake is complete.
   *
   * This is called when the message channel is established.
   *
   * @param session not used.
   * @return false: don't cache the session
   */
  bool Channel::handshake(const Botan::TLS::Session &)
  {
    return false;
  }
}
