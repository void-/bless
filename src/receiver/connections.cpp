#include "connections.h"

#include <unistd.h>
#include <iostream>

using namespace Botan;

namespace Bless
{
  /**
   * @class ChannelPolicy
   * @brief specifies the connection policy for the message channel.
   *
   * The ultimate goal is to use safe curves such as Curve25519 implemented in
   * Botan. However, there is no support for this with D/TLS.
   */
  class ChannelPolicy : public TLS::Strict_Policy
  {
    public:
      /**
       * @brief turn DTLS heartbeats on.
       *
       * This is critical in keeping the UDP holepunch active. Built-in
       * heartbeat support is the key reason DTLS is used.
       *
       * @return true.
       */
      bool negotiate_hearbeat_support() const
      {
        return true;
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
   * @class ChannelCredentials
   * @brief Manage the credentials for the message channel.
   *
   * Essentially, interface from AuthKeys to Credentials_Manager interface.
   */
  class ChannelCredentials : virtual Credentials_Manager
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
       * @brief return the trusted certificate authorities, i.e. the Server.
       *
       * The Server's public key will be in the form of a self-signed
       * certificate. The Server is the only trusted CA.
       *
       * @param type the type of operation occuring.
       * @param context a context relative to \p type.
       * @return a vector of trusted CAs.
       */
      std::vector<Certificate_Store *> trusted_certificate_authorities(
          const std::string &type, const std::string &context) override
      {
        return std::vector<Certificate_Store *>();
      }

      /**
       * @brief verify the given certificate chain for \p hostname.
       *
       * \p certChain should contain the Server's public key.
       *
       * @param type the type of operation occuring.
       * @param hostname the hostname claimed to belong to \p certChain.
       * @param certChain the certificate chain to verify.
       * @throw a std::exception if its wrong.
       */
      void verify_certificate_chain(const std::string &type,
          const std::string &hostname,
          const std::vector<X509_Certificate> &certChain) override
      {
        Credentials_Manager::verify_certificate_chain(
          type, hostname, certChain);
      }

      /**
       * @brief return a certificate chain to identify the Receiver.
       *
       * The difference between this and
       * Credentials_Manager::cert_chain_single_type() is cert_chain() can
       * return any type of certificate key type (algorithm) from \p
       * certKeyTypes.
       *
       * This returns the Receiver's self-signed cert; this must be
       * communicated, to the Server by means of some externel PKI.
       *
       * @param certKeyTypes vector of types of keys requested, e.g.
       *   (RSA, ECDSA)
       * @param type the type of operation occuring
       * @param context a context relative to \p type.
       * @return vector containing the self-signed certificate for the
       *   Receiver.
       */
      std::vector<X509_Certificate> cert_chain(const std::vector<std::string>
          &certKeyTypes, const std::string &type, const std::string &context)
          override
      {
        auto cert = authKeys->getReceiverCert();
        return std::vector<X509_Certificate>{*cert};
      }

      /**
       * @brief return the private key corresponding to the given \p cert.
       *
       * \p cert should have been returned by cert_chain().
       *
       * @param cert the certificate to yield the private key for.
       * @param type the type of operation occuring.
       * @param context the context \p cert will be used under.
       * @return the private half of \p cert.
       */
      Private_Key *private_key_for(const X509_Certificate &cert,
          const std::string &type, const std::string &context) override
      {
        //if the cert is the Receiver's, return the private key
        if(cert == authKeys->getReceiverCert())
        {
          return authKeys->getReceiverPrivKey();
        }
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
    //XXX: does this do an *unclean* disconnect?
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
   * @param keys pointer to initialized AuthKeys to use for authentication.
   * @param server ip address of the Server in the protocol.
   * @param port UDP port to connect to the Server on.
   * @return non-zero on error.
   */
  int Channel::init(AuthKeys *keys, const std::string &server,
      unsigned short port)
  {
    int error = 0;
    in_addr address;
    authKeys = keys;

    //allocate socket
    if((connection = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
    {
      error = -1;
      goto fail;
    }
    memset(&connectionInfo, 0, sizeof(connectionInfo));

    //convert ip address to number
    if(!inet_aton(server.c_str(), &address))
    {
      //couldn't convert address
      error = -2;
      goto fail;
    }
    connectionInfo.sin_addr = address;

    connectionInfo.sin_port = htons(port);

    //allocate parameters for the channel
    try
    {
      policy = new ChannelPolicy();
      sessionManager = new TLS::Session_Manager_Noop(); //don't keep a session
      credentialsManager = new Botan::Credentials_Manager();
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
   * This is a blocking call, it will receive connections indenfinitely until
   * something goes wrong, at which point connect() will return.
   *
   * @param rng RandomNumberGenerator to use for making the connection
   * @param cb receive callback called whenever a new, authenticated message is
   * received
   * @return non-zero on error.
   */
  int Channel::connect(RandomNumberGenerator &rng, recvCallback cb)
  {
    client = new TLS::Client(
      [this](const byte *const data, size_t len) {
        this->send(data, len);
      },
      cb,
      [this](TLS::Alert alert_, const byte *const data, size_t len) {
        this->alert(alert_, data, len);
      },
      [this](const TLS::Session &session) {
        return this->handshake(session);
      },
      *sessionManager,
      *credentialsManager,
      *policy,
      rng,
      *serverInformation,
      TLS::Protocol_Version::latest_dtls_version(),
      {},
      bufferSize);

    return 0;
  }

  /**
   * @brief callback used by the DTLS connection to send data.
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
   * @brief callback when the DTLS connection receives an encryption alert.
   *
   * This silently kills the connection.
   *
   * @param alert the alert received.
   * @param payload not used.
   * @param len not used.
   */
  void Channel::alert(Botan::TLS::Alert alert,
      const Botan::byte *const payload, size_t len)
  {
    std::cout << alert.type_string();
    close(connection);
  }

  /**
   * @brief callback when the DTLS handshake is complete.
   *
   * This is called when the message channel is established.
   *
   * @param session not used.
   * @return true.
   */
  bool Channel::handshake(const Botan::TLS::Session &session)
  {
    return true;
  }
}
