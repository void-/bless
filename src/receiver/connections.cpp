#include "connections.h"

#include <unistd.h>
#include <iostream>

using namespace Botan;

namespace Bless
{
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
   * @param port_ UDP port to connect to the Server on.
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
      policy = new TLS::Policy();
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
   * @brief callback used by the DTLS connection to receive application data.
   *
   * This currently writes \p payload to stdout, but should do something more
   * sophisticated in the future.
   *
   * @param payload the bytes received from the Server.
   * @param len the length of \p payload.
   */
  void Channel::recv(const Botan::byte *const payload, size_t len)
  {
    for(size_t i = 0; i < len; ++i)
    {
      std::cout << payload[i];
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
