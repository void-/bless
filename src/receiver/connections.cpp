#include "connections.h"

#include <unistd.h>

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
      [this](const byte *const data, size_t len) {
        this->recv(data, len);
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
      rng,
      *serverInformation,
      TLS::Protocol_Version::latest_dtls_version(),
      {},
      bufferSize);

    return 0;
  }

  void Channel::send(const byte *const payload, size_t len)
  {
  }

  void Channel::recv(const Botan::byte *const payload, size_t len)
  {

  }

  void Channel::alert(Botan::TLS::Alert alert, const Botan::byte *const payload,
      size_t len)
  {

  }

  bool Channel::handshake(const Botan::TLS::Session &session)
  {
    return true;
  }
}
