#include "connections.h"

using namespace Botan;

namespace Bless
{
  /**
   * @brief construct a new, unitialized, Channel.
   *
   * @warning invalid unless init() is called.
   */
  Channel::Channel() : sessionManager(new TLS::Session_Manager_Noop())
  {
  }

  /**
   * @brief disconnect and destruct the Channel.
   *
   * Any resources allocated for the connection will be freed, but fields like
   * Channel::authKeys will not be.
   */
  Channel::~Channel()
  {
  }

  /**
   * @brief initialize the Channel, but don't connect it.
   *
   * @param keys pointer to initialized AuthKeys to use for authentication.
   * @param server ip address of the Server in the protocol.
   * @return non-zero on error; this implementation always returns 0.
   */
  int Channel::init(AuthKeys *keys, std::string server)
  {
    authKeys = keys;
    serverAddress = server;

    return 0;
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
      serverInformation,
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
