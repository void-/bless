#include "connections.h"

namespace Bless
{
  /**
   * @brief construct a new, unitialized, Channel.
   *
   * @warning invalid unless init() is called.
   */
  Channel::Channel()
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
   * @return non-zero on error.
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
   * This is a blocking call, it will loo
   *
   * @param rng RandomNumberGenerator to use for making the connection
   * @param cb receive callback called whenever a new, authenticated message is
   * received
   * @return non-zero on error.
   */
  int Channel::connect(Botan::RandomNumberGenerator &rng, recvCallback cb)
  {
    return 0;
  }
}
