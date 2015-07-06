/**
 * @file
 * @brief manage network connections between the Receiver and the Server.
 */

#include "connections.h"

/**
 * @brief bootstrap the message channel between Sender and Receiver.
 *
 * Steps:
 * <p>
 * -# make a TCP connection to \p host
 * -# do a Diffie-Hellman key exchange to derive the keys in \p keyOut
 * </p>
 *
 * The derived session keys are used for the duration of the message channel.
 *
 * @param host server ip address to connect to.
 * @param port tcp port to connect to on \p host.
 * @param keyAuth long-standing authentication keys used to authenticate
 *   the Diffie-Hellman exchange.
 * @param keyOut structure to write the session keys to derived from the key
 *   exchange.
 * @return 0 on success, non-zero on any error.
 */
int tcpBootstrap(char const *host, unsigned short port,
    struct serverAuthKeys const *keyAuth, struct sessionKeys *keyOut)
{

}

/**
 * @brief bootstrap the second, udp half of the message channel.
 *
 * Call udpBootstrap() after tcpBootstrap() with the sessionKeys created.
 *
 * Steps:
 * -# Open a udp holepunch in the NAT to facilitate the push protocol of the
 * message channel
 * -# Authenticate with the Server using the session keys
 * -# Write the opened UDP socket into \p socket
 *
 * @param host server ip address to connect to.
 * @param port udp port to connect to on \p host.
 * @param keySess message channel session keys derived from tcpBootstrap().
 * @param socket resultant udp socket for the message channel.
 * @return 0 on success, non-zero on any error.
 */
int udpBootstrap(char const *host, unsigned short port,
    struct sessionKeys const *keySess, int *socket)
{

}

/**
 * @brief listen on the message channel for any messages from the Sender.
 *
 * Until interupted by a signal:
 * <p>
 * - Listen for any packets on the message channel.
 * - Take action when authentic messages from the Sender arrive.
 * - Ignore empty or unauthenticated packets (used to keep the udp holepunch
 * open)
 * </p>
 *
 * When listenLoop() returns, \p socket will remain open.
 *
 * Messages from the Sender will overwrite \p keyMsg, these will need to be
 * written to persistent storage when listenLoop() terminates and passed in the
 * next time listenLoop() is called.
 *
 * @param socket udp socket for the message channel.
 * @param keySess session keys between the Server and Receiver.
 * @param keyMsg keys shared between Sender and Receiver.
 * @return 0 on success, non-zero on any error.
 */
int listenLoop(int socket, struct sessionKeys const *keySess,
    struct messageKeys *keyMsg)
{

}
