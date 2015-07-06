#ifndef AUTH_H
#define AUTH_H

/**
 * The length in bytes of symmetric session keys.
 */
#define SYM_KEY_BYTES 16u

/**
 * The length in bytes of the public keys used for authentication.
 */
#define PUB_KEY_BYTES 32u

/**
 * Contains long-standing authentication keys for the Server and the Receiver.
 *
 * Public key of the Server.
 * Private key of the Receiver.
 */
struct serverAuthKeys
{
};

/**
 * @struct sessionKeys
 * @brief temporary keys between the Server and Receiver.
 *
 * The symmetric keys derived from the Diffie Hellman exchange between the
 * Server and Receiver. This is the result of tcpBootstrap().
 *
 * Different keys are needed for both directions: Server to Receiver and for
 * Receiver to Server.
 *
 * @var unsigned char sessionKeys::keyEnServer
 * @brief encryption key for Server->Receiver.
 *
 * symmetric encryption key used by the Server to send to the Receiver.
 *
 * @var unsigned char sessionKeys::keyMacServer
 * @brief mac key for Server->Receiver.
 *
 * message authentication key used by the Server to send to the Receiver.
 *
 * @var unsigned char sessionKeys::keyEnReceiver
 * @brief encryption key for Receiver->Server
 *
 * symmetric encryption key used by the Receiver to send to the Server.
 *
 * @var unsigned char sessionKeys::keyMacReceiver
 * @brief mac key for Receiver->Server
 *
 * message authentication key used by the Receiver to send to the Server.
 */
struct sessionKeys
{
  unsigned char keyEnServer[SYM_KEY_BYTES];
  unsigned char keyMacServer[SYM_KEY_BYTES];
  unsigned char keyEnReceiver[SYM_KEY_BYTES];
  unsigned char keyMacReceiver[SYM_KEY_BYTES];
};

/**
 * Key suite shared with the Sender used to encrypt a single message.
 */
struct messageKeys
{
};

#endif //AUTH_H
