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
 * The symmetric keys derived from the Diffie Hellman exchange between the
 * Server and Receiver. This is the result of tcpBootstrap().
 */
struct sessionKeys
{
  unsigned char keyEnc[SYM_KEY_BYTES];
  unsigned char keyMac[SYM_KEY_BYTES];
};

/**
 * Key suite shared with the Sender used to encrypt a single message.
 */
struct messageKeys
{
};

#endif //AUTH_H
