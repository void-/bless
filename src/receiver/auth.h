#ifndef AUTH_H
#define AUTH_H

/**
 * The length in bytes of symmetric session keys.
 */
const unsigned int KEY_BYTES = 16u;

/**
 * The symmetric keys derived from the Diffie Hellman exchange between the
 * Server and Receiver. This is the result of tcpBootstrap().
 */
struct sessionKeys
{
  unsigned char keyEnc[KEY_BYTES];
  unsigned char keyMac[KEY_BYTES];
};
#endif //AUTH_H
